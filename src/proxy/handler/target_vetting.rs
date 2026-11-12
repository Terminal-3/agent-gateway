//! SSRF vetting of a direct Access Point's forward target.

use std::time::Duration;

use axum::http::StatusCode;
use axum::response::Response;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::a2a::create_error_response;
use crate::audit::request_events::{RejectionReason, RejectionStage, RequestFacts, request_rejected};
use crate::egress::EgressError;
use crate::observability::loggable;
use crate::state::ProxyState;

/// The vetting of one forward target, running on a blocking thread: resolve
/// the host, refuse cloud-metadata addresses, and build a redirect-disabled
/// client pinned to the vetted addresses. Pinning stops DNS rebinding between
/// vetting and connect; disabling redirects stops a 3xx from sending the
/// request, and any credential on it, to an unvetted host.
///
/// Dropping it aborts a vetting that has not started; one already resolving
/// runs to the end of its lookup and its client is discarded unused.
pub(super) struct TargetVetting {
    target_url: String,
    task: JoinHandle<Result<reqwest::Client, EgressError>>,
}

#[cfg(test)]
tokio::task_local! {
    static STARTS: std::sync::atomic::AtomicUsize;
}

/// Runs `future` and returns, with its output, how many vettings it started
/// on its own task.
#[cfg(test)]
pub(super) async fn count_starts<F: std::future::Future>(future: F) -> (F::Output, usize) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    STARTS
        .scope(AtomicUsize::new(0), async {
            let output = future.await;
            (output, STARTS.with(|starts| starts.load(Ordering::SeqCst)))
        })
        .await
}

impl TargetVetting {
    pub(super) fn start(
        state: &ProxyState,
        channel_name: &str,
        target_url: &str,
    ) -> Self {
        debug!(channel = channel_name, target = %loggable::url(target_url), "Vetting the forward target");
        #[cfg(test)]
        let _ = STARTS.try_with(|starts| starts.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
        let candidate = target_url.to_string();
        let timeout = Duration::from_secs(
            state
                .config
                .a2a
                .timeout_seconds,
        );
        Self::spawn(target_url, move || {
            crate::egress::pinned_forward_client(&candidate, timeout).map(|(client, _target)| client)
        })
    }

    fn spawn(
        target_url: &str,
        vet: impl FnOnce() -> Result<reqwest::Client, EgressError> + Send + 'static,
    ) -> Self {
        Self {
            target_url: target_url.to_string(),
            task: tokio::task::spawn_blocking(vet),
        }
    }

    /// The vetted client, or the 403 to answer. A block is recorded as a
    /// refusal; a vetting task that did not complete is a gateway fault.
    pub(super) async fn finish(
        mut self,
        channel_name: &str,
        facts: &RequestFacts<'_>,
    ) -> Result<reqwest::Client, Response> {
        let target = loggable::url(&self.target_url);
        match (&mut self.task).await {
            Ok(Ok(client)) => Ok(client),
            Ok(Err(e)) => {
                warn!(channel = channel_name, target = %target, "SSRF blocked by egress policy: {}", e);
                request_rejected(facts, RejectionStage::Forward, RejectionReason::SsrfBlocked, 403, None);
                Err(create_error_response(StatusCode::FORBIDDEN, "Request blocked by egress policy"))
            }
            Err(e) => {
                warn!(channel = channel_name, target = %target, "SSRF egress validation task failed: {}", e);
                Err(create_error_response(StatusCode::FORBIDDEN, "Request blocked by egress policy"))
            }
        }
    }
}

impl Drop for TargetVetting {
    fn drop(&mut self) {
        self.task
            .abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn facts() -> RequestFacts<'static> {
        RequestFacts {
            surface_id: "vetting",
            channel_name: "vetting",
            trace_id: None,
            via_fabric: false,
        }
    }

    async fn finished(vetting: TargetVetting) -> (Result<reqwest::Client, Response>, Vec<RecordedRefusal>) {
        let facts = facts();
        let (outcome, events) = crate::audit::producer::capture(vetting.finish("vetting", &facts)).await;
        let refusals = events
            .into_iter()
            .filter_map(|event| match event.event {
                crate::delegation_vault::audit::DelegationAuditAction::RequestRejected {
                    stage,
                    reason,
                    http_status,
                    ..
                } => Some((stage, reason, http_status)),
                _ => None,
            })
            .collect();
        (outcome, refusals)
    }

    type RecordedRefusal = (RejectionStage, RejectionReason, Option<u16>);

    #[tokio::test]
    async fn a_vetted_target_yields_its_client() {
        let (outcome, refusals) = finished(TargetVetting::spawn("http://upstream.example", || Ok(reqwest::Client::new()))).await;
        assert!(outcome.is_ok());
        assert!(refusals.is_empty());
    }

    #[tokio::test]
    async fn a_blocked_target_is_refused_with_its_record() {
        let (outcome, refusals) = finished(TargetVetting::spawn("http://169.254.169.254/rpc", || {
            Err(EgressError::Blocked("cloud metadata".into()))
        }))
        .await;
        assert_eq!(outcome.map(|_| ()).unwrap_err().status(), StatusCode::FORBIDDEN);
        assert_eq!(refusals, vec![(RejectionStage::Forward, RejectionReason::SsrfBlocked, Some(403))]);
    }

    #[tokio::test]
    async fn a_vetting_that_panics_fails_closed() {
        let (outcome, refusals) = finished(TargetVetting::spawn("http://upstream.example", || {
            panic!("vetting panicked")
        }))
        .await;
        assert_eq!(outcome.map(|_| ()).unwrap_err().status(), StatusCode::FORBIDDEN);
        assert!(refusals.is_empty());
    }

    /// With the one blocking thread busy, a vetting waits in the queue;
    /// dropping it there cancels it, so its closure never runs.
    #[test]
    fn a_dropped_vetting_that_has_not_started_never_runs() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (release, held) = std::sync::mpsc::channel::<()>();
            let (running, started) = tokio::sync::oneshot::channel::<()>();
            let busy = tokio::task::spawn_blocking(move || {
                let _ = running.send(());
                let _ = held.recv();
            });
            started
                .await
                .unwrap();

            let ran = Arc::new(AtomicBool::new(false));
            let in_task = ran.clone();
            let vetting = TargetVetting::spawn("http://upstream.example", move || {
                in_task.store(true, Ordering::SeqCst);
                Ok(reqwest::Client::new())
            });
            drop(vetting);
            drop(release);
            busy.await
                .unwrap();
            tokio::task::spawn_blocking(|| ())
                .await
                .unwrap();
            assert!(!ran.load(Ordering::SeqCst), "a dropped vetting still ran");
        });
    }
}
