//! Per-registry DIDComm stream reader.
//!
//! Each active trust-registry connection has exactly one reader task draining
//! the mediator websocket via `live_stream_next`. It is the **sole** consumer of
//! that stream: it demultiplexes query responses back to the `send_and_await`
//! waiter registered under the response's thread id (`thid`), and drives the
//! connection setup/approval status transitions.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm::Message as DIDCommMessage;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use super::communication::{TrustRegistryConnection, connection};
use super::store::TrustRegistryStore;
use super::types::{TrustRegistry, TrustRegistryConnectionStatus};
use crate::comm::didcomm::trust_registry::PollResult;
use crate::server::websocket::WsState;

/// Problem report message type (DIDComm standard).
const MSG_TYPE_PROBLEM_REPORT: &str = "https://didcomm.org/report-problem/2.0/problem-report";

/// How long a single `live_stream_next` call blocks before returning `None`,
/// letting the loop re-check that its connection still exists.
const READ_WAIT: Duration = Duration::from_secs(300);

type Connections = Arc<RwLock<HashMap<String, TrustRegistryConnection>>>;

/// Drive the reader loop for a single registry connection until the connection
/// is removed from the map (graceful stop) or the task is aborted.
pub(crate) async fn run(
    connections: Connections,
    trust_registry_id: String,
    store: Option<Arc<dyn TrustRegistryStore>>,
    ws_state: Option<WsState>,
) {
    info!("TR reader: starting for '{}'", trust_registry_id);

    loop {
        let connection = {
            let guard = connections.read().await;
            match guard.get(&trust_registry_id) {
                Some(c) => c.clone(),
                None => {
                    debug!("TR reader: connection '{}' gone, stopping", trust_registry_id);
                    break;
                }
            }
        };

        match connection
            .client
            .live_stream_next(READ_WAIT, true)
            .await
        {
            Ok(Some((message, _metadata))) => {
                // Sender identity is verified natively by the SDK's authcrypt-only
                // UnpackPolicy (anoncrypt/plaintext envelopes are purged at pickup),
                // so any message delivered here has a cryptographically verified
                // `from`.
                handle_message(message, &connection, &store, &ws_state).await;
            }
            Ok(None) => {
                // Timeout or a transient disconnect. The SDK reconnects the
                // socket in the background; re-check the connection and retry.
                continue;
            }
            Err(e) => {
                warn!("TR reader: stream error for '{}': {:?}", trust_registry_id, e);
                connection
                    .fail_all_waiters()
                    .await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    // Reader exiting — release any queries still awaiting on this connection so
    // they fail fast rather than block until their own timeout.
    if let Some(connection) = connections
        .read()
        .await
        .get(&trust_registry_id)
    {
        connection
            .fail_all_waiters()
            .await;
    }
    info!("TR reader: stopped for '{}'", trust_registry_id);
}

/// Route one inbound message: demux query responses by `thid`, otherwise drive
/// connection-setup status transitions.
async fn handle_message(
    message: DIDCommMessage,
    connection: &TrustRegistryConnection,
    store: &Option<Arc<dyn TrustRegistryStore>>,
    ws_state: &Option<WsState>,
) {
    let thid = message
        .thid
        .clone()
        .or_else(|| message.pthid.clone())
        .unwrap_or_else(|| message.id.clone());

    match message.typ.as_str() {
        connection::SETUP_RECEIVED => {
            info!("TR reader: setup/received for '{}'", connection.trust_registry_id);
            update_status(connection, TrustRegistryConnectionStatus::AwaitingApproval, store, ws_state).await;
        }
        connection::SETUP_APPROVED => {
            info!("TR reader: setup/approved for '{}'", connection.trust_registry_id);
            update_status(connection, TrustRegistryConnectionStatus::Connected, store, ws_state).await;
        }
        MSG_TYPE_PROBLEM_REPORT => {
            let result = PollResult {
                msg_type: message.typ.clone(),
                body: message.body.clone(),
            };
            if connection
                .deliver_response(&thid, result)
                .await
            {
                debug!("TR reader: delivered problem-report to waiter (thid {})", thid);
            } else if connection
                .timed_out_queries
                .contains(&thid)
            {
                warn!(
                    "TR reader: problem-report for '{}' answers a query that timed out (thid {}), ignoring",
                    connection.trust_registry_id, thid
                );
            } else {
                let code = message
                    .body
                    .get("code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let comment = message
                    .body
                    .get("comment")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if rejects_setup(&message, connection) {
                    error!(
                        "TR reader: problem-report for '{}' (thid {}, pthid {:?}, id {}): {}: {}",
                        connection.trust_registry_id, thid, message.pthid, message.id, code, comment
                    );
                    update_status(connection, TrustRegistryConnectionStatus::Failed, store, ws_state).await;
                } else {
                    warn!(
                        "TR reader: problem-report for '{}' matches no query (thid {}, pthid {:?}, id {}), ignoring: {}: {}",
                        connection.trust_registry_id, thid, message.pthid, message.id, code, comment
                    );
                }
            }
        }
        other => {
            let result = PollResult {
                msg_type: message.typ.clone(),
                body: message.body.clone(),
            };
            if !connection
                .deliver_response(&thid, result)
                .await
            {
                debug!(
                    "TR reader: no waiter for message type '{}' (thid {}) on '{}', ignoring",
                    other, thid, connection.trust_registry_id
                );
            }
        }
    }
}

/// Whether `message` is on the thread of the connection's setup message, which
/// makes a problem report the registry rejecting the gateway.
fn rejects_setup(
    message: &DIDCommMessage,
    connection: &TrustRegistryConnection,
) -> bool {
    let Some(setup_thid) = connection.setup_thid.as_deref() else {
        return false;
    };
    [&message.thid, &message.pthid]
        .into_iter()
        .any(|thid| thid.as_deref() == Some(setup_thid))
}

/// Persist a connection-status change and refresh the dashboard. A no-op when
/// no store is configured.
async fn update_status(
    connection: &TrustRegistryConnection,
    new_status: TrustRegistryConnectionStatus,
    store: &Option<Arc<dyn TrustRegistryStore>>,
    ws_state: &Option<WsState>,
) {
    let Some(store) = store else {
        return;
    };
    let tr_id = &connection.trust_registry_id;

    let status_label = format!("{:?}", new_status);
    let change = Box::new(move |tr: &mut TrustRegistry| {
        tr.connection_status = new_status;
        tr.updated_at = chrono::Utc::now();
    });
    match store
        .modify(tr_id, change)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            debug!("TR reader: trust registry '{}' was deleted; its status was not written", tr_id);
            return;
        }
        Err(e) => {
            error!("TR reader: failed to update status for '{}': {}", tr_id, e);
            return;
        }
    }

    info!("TR reader: updated '{}' status to {}", tr_id, status_label);

    if let Some(ws_state) = ws_state {
        ws_state.broadcast(crate::server::WsUpdate::RefreshDashboard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_registries::FileSystemTrustRegistryStore;
    use crate::trust_registries::communication::TimedOutQueries;
    use crate::trust_registries::did_manager::DidMethod;
    use crate::trust_registries::types::TrustRegistry;
    use tokio::sync::Mutex;

    const SETUP_THID: &str = "thid-setup";

    async fn registry_with(
        status: TrustRegistryConnectionStatus
    ) -> (TrustRegistryConnection, Option<Arc<dyn TrustRegistryStore>>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemTrustRegistryStore::new(dir.path().join("records"))
            .await
            .expect("store");
        let mut registry = TrustRegistry::new(
            "registry".to_string(),
            String::new(),
            "https://registry.example/oob".to_string(),
            DidMethod::Peer,
        );
        registry.connection_status = status;
        store
            .create(&registry)
            .await
            .expect("create");
        let connection = TrustRegistryConnection {
            trust_registry_id: registry.id,
            our_did: "did:example:gateway".to_string(),
            registry_did: "did:example:registry".to_string(),
            main_did: None,
            mediator_did: "did:example:mediator".to_string(),
            setup_thid: Some(SETUP_THID.to_string()),
            is_temporary: false,
            client: crate::trust_registries::test_builds::offline_client().await,
            response_waiters: Arc::new(Mutex::new(HashMap::new())),
            timed_out_queries: TimedOutQueries::default(),
        };
        (connection, Some(Arc::new(store) as Arc<dyn TrustRegistryStore>), dir)
    }

    fn report() -> affinidi_messaging_didcomm::MessageBuilder {
        DIDCommMessage::build(
            uuid::Uuid::new_v4().to_string(),
            MSG_TYPE_PROBLEM_REPORT.to_string(),
            serde_json::json!({ "code": "e.p.rejected", "comment": "rejected" }),
        )
    }

    fn problem_report(thid: &str) -> DIDCommMessage {
        report()
            .thid(thid.to_string())
            .finalize()
    }

    async fn status_of(
        store: &Option<Arc<dyn TrustRegistryStore>>,
        connection: &TrustRegistryConnection,
    ) -> TrustRegistryConnectionStatus {
        store
            .as_ref()
            .expect("store")
            .get(&connection.trust_registry_id)
            .await
            .expect("get")
            .expect("the registry is stored")
            .connection_status
    }

    #[tokio::test]
    async fn a_problem_report_answering_a_timed_out_query_keeps_the_status() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;
        connection
            .timed_out_queries
            .record("thid-timed-out");

        handle_message(problem_report("thid-timed-out"), &connection, &store, &None).await;

        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connected);
    }

    #[tokio::test]
    async fn a_problem_report_on_the_setup_thread_marks_the_registry_failed() {
        let by_thid = problem_report(SETUP_THID);
        let by_pthid = report()
            .thid("thid-reply".to_string())
            .pthid(SETUP_THID.to_string())
            .finalize();
        for message in [by_thid, by_pthid] {
            let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::AwaitingApproval).await;

            handle_message(message, &connection, &store, &None).await;

            assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Failed);
        }
    }

    #[tokio::test]
    async fn a_problem_report_on_another_thread_keeps_the_status() {
        for status in [
            TrustRegistryConnectionStatus::Connecting,
            TrustRegistryConnectionStatus::AwaitingApproval,
            TrustRegistryConnectionStatus::Connected,
        ] {
            let (connection, store, _dir) = registry_with(status.clone()).await;

            handle_message(problem_report("thid-unmatched"), &connection, &store, &None).await;

            assert_eq!(status_of(&store, &connection).await, status);
        }
    }

    #[tokio::test]
    async fn a_problem_report_without_a_known_setup_thread_keeps_the_status() {
        let (mut connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connecting).await;
        connection.setup_thid = None;

        handle_message(problem_report(SETUP_THID), &connection, &store, &None).await;

        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connecting);
    }
}
