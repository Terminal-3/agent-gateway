//! Shares one TRQP query between identical requests that are in flight at the
//! same time.
//!
//! The first request for a [`QueryKey`] spawns the query in its own task;
//! requests with the same key that arrive before that task finishes await the
//! same answer. The task removes its entry before its answer becomes visible,
//! so an answer is never handed to a request that arrives after it was
//! delivered: nothing is cached.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use tokio::sync::oneshot;
use tracing::Instrument;

use crate::trust_registries::types::TrqpQueryRequest;
use crate::trust_registry_verification::trust_check_element::TrqpQueryType;
use crate::trust_registry_verification::trust_check_executor::{TrqpClientError, TrqpOutcome};

/// Most distinct queries shared at once. Past it a request sends its own
/// query without sharing.
const MAX_IN_FLIGHT: usize = 1024;

/// Longest a shared query may run. One still running then fails for every
/// request awaiting it, and its entry is removed.
const MAX_QUERY_TIME: Duration = Duration::from_secs(30);

type QueryResult = Result<TrqpOutcome, TrqpClientError>;
type SharedQuery = Shared<BoxFuture<'static, QueryResult>>;
type Entries = Arc<Mutex<HashMap<QueryKey, SharedQuery>>>;

/// Identity of a query as sent: the registry it goes to and the exact
/// serialised request body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct QueryKey {
    registry_id: String,
    registry_did: String,
    query_type: TrqpQueryType,
    body: Vec<u8>,
}

impl QueryKey {
    /// `None` when the request cannot be serialised; such a query is not
    /// shared.
    pub(crate) fn new(
        registry_id: &str,
        registry_did: &str,
        query_type: TrqpQueryType,
        request: &TrqpQueryRequest,
    ) -> Option<Self> {
        let body = serde_json::to_vec(request).ok()?;
        Some(Self {
            registry_id: registry_id.to_string(),
            registry_did: registry_did.to_string(),
            query_type,
            body,
        })
    }
}

/// The queries currently in flight, keyed by [`QueryKey`]. A key identifies
/// a query only among those sent over one set of registry connections, so
/// each listener manager owns its own instance.
pub(crate) struct InFlightQueries {
    entries: Entries,
    capacity: usize,
    time_limit: Duration,
}

impl Default for InFlightQueries {
    fn default() -> Self {
        Self::new(MAX_IN_FLIGHT, MAX_QUERY_TIME)
    }
}

impl InFlightQueries {
    fn new(
        capacity: usize,
        time_limit: Duration,
    ) -> Self {
        Self {
            entries: Arc::default(),
            capacity,
            time_limit,
        }
    }

    /// Answer `query`, sharing it with identical in-flight requests. Sets
    /// `joined` when this request awaits a query another request started.
    pub(crate) async fn run<F>(
        &self,
        key: QueryKey,
        query: F,
        joined: &AtomicBool,
    ) -> QueryResult
    where
        F: Future<Output = QueryResult> + Send + 'static,
    {
        match self.join_or_start(key, query) {
            Ok((shared, was_joined)) => {
                joined.store(was_joined, Ordering::Relaxed);
                shared.await
            }
            Err(query) => query.await,
        }
    }

    /// Returns the query to await and whether it was joined, or hands
    /// `query` back when the map is full.
    fn join_or_start<F>(
        &self,
        key: QueryKey,
        query: F,
    ) -> Result<(SharedQuery, bool), F>
    where
        F: Future<Output = QueryResult> + Send + 'static,
    {
        let (answer, answered) = oneshot::channel();
        let shared = {
            let mut entries = lock(&self.entries);
            if let Some(shared) = entries.get(&key) {
                return Ok((shared.clone(), true));
            }
            if entries.len() >= self.capacity {
                return Err(query);
            }
            let shared = answered
                .map(|answer| {
                    answer.unwrap_or_else(|_| {
                        Err(TrqpClientError::QueryFailed(
                            "shared trust registry query ended without an answer".to_string(),
                        ))
                    })
                })
                .boxed()
                .shared();
            entries.insert(key.clone(), shared.clone());
            shared
        };
        // Spawned with the map unlocked: a runtime that is shutting down
        // drops the task, and with it the entry, inside `spawn`.
        let delivery = Delivery {
            entry: EntryGuard {
                entries: Arc::clone(&self.entries),
                key,
            },
            answer,
        };
        let time_limit = self.time_limit;
        tokio::spawn(
            async move {
                let result = tokio::time::timeout(time_limit, query)
                    .await
                    .unwrap_or_else(|_| {
                        Err(TrqpClientError::QueryFailed(format!(
                            "shared trust registry query exceeded {}s",
                            time_limit.as_secs()
                        )))
                    });
                delivery.deliver(result);
            }
            .in_current_span(),
        );
        Ok((shared, false))
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        lock(&self.entries).len()
    }
}

/// A spawned query's entry and the channel its answer goes out on. However
/// the task ends, the entry is removed before the waiters are woken: the
/// fields drop in declaration order.
struct Delivery {
    entry: EntryGuard,
    answer: oneshot::Sender<QueryResult>,
}

impl Delivery {
    fn deliver(
        self,
        result: QueryResult,
    ) {
        let Self { entry, answer } = self;
        drop(entry);
        // Every waiter may have been cancelled, leaving no receiver.
        let _ = answer.send(result);
    }
}

/// Removes its entry from the map when dropped.
struct EntryGuard {
    entries: Entries,
    key: QueryKey,
}

impl Drop for EntryGuard {
    fn drop(&mut self) {
        lock(&self.entries).remove(&self.key);
    }
}

/// Every critical section is a single map insert or remove, so a poisoned
/// map is still consistent.
fn lock(entries: &Mutex<HashMap<QueryKey, SharedQuery>>) -> MutexGuard<'_, HashMap<QueryKey, SharedQuery>> {
    entries
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use super::*;

    fn key(entity: &str) -> QueryKey {
        let request = TrqpQueryRequest {
            authority_id: "did:web:bank".to_string(),
            entity_id: entity.to_string(),
            action: "bank:assistant".to_string(),
            resource: "merlion-bank".to_string(),
        };
        QueryKey::new("tr-a", "did:web:registry", TrqpQueryType::Authorization, &request).expect("key")
    }

    /// A query that counts its sends and answers when `release` fires.
    fn gated_query(
        sends: &Arc<AtomicUsize>,
        release: oneshot::Receiver<QueryResult>,
    ) -> impl Future<Output = QueryResult> + Send + 'static {
        let sends = Arc::clone(sends);
        async move {
            sends.fetch_add(1, Ordering::SeqCst);
            release
                .await
                .unwrap_or_else(|_| Err(TrqpClientError::QueryFailed("released without an answer".to_string())))
        }
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    async fn allowed() -> QueryResult {
        Ok(TrqpOutcome::Allowed)
    }

    async fn panicking_query() -> QueryResult {
        settle().await;
        panic!("registry client bug");
    }

    #[tokio::test]
    async fn concurrent_identical_queries_send_once_and_share_the_answer() {
        let in_flight = Arc::new(InFlightQueries::default());
        let sends = Arc::new(AtomicUsize::new(0));
        let (release, gate) = oneshot::channel();
        let (unused_release, unused_gate) = oneshot::channel();

        let leader_joined = AtomicBool::new(false);
        let joiner_joined = AtomicBool::new(false);
        let leader = in_flight.run(key("did:web:assistant"), gated_query(&sends, gate), &leader_joined);
        let joiner = in_flight.run(key("did:web:assistant"), gated_query(&sends, unused_gate), &joiner_joined);
        let (leader, joiner, ()) = tokio::join!(leader, joiner, async {
            settle().await;
            release
                .send(Ok(TrqpOutcome::Allowed))
                .expect("query awaiting its answer");
        });
        drop(unused_release);

        assert_eq!(leader, Ok(TrqpOutcome::Allowed));
        assert_eq!(joiner, Ok(TrqpOutcome::Allowed));
        assert_eq!(sends.load(Ordering::SeqCst), 1);
        assert!(!leader_joined.load(Ordering::Relaxed));
        assert!(joiner_joined.load(Ordering::Relaxed));
        assert_eq!(in_flight.len(), 0);
    }

    #[tokio::test]
    async fn different_queries_are_not_shared() {
        let in_flight = InFlightQueries::default();
        let sends = Arc::new(AtomicUsize::new(0));
        let (release_a, gate_a) = oneshot::channel();
        let (release_b, gate_b) = oneshot::channel();
        let joined_a = AtomicBool::new(false);
        let joined_b = AtomicBool::new(false);

        let (a, b, ()) = tokio::join!(
            in_flight.run(key("did:web:assistant-a"), gated_query(&sends, gate_a), &joined_a),
            in_flight.run(key("did:web:assistant-b"), gated_query(&sends, gate_b), &joined_b),
            async {
                settle().await;
                release_a
                    .send(Ok(TrqpOutcome::Allowed))
                    .expect("query a waiting");
                release_b
                    .send(Ok(TrqpOutcome::Denied {
                        detail: "Registry answered `authorized: false`".to_string(),
                    }))
                    .expect("query b waiting");
            }
        );

        assert_eq!(a, Ok(TrqpOutcome::Allowed));
        assert!(matches!(b, Ok(TrqpOutcome::Denied { .. })));
        assert_eq!(sends.load(Ordering::SeqCst), 2);
        assert!(!joined_a.load(Ordering::Relaxed));
        assert!(!joined_b.load(Ordering::Relaxed));
    }

    #[test]
    fn the_key_covers_every_field_the_query_sends() {
        let base = TrqpQueryRequest {
            authority_id: "did:a".to_string(),
            entity_id: "did:e".to_string(),
            action: "act".to_string(),
            resource: "res".to_string(),
        };
        let reference = QueryKey::new("tr-a", "did:r", TrqpQueryType::Authorization, &base).expect("key");
        let variants = [
            QueryKey::new("tr-b", "did:r", TrqpQueryType::Authorization, &base),
            QueryKey::new("tr-a", "did:other", TrqpQueryType::Authorization, &base),
            QueryKey::new("tr-a", "did:r", TrqpQueryType::Recognition, &base),
            QueryKey::new("tr-a", "did:r", TrqpQueryType::Authorization, &TrqpQueryRequest {
                authority_id: "did:a2".to_string(),
                ..base.clone()
            }),
            QueryKey::new("tr-a", "did:r", TrqpQueryType::Authorization, &TrqpQueryRequest {
                entity_id: "did:e2".to_string(),
                ..base.clone()
            }),
            QueryKey::new("tr-a", "did:r", TrqpQueryType::Authorization, &TrqpQueryRequest {
                action: "act2".to_string(),
                ..base.clone()
            }),
            QueryKey::new("tr-a", "did:r", TrqpQueryType::Authorization, &TrqpQueryRequest {
                resource: "res2".to_string(),
                ..base.clone()
            }),
        ];
        for variant in variants {
            assert_ne!(variant.expect("key"), reference);
        }
        assert_eq!(QueryKey::new("tr-a", "did:r", TrqpQueryType::Authorization, &base).expect("key"), reference);
    }

    #[tokio::test]
    async fn a_sequential_repeat_sends_again() {
        let in_flight = InFlightQueries::default();
        let sends = Arc::new(AtomicUsize::new(0));
        for expected_sends in 1..=2 {
            let (release, gate) = oneshot::channel();
            release
                .send(Ok(TrqpOutcome::Allowed))
                .expect("gate open");
            let joined = AtomicBool::new(false);
            let answer = in_flight
                .run(key("did:web:assistant"), gated_query(&sends, gate), &joined)
                .await;
            assert_eq!(answer, Ok(TrqpOutcome::Allowed));
            assert!(!joined.load(Ordering::Relaxed));
            assert_eq!(sends.load(Ordering::SeqCst), expected_sends);
            assert_eq!(in_flight.len(), 0);
        }
    }

    #[tokio::test]
    async fn a_failure_fails_every_waiter() {
        let in_flight = InFlightQueries::default();
        let sends = Arc::new(AtomicUsize::new(0));
        let (release, gate) = oneshot::channel();
        let (_unused_release, unused_gate) = oneshot::channel();
        let joined = [AtomicBool::new(false), AtomicBool::new(false)];
        let failure = TrqpClientError::Unreachable("no connection".to_string());

        let (first, second, ()) = tokio::join!(
            in_flight.run(key("did:web:assistant"), gated_query(&sends, gate), &joined[0]),
            in_flight.run(key("did:web:assistant"), gated_query(&sends, unused_gate), &joined[1]),
            async {
                settle().await;
                release
                    .send(Err(failure.clone()))
                    .expect("query waiting");
            }
        );

        assert_eq!(first, Err(failure.clone()));
        assert_eq!(second, Err(failure));
        assert_eq!(sends.load(Ordering::SeqCst), 1);
        assert_eq!(in_flight.len(), 0);
    }

    #[tokio::test]
    async fn a_panicking_query_fails_every_waiter_closed() {
        let in_flight = InFlightQueries::default();
        let joined = [AtomicBool::new(false), AtomicBool::new(false)];
        let (first, second) = tokio::join!(
            in_flight.run(key("did:web:assistant"), panicking_query(), &joined[0]),
            in_flight.run(key("did:web:assistant"), allowed(), &joined[1]),
        );

        assert!(matches!(first, Err(TrqpClientError::QueryFailed(_))));
        assert!(matches!(second, Err(TrqpClientError::QueryFailed(_))));
        assert!(joined[1].load(Ordering::Relaxed));
        assert_eq!(in_flight.len(), 0);
    }

    #[tokio::test]
    async fn a_cancelled_leader_does_not_affect_its_joiners() {
        let in_flight = Arc::new(InFlightQueries::default());
        let sends = Arc::new(AtomicUsize::new(0));
        let (release, gate) = oneshot::channel();

        let leader = tokio::spawn({
            let in_flight = Arc::clone(&in_flight);
            let query = gated_query(&sends, gate);
            async move {
                in_flight
                    .run(key("did:web:assistant"), query, &AtomicBool::new(false))
                    .await
            }
        });
        settle().await;
        let joiner = tokio::spawn({
            let in_flight = Arc::clone(&in_flight);
            async move {
                let joined = AtomicBool::new(false);
                let answer = in_flight
                    .run(key("did:web:assistant"), allowed(), &joined)
                    .await;
                (answer, joined.load(Ordering::Relaxed))
            }
        });
        settle().await;
        leader.abort();
        assert!(
            leader
                .await
                .expect_err("leader aborted")
                .is_cancelled()
        );

        release
            .send(Ok(TrqpOutcome::Denied {
                detail: "Registry answered `authorized: false`".to_string(),
            }))
            .expect("shared query still waiting after the leader was cancelled");
        let (answer, joined) = joiner.await.expect("joiner completes");

        assert_eq!(
            answer,
            Ok(TrqpOutcome::Denied {
                detail: "Registry answered `authorized: false`".to_string(),
            })
        );
        assert!(joined);
        assert_eq!(sends.load(Ordering::SeqCst), 1);
        assert_eq!(in_flight.len(), 0);
    }

    #[tokio::test]
    async fn a_full_map_sends_unshared() {
        let in_flight = InFlightQueries::new(1, MAX_QUERY_TIME);
        let sends = Arc::new(AtomicUsize::new(0));
        let (release, gate) = oneshot::channel();
        let (_unused_release, unused_gate) = oneshot::channel();
        let (own_release, own_gate) = oneshot::channel();
        let joined = [AtomicBool::new(false), AtomicBool::new(false), AtomicBool::new(false)];

        let (held, overflow, joiner, ()) = tokio::join!(
            in_flight.run(key("did:web:assistant-a"), gated_query(&sends, gate), &joined[0]),
            in_flight.run(key("did:web:assistant-b"), gated_query(&sends, own_gate), &joined[1]),
            in_flight.run(key("did:web:assistant-a"), gated_query(&sends, unused_gate), &joined[2]),
            async {
                settle().await;
                assert_eq!(in_flight.len(), 1);
                own_release
                    .send(Ok(TrqpOutcome::Allowed))
                    .expect("unshared query waiting");
                release
                    .send(Ok(TrqpOutcome::Allowed))
                    .expect("shared query waiting");
            }
        );

        assert_eq!(held, Ok(TrqpOutcome::Allowed));
        assert_eq!(overflow, Ok(TrqpOutcome::Allowed));
        assert_eq!(joiner, Ok(TrqpOutcome::Allowed));
        assert!(!joined[1].load(Ordering::Relaxed));
        assert!(joined[2].load(Ordering::Relaxed));
        assert_eq!(sends.load(Ordering::SeqCst), 2);
        assert_eq!(in_flight.len(), 0);
    }

    #[test]
    fn a_query_started_on_a_stopped_runtime_fails_closed() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let handle = runtime.handle().clone();
        drop(runtime);
        let _context = handle.enter();

        let in_flight = InFlightQueries::default();
        let joined = AtomicBool::new(false);
        let answer = futures::executor::block_on(in_flight.run(key("did:web:assistant"), allowed(), &joined));

        assert!(matches!(answer, Err(TrqpClientError::QueryFailed(_))));
        assert_eq!(in_flight.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_query_past_the_time_limit_fails_every_waiter_and_frees_its_entry() {
        let in_flight = InFlightQueries::new(MAX_IN_FLIGHT, Duration::from_secs(5));
        let joined = [AtomicBool::new(false), AtomicBool::new(false)];

        let (first, second) = tokio::join!(
            in_flight.run(key("did:web:assistant"), std::future::pending(), &joined[0]),
            in_flight.run(key("did:web:assistant"), allowed(), &joined[1]),
        );

        assert!(matches!(first, Err(TrqpClientError::QueryFailed(_))));
        assert!(matches!(second, Err(TrqpClientError::QueryFailed(_))));
        assert!(joined[1].load(Ordering::Relaxed));
        assert_eq!(in_flight.len(), 0);
    }
}
