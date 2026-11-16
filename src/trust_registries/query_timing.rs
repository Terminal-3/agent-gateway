//! Step timings of the trust registry queries a future runs. Queries record
//! their steps only inside [`collect`], which keeps the steps of the slowest
//! query; everywhere else a [`QueryTimer`] reads no clock and records nothing.

use std::cell::Cell;
use std::future::Future;
use std::time::{Duration, Instant};

tokio::task_local! {
    static SLOWEST: Cell<Option<QuerySteps>>;
}

/// Time one query spent in each step, summed over its attempts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuerySteps {
    /// Looking up the registry's connection, or waiting for it to be built or
    /// rebuilt and for its websocket to be ready.
    pub(crate) connection: Duration,
    /// The mediator status check before the query is sent.
    pub(crate) preflight: Duration,
    /// Registering the reply waiter, packing the query and forwarding it.
    pub(crate) send: Duration,
    /// Waiting for the registry's reply.
    pub(crate) reply: Duration,
}

impl QuerySteps {
    fn total(&self) -> Duration {
        self.connection + self.preflight + self.send + self.reply
    }

    fn slot(
        &mut self,
        step: QueryStep,
    ) -> &mut Duration {
        match step {
            QueryStep::Connection => &mut self.connection,
            QueryStep::Preflight => &mut self.preflight,
            QueryStep::Send => &mut self.send,
            QueryStep::Reply => &mut self.reply,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueryStep {
    Connection,
    Preflight,
    Send,
    Reply,
}

/// Runs `future` and returns its output with the steps of the slowest query
/// it ran, by the sum of their steps. Queries running concurrently in
/// `future` overlap, so the slowest one is the one the caller waited for.
/// When `enabled` is false, `future` runs as it is and no steps are returned.
pub(crate) async fn collect<F: Future>(
    enabled: bool,
    future: F,
) -> (F::Output, Option<QuerySteps>) {
    if !enabled {
        return (future.await, None);
    }
    SLOWEST
        .scope(Cell::new(None), async {
            let output = future.await;
            (output, SLOWEST.with(Cell::get))
        })
        .await
}

/// The steps of one query. The open step closes when the next one begins or
/// when the timer is dropped, so a query that fails or is cancelled part-way
/// still reports the time it spent.
pub(crate) struct QueryTimer {
    steps: QuerySteps,
    open: Option<(QueryStep, Instant)>,
    collecting: bool,
}

impl QueryTimer {
    pub(crate) fn new() -> Self {
        Self {
            steps: QuerySteps::default(),
            open: None,
            collecting: SLOWEST
                .try_with(|_| ())
                .is_ok(),
        }
    }

    pub(crate) fn begin(
        &mut self,
        step: QueryStep,
    ) {
        if !self.collecting {
            return;
        }
        let now = Instant::now();
        self.close(now);
        self.open = Some((step, now));
    }

    fn close(
        &mut self,
        now: Instant,
    ) {
        if let Some((step, started)) = self.open.take() {
            *self.steps.slot(step) += now.saturating_duration_since(started);
        }
    }
}

impl Drop for QueryTimer {
    fn drop(&mut self) {
        if !self.collecting {
            return;
        }
        self.close(Instant::now());
        let steps = self.steps;
        let _ = SLOWEST.try_with(|slowest| {
            if slowest
                .get()
                .is_none_or(|current| current.total() < steps.total())
            {
                slowest.set(Some(steps));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn query(steps: QuerySteps) {
        let mut timer = QueryTimer::new();
        timer.steps = steps;
    }

    fn steps(reply_ms: u64) -> QuerySteps {
        QuerySteps {
            reply: Duration::from_millis(reply_ms),
            ..QuerySteps::default()
        }
    }

    #[tokio::test]
    async fn keeps_the_steps_of_the_slowest_query() {
        let ((), slowest) = collect(true, async {
            futures::future::join_all([query(steps(5)), query(steps(40)), query(steps(12))]).await;
        })
        .await;
        assert_eq!(slowest, Some(steps(40)));
    }

    #[tokio::test]
    async fn returns_no_steps_when_disabled_or_when_no_query_ran() {
        let ((), steps_when_disabled) = collect(false, query(steps(40))).await;
        assert_eq!(steps_when_disabled, None);
        let (value, no_query) = collect(true, async { 7 }).await;
        assert_eq!((value, no_query), (7, None));
    }

    #[test]
    fn records_nothing_outside_collect() {
        let mut timer = QueryTimer::new();
        timer.begin(QueryStep::Connection);
        assert!(!timer.collecting && timer.open.is_none());
    }

    #[tokio::test]
    async fn adds_each_step_and_closes_the_open_one_on_drop() {
        let ((), slowest) = collect(true, async {
            let mut timer = QueryTimer::new();
            timer.begin(QueryStep::Connection);
            timer.begin(QueryStep::Preflight);
            timer.begin(QueryStep::Connection);
            std::thread::sleep(Duration::from_millis(2));
        })
        .await;
        let slowest = slowest.expect("a query ran");
        assert!(slowest.connection >= Duration::from_millis(2), "{slowest:?}");
        assert_eq!((slowest.send, slowest.reply), (Duration::ZERO, Duration::ZERO));
    }
}
