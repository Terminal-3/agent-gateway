//! The per-request timing summary of an MCP Access Point: one `info` line,
//! "MCP request timing", written when the request handler finishes, on every
//! return path. It carries durations, the MCP method, the surface and the
//! Target's host and port, and nothing else from the caller.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tracing::info;

use crate::egress::PinTimings;
use crate::trust_registries::query_timing::QuerySteps;

/// The longest MCP method written as sent; anything longer or outside the
/// method character set is written as [`INVALID_METHOD`].
const MAX_LOGGED_METHOD_LEN: usize = 64;
const INVALID_METHOD: &str = "invalid";

/// Proxy requests whose handler is running, on every surface.
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

/// One request counted in an in-flight counter until it is dropped, so an
/// early return or a panic still counts it out.
struct InFlight {
    counter: &'static AtomicUsize,
    at_entry: usize,
}

impl InFlight {
    /// Counts the request in and keeps the count it brought the counter to.
    fn enter(counter: &'static AtomicUsize) -> Self {
        let at_entry = counter.fetch_add(1, Ordering::Relaxed) + 1;
        Self { counter, at_entry }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// The client a request was forwarded with. Both are built for the one
/// request, so each send opens a new connection to the Target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EgressClient {
    /// Pinned to the Target by the pin step.
    Pinned,
    /// Pinned to the provider's resource by the route of a Target grant.
    GrantRoute,
}

impl EgressClient {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pinned => "pinned",
            Self::GrantRoute => "grant_route",
        }
    }
}

/// The wait for, and the steps of, the blocking task that resolves, vets and
/// pins the Target before the request is classified.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinStepTiming {
    /// From submitting the blocking task until the handler resumed with its result.
    pub(crate) total: Duration,
    /// From submitting the blocking task until it started on a blocking thread.
    pub(crate) queued: Option<Duration>,
    pub(crate) steps: PinTimings,
}

/// Durations of the stages of one request, logged on drop when `enabled`.
pub(crate) struct RequestTiming {
    enabled: bool,
    started: Instant,
    in_flight: InFlight,
    surface_id: String,
    surface: String,
    mcp_method: Option<String>,
    target: Option<String>,
    egress_client: Option<EgressClient>,
    body_read: Option<Duration>,
    pin: Option<PinStepTiming>,
    before_classify: Option<Duration>,
    identity_started: Option<Instant>,
    identity: Option<Duration>,
    trust_check: Option<(Duration, usize)>,
    trust_check_slowest_query: Option<QuerySteps>,
    grant_client_build: Option<Duration>,
    vp_mint: Option<Duration>,
    mcp_proxy: Option<Duration>,
    upstream: Option<Duration>,
}

impl RequestTiming {
    pub(crate) fn new(
        enabled: bool,
        started: Instant,
        surface_id: &str,
        surface: &str,
    ) -> Self {
        let copied = |value: &str| if enabled { value.to_string() } else { String::new() };
        Self {
            enabled,
            started,
            in_flight: InFlight::enter(&IN_FLIGHT),
            surface_id: copied(surface_id),
            surface: copied(surface),
            mcp_method: None,
            target: None,
            egress_client: None,
            body_read: None,
            pin: None,
            before_classify: None,
            identity_started: None,
            identity: None,
            trust_check: None,
            trust_check_slowest_query: None,
            grant_client_build: None,
            vp_mint: None,
            mcp_proxy: None,
            upstream: None,
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn mcp_method(
        &mut self,
        method: &str,
    ) {
        if !self.enabled {
            return;
        }
        self.mcp_method = Some(loggable_method(method).to_string());
    }

    /// Records the `method` of a JSON-RPC body, such as a notification, that
    /// has no MCP context.
    pub(crate) fn mcp_method_from_body(
        &mut self,
        body: &[u8],
    ) {
        #[derive(serde::Deserialize)]
        struct Envelope {
            method: Option<String>,
        }
        if !self.enabled {
            return;
        }
        if let Some(method) = serde_json::from_slice::<Envelope>(body)
            .ok()
            .and_then(|envelope| envelope.method)
        {
            self.mcp_method(&method);
        }
    }

    /// Records the pin step and the Target's `host:port`, taken from the
    /// operator-configured Target URL.
    pub(crate) fn pin(
        &mut self,
        target_url: &str,
        timing: PinStepTiming,
    ) {
        if !self.enabled {
            return;
        }
        self.target = target_host_port(target_url);
        self.pin = Some(timing);
    }

    /// Reading the request body from the caller.
    pub(crate) fn body_read(
        &mut self,
        elapsed: Duration,
    ) {
        self.body_read = Some(elapsed);
    }

    pub(crate) fn egress_client(
        &mut self,
        client: EgressClient,
    ) {
        self.egress_client = Some(client);
    }

    pub(crate) fn classified(&mut self) {
        self.before_classify = Some(self.started.elapsed());
    }

    /// Starts the identity stage. A stage that is started and not finished,
    /// because the request ended inside it, is logged up to the end of the
    /// request.
    pub(crate) fn identity_started(&mut self) {
        if !self.enabled {
            return;
        }
        self.identity_started = Some(Instant::now());
    }

    pub(crate) fn identity_finished(&mut self) {
        self.identity = self
            .identity_started
            .map(|started| started.elapsed());
    }

    /// Records the caller-leg Trust Check and the steps of its slowest
    /// registry query.
    pub(crate) fn trust_check(
        &mut self,
        elapsed: Duration,
        checks: usize,
        slowest_query: Option<QuerySteps>,
    ) {
        self.trust_check = Some((elapsed, checks));
        self.trust_check_slowest_query = slowest_query;
    }

    /// Building the client of a Target grant's route.
    pub(crate) fn grant_client_build(
        &mut self,
        elapsed: Duration,
    ) {
        self.grant_client_build = Some(elapsed);
    }

    pub(crate) fn vp_mint(
        &mut self,
        elapsed: Duration,
    ) {
        self.vp_mint = Some(elapsed);
    }

    /// Loading and running the request on a gateway-owned MCP Proxy, which
    /// includes its calls to the Proxy's backend.
    pub(crate) fn mcp_proxy(
        &mut self,
        elapsed: Duration,
    ) {
        self.mcp_proxy = Some(elapsed);
    }

    pub(crate) fn upstream(
        &mut self,
        elapsed: Duration,
    ) {
        self.upstream = Some(elapsed);
    }
}

impl Drop for RequestTiming {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        let pin = self.pin.as_ref();
        let query = self.trust_check_slowest_query;
        info!(
            surface_id = %self.surface_id,
            channel = %self.surface,
            mcp_method = self.mcp_method.as_deref(),
            target = self.target.as_deref(),
            in_flight = self.in_flight.at_entry as u64,
            egress_client = self.egress_client.map(EgressClient::as_str),
            total_ms = ms(self.started.elapsed()),
            body_read_ms = self.body_read.map(ms),
            before_classify_ms = self.before_classify.map(ms),
            pin_ms = pin.map(|p| ms(p.total)),
            pin_queue_ms = pin.and_then(|p| p.queued).map(ms),
            pin_resolve_ms = pin.and_then(|p| p.steps.resolve).map(ms),
            pin_build_ms = pin.and_then(|p| p.steps.build).map(ms),
            grant_client_ms = self.grant_client_build.map(ms),
            identity_ms = self
                .identity
                .or_else(|| {
                    self.identity_started
                        .map(|started| started.elapsed())
                })
                .map(ms),
            trust_check_ms = self.trust_check.map(|(elapsed, _)| ms(elapsed)),
            trust_checks = self.trust_check.map(|(_, checks)| checks as u64),
            trust_check_connection_ms = query.map(|q| ms(q.connection)),
            trust_check_preflight_ms = query.map(|q| ms(q.preflight)),
            trust_check_send_ms = query.map(|q| ms(q.send)),
            trust_check_reply_ms = query.map(|q| ms(q.reply)),
            vp_mint_ms = self.vp_mint.map(ms),
            mcp_proxy_ms = self.mcp_proxy.map(ms),
            upstream_ms = self.upstream.map(ms),
            "MCP request timing"
        );
    }
}

/// `elapsed` in milliseconds, to a tenth of a millisecond.
pub(crate) fn ms(elapsed: Duration) -> f64 {
    (elapsed.as_secs_f64() * 10_000.0).round() / 10.0
}

fn loggable_method(method: &str) -> &str {
    let well_formed = !method.is_empty()
        && method.len() <= MAX_LOGGED_METHOD_LEN
        && method
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.' | b'$'));
    if well_formed { method } else { INVALID_METHOD }
}

fn target_host_port(target_url: &str) -> Option<String> {
    let url = url::Url::parse(target_url).ok()?;
    let host = url.host_str()?;
    let port = url.port_or_known_default()?;
    Some(format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::{Context, SubscriberExt};

    /// The `(name, value)` pairs of one captured event.
    type Event = Vec<(String, String)>;

    #[derive(Default)]
    struct Fields(Event);

    impl Visit for Fields {
        fn record_debug(
            &mut self,
            field: &Field,
            value: &dyn std::fmt::Debug,
        ) {
            self.0
                .push((field.name().to_string(), format!("{value:?}")));
        }
    }

    struct Capture(Arc<Mutex<Vec<Event>>>);

    impl<S: tracing::Subscriber> Layer<S> for Capture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: Context<'_, S>,
        ) {
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.0
                .lock()
                .expect("capture lock")
                .push(fields.0);
        }
    }

    fn capture(f: impl FnOnce()) -> Vec<Event> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Capture(events.clone()));
        tracing::subscriber::with_default(subscriber, f);
        events
            .lock()
            .expect("capture lock")
            .clone()
    }

    fn field<'a>(
        event: &'a [(String, String)],
        name: &str,
    ) -> Option<&'a str> {
        event
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn writes_one_line_with_the_recorded_stages() {
        let events = capture(|| {
            let mut timing = RequestTiming::new(true, Instant::now(), "surface-1", "bank");
            timing.mcp_method("tools/list");
            timing.pin(
                "http://mock-bank:7300/mcp?token=secret",
                PinStepTiming {
                    total: Duration::from_micros(104_300),
                    queued: Some(Duration::from_micros(200)),
                    steps: PinTimings {
                        resolve: Some(Duration::from_micros(101_040)),
                        build: Some(Duration::from_micros(2_960)),
                    },
                },
            );
            timing.body_read(Duration::from_micros(1_260));
            timing.egress_client(EgressClient::Pinned);
            timing.classified();
            timing.identity_started();
            timing.identity_finished();
            timing.trust_check(
                Duration::from_millis(312),
                1,
                Some(QuerySteps {
                    connection: Duration::from_micros(400),
                    preflight: Duration::from_millis(95),
                    send: Duration::from_millis(12),
                    reply: Duration::from_millis(201),
                }),
            );
            timing.grant_client_build(Duration::from_micros(4_120));
            timing.vp_mint(Duration::from_micros(3_460));
            timing.mcp_proxy(Duration::from_millis(7));
            timing.upstream(Duration::from_millis(18));
        });

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(field(event, "message"), Some("MCP request timing"));
        assert_eq!(field(event, "surface_id"), Some("surface-1"));
        assert_eq!(field(event, "channel"), Some("bank"));
        assert_eq!(field(event, "mcp_method"), Some("\"tools/list\""));
        assert_eq!(field(event, "target"), Some("\"mock-bank:7300\""));
        assert_eq!(field(event, "egress_client"), Some("\"pinned\""));
        assert_eq!(field(event, "body_read_ms"), Some("1.3"));
        assert!(field(event, "in_flight").is_some_and(|count| count.parse::<u64>().is_ok_and(|count| count >= 1)));
        assert_eq!(field(event, "pin_ms"), Some("104.3"));
        assert_eq!(field(event, "pin_queue_ms"), Some("0.2"));
        assert_eq!(field(event, "pin_resolve_ms"), Some("101.0"));
        assert_eq!(field(event, "pin_build_ms"), Some("3.0"));
        assert!(field(event, "identity_ms").is_some());
        assert_eq!(field(event, "trust_check_ms"), Some("312.0"));
        assert_eq!(field(event, "trust_checks"), Some("1"));
        assert_eq!(field(event, "trust_check_connection_ms"), Some("0.4"));
        assert_eq!(field(event, "trust_check_preflight_ms"), Some("95.0"));
        assert_eq!(field(event, "trust_check_send_ms"), Some("12.0"));
        assert_eq!(field(event, "trust_check_reply_ms"), Some("201.0"));
        assert_eq!(field(event, "grant_client_ms"), Some("4.1"));
        assert_eq!(field(event, "vp_mint_ms"), Some("3.5"));
        assert_eq!(field(event, "mcp_proxy_ms"), Some("7.0"));
        assert_eq!(field(event, "upstream_ms"), Some("18.0"));
        assert!(field(event, "before_classify_ms").is_some());
        assert!(field(event, "total_ms").is_some());
        assert!(
            event
                .iter()
                .all(|(_, value)| !value.contains("secret") && !value.contains("/mcp")),
            "{event:?}"
        );
    }

    #[test]
    fn leaves_out_the_stages_that_did_not_run() {
        let events = capture(|| {
            let mut timing = RequestTiming::new(true, Instant::now(), "surface-1", "bank");
            timing.mcp_method("notifications/initialized");
        });

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(field(event, "mcp_method"), Some("\"notifications/initialized\""));
        for absent in [
            "target",
            "egress_client",
            "body_read_ms",
            "before_classify_ms",
            "pin_ms",
            "identity_ms",
            "trust_check_ms",
            "trust_checks",
            "trust_check_connection_ms",
            "trust_check_preflight_ms",
            "trust_check_send_ms",
            "trust_check_reply_ms",
            "grant_client_ms",
            "vp_mint_ms",
            "mcp_proxy_ms",
            "upstream_ms",
        ] {
            assert_eq!(field(event, absent), None, "{absent} in {event:?}");
        }
    }

    #[test]
    fn logs_a_stage_the_request_ended_in() {
        let events = capture(|| {
            RequestTiming::new(true, Instant::now(), "surface-1", "bank").identity_started();
        });
        assert!(field(&events[0], "identity_ms").is_some(), "{:?}", events[0]);
    }

    #[test]
    fn reads_the_method_of_a_body_without_mcp_context() {
        let events = capture(|| {
            let mut timing = RequestTiming::new(true, Instant::now(), "surface-1", "bank");
            timing.mcp_method_from_body(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        });
        assert_eq!(field(&events[0], "mcp_method"), Some("\"notifications/initialized\""));

        for body in [&b"not json"[..], br#"{"jsonrpc":"2.0","id":1,"result":{}}"#] {
            let events = capture(|| {
                RequestTiming::new(true, Instant::now(), "surface-1", "bank").mcp_method_from_body(body);
            });
            assert_eq!(field(&events[0], "mcp_method"), None);
        }
    }

    #[test]
    fn writes_nothing_when_disabled() {
        let events = capture(|| {
            let mut timing = RequestTiming::new(false, Instant::now(), "surface-1", "bank");
            timing.mcp_method("tools/list");
            timing.pin("http://mock-bank:7300/mcp", PinStepTiming::default());
            timing.identity_started();
            timing.upstream(Duration::from_millis(18));
            assert!(timing.surface_id.is_empty() && timing.surface.is_empty());
            assert!(timing.mcp_method.is_none() && timing.target.is_none() && timing.pin.is_none());
            assert!(timing.identity_started.is_none());
        });
        assert!(events.is_empty(), "{events:?}");
    }

    #[test]
    fn writes_a_malformed_or_overlong_method_as_invalid() {
        assert_eq!(loggable_method("tools/call"), "tools/call");
        assert_eq!(loggable_method("$/cancelRequest"), "$/cancelRequest");
        assert_eq!(loggable_method(""), INVALID_METHOD);
        assert_eq!(loggable_method("tools/call\nINFO forged"), INVALID_METHOD);
        assert_eq!(loggable_method("did:web:alice.example"), INVALID_METHOD);
        assert_eq!(loggable_method(&"a".repeat(MAX_LOGGED_METHOD_LEN + 1)), INVALID_METHOD);
    }

    #[test]
    fn target_is_host_and_port_only() {
        assert_eq!(target_host_port("https://user:pw@api.example/x?q=1").as_deref(), Some("api.example:443"));
        assert_eq!(target_host_port("http://10.0.0.1:8080/mcp").as_deref(), Some("10.0.0.1:8080"));
        assert_eq!(target_host_port("not a url"), None);
    }

    #[test]
    fn counts_a_request_in_flight_until_it_is_dropped() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let first = InFlight::enter(&COUNTER);
        let second = InFlight::enter(&COUNTER);
        assert_eq!((first.at_entry, second.at_entry), (1, 2));
        drop(second);
        assert_eq!(COUNTER.load(Ordering::Relaxed), 1);

        let unwound = std::panic::catch_unwind(|| {
            let _in_flight = InFlight::enter(&COUNTER);
            panic!("request handler panicked");
        });
        assert!(unwound.is_err());
        assert_eq!(COUNTER.load(Ordering::Relaxed), 1);
        drop(first);
        assert_eq!(COUNTER.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn names_the_egress_client() {
        assert_eq!(EgressClient::Pinned.as_str(), "pinned");
        assert_eq!(EgressClient::GrantRoute.as_str(), "grant_route");
    }

    #[test]
    fn ms_rounds_to_a_tenth() {
        assert_eq!(ms(Duration::from_micros(1_549)), 1.5);
        assert_eq!(ms(Duration::from_micros(1_560)), 1.6);
        assert_eq!(ms(Duration::ZERO), 0.0);
    }
}
