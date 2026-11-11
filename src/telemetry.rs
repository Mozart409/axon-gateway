//! Telemetry initialization: tracing subscriber with optional OpenTelemetry export.
//!
//! Logging behaves as it always did: `RUST_LOG` if set, otherwise
//! `axon_gateway=debug,info`, printed pretty or as JSON. On top of that, trace
//! export over OTLP is opt-in and configured by the standard OpenTelemetry
//! environment variables only:
//!
//! - `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`:
//!   export is enabled iff one of them is set and non-empty
//! - `OTEL_EXPORTER_OTLP_PROTOCOL`: `grpc` (default) or `http/protobuf`
//! - `OTEL_EXPORTER_OTLP_HEADERS` / `OTEL_EXPORTER_OTLP_TRACES_HEADERS`: auth
//!   headers, read by the SDK
//! - `OTEL_SERVICE_NAME`: service name (default: `axon-gateway`)
//! - `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG`: read by the SDK itself;
//!   the default is parent-based always-on
//!
//! Incoming W3C `traceparent` headers parent the request span, see
//! [`http_request_span`]. Backend calls carry the current span's context on to
//! the backend, see [`current_trace_context`]. A failing exporter never fails startup: the gateway
//! logs a warning and runs without export.

use std::collections::HashMap;

use axum::extract::MatchedPath;
use axum::http::{HeaderMap, Request, StatusCode};
use opentelemetry::propagation::Extractor;
use opentelemetry::trace::TracerProvider;
use opentelemetry::{Context, KeyValue, global};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt};

const DEFAULT_SERVICE_NAME: &str = "axon-gateway";

/// Guard returned by [`init`].
///
/// Hold it in `main` and call [`TelemetryGuard::shutdown`] before the process
/// exits so pending spans are flushed. Dropping it does the same.
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl TelemetryGuard {
    /// Shut down the OpenTelemetry pipeline, flushing all pending spans.
    ///
    /// Idempotent: `Drop` calls this again after an explicit call. A no-op
    /// when export is disabled.
    pub fn shutdown(&self) {
        let Some(provider) = &self.provider else {
            return;
        };
        match provider.shutdown() {
            Ok(()) | Err(opentelemetry_sdk::error::OTelSdkError::AlreadyShutdown) => {}
            Err(e) => {
                tracing::warn!(error = %e, "Failed to shut down OpenTelemetry tracer provider");
            }
        }
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Install the global tracing subscriber and, when configured, OTLP trace export.
///
/// The env filter is `RUST_LOG` if set, otherwise `axon_gateway=debug,info`.
/// `json_logs` selects JSON instead of pretty log lines. Call it once, from
/// inside the tokio runtime (the gRPC exporter needs one), and hold the
/// returned [`TelemetryGuard`] until shutdown.
///
/// # Panics
///
/// Panics if a global subscriber has already been set.
pub fn init(json_logs: bool) -> TelemetryGuard {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("axon_gateway=debug,info"));

    global::set_text_map_propagator(TraceContextPropagator::new());

    let (provider, export_error) = match build_provider() {
        Ok(provider) => (provider, None),
        Err(e) => (None, Some(e)),
    };
    let otel_layer = provider
        .as_ref()
        .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer(env!("CARGO_PKG_NAME"))));

    // Boxed so the pretty and JSON layers share one type
    let fmt_layer: Box<dyn Layer<_> + Send + Sync> = if json_logs {
        Box::new(fmt::layer().json())
    } else {
        Box::new(fmt::layer())
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(otel_layer)
        .with(fmt_layer)
        .init();

    if provider.is_some() {
        tracing::info!("OpenTelemetry trace export enabled");
    }
    if let Some(error) = export_error {
        tracing::warn!(%error, "OpenTelemetry trace export disabled");
    }

    TelemetryGuard { provider }
}

/// Whether an OTLP endpoint is configured through the standard env vars.
fn export_enabled() -> bool {
    [
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    ]
    .iter()
    .any(|name| std::env::var(name).is_ok_and(|value| !value.is_empty()))
}

/// Build the tracer provider from the environment.
///
/// `Ok(None)` when no endpoint is configured, `Err` with a message when the
/// configuration is unusable.
///
/// No sampler is set on purpose: the SDK's default config reads
/// `OTEL_TRACES_SAMPLER`, and an explicit one would silently override it.
fn build_provider() -> Result<Option<SdkTracerProvider>, String> {
    if !export_enabled() {
        return Ok(None);
    }

    let protocol =
        std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL").unwrap_or_else(|_| "grpc".to_string());
    let builder = opentelemetry_otlp::SpanExporter::builder();
    let exporter = match protocol.as_str() {
        "grpc" => builder.with_tonic().build(),
        "http/protobuf" => builder.with_http().build(),
        other => {
            return Err(format!(
                "unsupported OTEL_EXPORTER_OTLP_PROTOCOL `{other}`, use `grpc` or `http/protobuf`"
            ));
        }
    }
    .map_err(|e| format!("failed to create the OTLP span exporter: {e}"))?;

    let service_name = std::env::var("OTEL_SERVICE_NAME")
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_string());
    let resource = Resource::builder()
        .with_service_name(service_name)
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .build();

    Ok(Some(
        SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build(),
    ))
}

/// Reads W3C trace context headers for the global propagator.
struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(axum::http::HeaderName::as_str).collect()
    }
}

/// The remote parent context carried by the request headers, if any.
fn extract_parent_context(headers: &HeaderMap) -> Context {
    global::get_text_map_propagator(|propagator| propagator.extract(&HeaderExtractor(headers)))
}

/// Span name following the `OTel` HTTP server convention: `{method} {route}`.
///
/// The route is the matched axum route template, never the raw path, so the
/// cardinality stays low; without a match (fallback, unknown path) it is the
/// method alone.
fn otel_span_name(method: &str, route: Option<&str>) -> String {
    route.map_or_else(|| method.to_string(), |route| format!("{method} {route}"))
}

/// Create the span for one incoming HTTP request.
///
/// Same name and fields as the former inline `make_span_with` closure
/// (`request_id`, `method`, `uri`), plus `otel.kind = "server"`, an
/// `otel.name` of `{method} {route}`, and an empty `http.response.status_code`
/// for [`record_response_status`]. A valid incoming `traceparent` header makes
/// the span a child of the caller's trace.
///
/// `request_id` is the id [`crate::server`]'s middleware stored for the request.
/// The matched route is only known once the request went through a route, so a
/// request that hit the fallback is named by its method alone.
pub fn http_request_span<B>(request: &Request<B>, request_id: &str) -> Span {
    let method = request.method();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);

    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %method,
        uri = %request.uri(),
        otel.kind = "server",
        otel.name = %otel_span_name(method.as_str(), route),
        http.response.status_code = tracing::field::Empty,
    );

    if request.headers().contains_key("traceparent") {
        let parent = extract_parent_context(request.headers());
        if let Err(error) = span.set_parent(parent) {
            tracing::debug!(%error, "Could not set the remote parent of the request span");
        }
    }
    span
}

/// Record the response status on a span made by [`http_request_span`].
pub fn record_response_status(span: &Span, status: StatusCode) {
    span.record("http.response.status_code", i64::from(status.as_u16()));
}

/// The trace id of the current span as 32 hex digits, `None` when there is no
/// valid `OpenTelemetry` context (no `OTel` layer installed).
#[must_use]
pub fn current_trace_id() -> Option<String> {
    use opentelemetry::trace::TraceContextExt;

    let context = Span::current().context();
    let span = context.span();
    let span_context = span.span_context();
    span_context
        .is_valid()
        .then(|| span_context.trace_id().to_string())
}

/// The W3C trace context of a span, as it is sent to a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub traceparent: String,
    pub tracestate: Option<String>,
}

/// The W3C trace context of the current span, for a request that leaves the
/// gateway. `None` when the span has no valid `OpenTelemetry` context (no `OTel`
/// layer installed, or the span is disabled).
///
/// It is read from the span the caller is in, so take it on the task that
/// handles the client's request: it does not survive a hop through an actor
/// mailbox or a spawned task.
#[must_use]
pub fn current_trace_context() -> Option<TraceContext> {
    use opentelemetry::trace::TraceContextExt;

    let context = Span::current().context();
    if !context.span().span_context().is_valid() {
        return None;
    }
    let mut carrier = HashMap::new();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut carrier);
    });
    let traceparent = carrier.remove("traceparent")?;
    let tracestate = carrier
        .remove("tracestate")
        .filter(|state| !state.is_empty());
    Some(TraceContext {
        traceparent,
        tracestate,
    })
}

#[cfg(test)]
mod tests {
    use opentelemetry::trace::{TraceContextExt, TraceId};

    use super::*;

    const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0c3b4e8e-01";

    /// Run `f` under a subscriber with an OpenTelemetry layer, without
    /// touching the global one. The provider has no exporter.
    fn with_otel_subscriber<T>(f: impl FnOnce() -> T) -> T {
        global::set_text_map_propagator(TraceContextPropagator::new());
        let provider = SdkTracerProvider::builder().build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));
        tracing::subscriber::with_default(subscriber, f)
    }

    fn request(traceparent: Option<&str>) -> Request<()> {
        let mut builder = Request::builder().method("GET").uri("/api/status?x=1");
        if let Some(value) = traceparent {
            builder = builder.header("traceparent", value);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn span_is_named_http_request() {
        with_otel_subscriber(|| {
            let span = http_request_span(&request(None), "req-1");
            assert_eq!(
                span.metadata().map(tracing::Metadata::name),
                Some("http_request")
            );
        });
    }

    #[test]
    fn otel_name_uses_route_or_method_only() {
        assert_eq!(otel_span_name("GET", Some("/api/{id}")), "GET /api/{id}");
        assert_eq!(otel_span_name("POST", None), "POST");
    }

    #[test]
    fn traceparent_sets_the_remote_parent() {
        with_otel_subscriber(|| {
            let span = http_request_span(&request(Some(TRACEPARENT)), "req-2");
            let context = span.context();
            let trace_id = context.span().span_context().trace_id();
            assert_eq!(trace_id, TraceId::from_hex(TRACE_ID).unwrap());
        });
    }

    #[test]
    fn without_traceparent_the_span_starts_a_new_trace() {
        with_otel_subscriber(|| {
            let span = http_request_span(&request(None), "req-3");
            let trace_id = span.context().span().span_context().trace_id();
            assert_ne!(trace_id, TraceId::from_hex(TRACE_ID).unwrap());
        });
    }

    #[test]
    fn extractor_reads_the_traceparent_header() {
        global::set_text_map_propagator(TraceContextPropagator::new());
        let context = extract_parent_context(request(Some(TRACEPARENT)).headers());
        let span_context = context.span().span_context().clone();
        assert!(span_context.is_valid());
        assert!(span_context.is_remote());
        assert_eq!(
            span_context.trace_id(),
            TraceId::from_hex(TRACE_ID).unwrap()
        );
    }

    #[test]
    fn garbage_traceparent_is_ignored() {
        global::set_text_map_propagator(TraceContextPropagator::new());
        let context = extract_parent_context(request(Some("garbage")).headers());
        assert!(!context.span().span_context().is_valid());
    }

    #[test]
    fn trace_context_is_none_without_an_otel_layer() {
        global::set_text_map_propagator(TraceContextPropagator::new());
        let subscriber = tracing_subscriber::registry();
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("call");
            let _guard = span.enter();
            assert_eq!(current_trace_context(), None);
        });
    }

    #[test]
    fn trace_context_carries_the_current_span() {
        with_otel_subscriber(|| {
            let span = http_request_span(&request(Some(TRACEPARENT)), "req-4");
            let _guard = span.enter();
            let context = current_trace_context().unwrap();
            // Same trace as the caller's, but the gateway's own span id
            assert!(context.traceparent.starts_with(&format!("00-{TRACE_ID}-")));
            assert!(!context.traceparent.contains("00f067aa0c3b4e8e"));
            assert_eq!(context.tracestate, None);
        });
    }

    #[test]
    fn trace_context_keeps_the_tracestate() {
        with_otel_subscriber(|| {
            let mut builder = Request::builder().method("GET").uri("/");
            builder = builder
                .header("traceparent", TRACEPARENT)
                .header("tracestate", "vendor=value");
            let request = builder.body(()).unwrap();
            let span = http_request_span(&request, "req-5");
            let _guard = span.enter();
            let context = current_trace_context().unwrap();
            assert_eq!(context.tracestate.as_deref(), Some("vendor=value"));
        });
    }
}
