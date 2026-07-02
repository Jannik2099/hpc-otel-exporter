//! OpenTelemetry plumbing shared by every signal this process emits: the OTLP
//! exporters and global providers for logs and traces, the shared resource, and a
//! couple of small helpers. Per-cgroup *metrics* providers live in
//! [`crate::cgroup`]; the IO and profiling features build their own instruments.

use std::ffi::CStr;

use opentelemetry::trace::TracerProvider;
use opentelemetry::{Key, KeyValue};
use opentelemetry_appender_log::OpenTelemetryLogBridge;
use opentelemetry_otlp::tonic_types::transport::ClientTlsConfig;
use opentelemetry_otlp::{
    Compression, LogExporter, Protocol, SpanExporter, WithExportConfig, WithTonicConfig,
};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::{SdkLogger, SdkLoggerProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;

/// Best-effort system hostname, recorded as the `host.name` resource attribute on
/// every signal (metrics and traces) so series can be correlated per node, and
/// reused as a profile label by the CPU profiler.
pub(crate) fn hostname() -> String {
    let mut buf = [0u8; 4096];
    let _ = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    CStr::from_bytes_until_nul(&buf)
        .unwrap_or(c"unknown")
        .to_str()
        .unwrap_or("unknown")
        .to_owned()
}

/// The OTel resource shared by every signal this process emits. `service.name` and
/// any `OTEL_RESOURCE_ATTRIBUTES` are picked up from the environment by the default
/// detectors; we fall back to the node's hostname for `host.name` and
/// `service.instance.id`, but only where the detectors didn't already set them.
/// An explicit `OTEL_RESOURCE_ATTRIBUTES` value always wins.
pub(crate) fn build_resource() -> Resource {
    let detected = Resource::builder().build();
    let hostname = hostname();
    let fallback = [
        Key::from_static_str("host.name"),
        Key::from_static_str("service.instance.id"),
    ]
    .into_iter()
    .filter(|key| detected.get(key).is_none())
    .map(|key| KeyValue::new(key, hostname.clone()));

    Resource::builder().with_attributes(fallback).build()
}

/// TLS config for the OTLP/gRPC exporters. opentelemetry-otlp auto-enables TLS for
/// `https://` endpoints, but only with an *empty* root store unless given an
/// explicit config. Who the fuck came up with this?
pub(crate) fn otlp_tls_config() -> ClientTlsConfig {
    ClientTlsConfig::new().with_enabled_roots()
}

/// Mark a `tracing` span as failed, setting the OTel `ERROR` status through the
/// `otel.status_code` / `otel.status_description` fields the
/// tracing-opentelemetry layer recognises (see its `SpanAttributeVisitor`).
///
/// Both fields must be declared on the span (e.g. as [`tracing::field::Empty`])
/// at creation for the later `record` to take effect — `tracing` ignores
/// recordings for fields a span doesn't have.
pub(crate) fn record_span_error(span: &tracing::Span, err: &impl std::fmt::Display) {
    span.record("otel.status_code", "ERROR");
    span.record("otel.status_description", err.to_string().as_str());
}

/// Installs a global [`SdkTracerProvider`] exporting spans over OTLP/gRPC, so any
/// code can create spans via [`opentelemetry::global::tracer`]. The returned
/// guard must be kept alive for the process' lifetime; dropping it flushes and
/// shuts the provider down so buffered spans are exported on a clean exit.
#[must_use = "spans stop being exported once the guard is dropped"]
pub fn init_tracing() -> TracingGuard {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_protocol(Protocol::Grpc)
        .with_compression(Compression::Zstd)
        .with_tls_config(otlp_tls_config())
        .build()
        .expect("failed to create OTLP span exporter");

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(build_resource())
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());

    let otel_layer = OpenTelemetryLayer::new(provider.tracer("hpc-otel-exporter"));

    let subscriber = tracing_subscriber::registry().with(otel_layer);
    // Set the subscriber directly rather than via `.init()`: the latter also
    // installs a `tracing-log` `LogTracer` as the global `log` logger, which
    // collides with the `DualLogger` already installed by `init_logging` and
    // panics with `SetLoggerError`. We keep `log` records (-> DualLogger ->
    // console + OTLP logs) and `tracing` spans (-> OTLP traces) on separate
    // pipelines on purpose.
    tracing::subscriber::set_global_default(subscriber)
        .expect("failed to set global default tracing subscriber");
    TracingGuard(provider)
}

/// Flushes and shuts the global tracer provider down when dropped.
pub struct TracingGuard(SdkTracerProvider);

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Err(e) = self.0.shutdown() {
            log::warn!("failed to shut down tracer provider: {e}");
        }
    }
}

/// Fans every `log` record to two sinks: the console (via `env_logger`, the
/// project's existing human-readable output) and the OpenTelemetry log bridge
/// (which exports it over OTLP). Per-target verbosity is still governed by
/// `RUST_LOG`: `env_logger` applies its own directives, and the global max level
/// (set in [`init_logging`]) gates what reaches either sink.
struct DualLogger {
    console: env_logger::Logger,
    otel: OpenTelemetryLogBridge<SdkLoggerProvider, SdkLogger>,
}

impl log::Log for DualLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.console.enabled(metadata) || self.otel.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        // `env_logger` applies its own `RUST_LOG` filtering inside `log`; the
        // bridge exports whatever passed the global max level.
        self.console.log(record);
        self.otel.log(record);
    }

    fn flush(&self) {
        self.console.flush();
        self.otel.flush();
    }
}

/// Flushes and shuts the OpenTelemetry logger provider down when dropped, so
/// buffered log records are exported on a clean exit.
pub struct LoggingGuard(SdkLoggerProvider);

impl Drop for LoggingGuard {
    fn drop(&mut self) {
        if let Err(e) = self.0.shutdown() {
            // The `log` logger is being torn down, so report directly.
            eprintln!("failed to shut down logger provider: {e}");
        }
    }
}

/// Installs the global `log` logger: console output (`env_logger`, honouring
/// `env`/`RUST_LOG`) plus OTLP export of every record through the OpenTelemetry
/// [appender bridge]. Returns a guard that must be kept alive for the process'
/// lifetime; dropping it flushes and shuts the logger provider down.
///
/// Call once, before any other telemetry, so even setup-time logs are exported.
///
/// [appender bridge]: opentelemetry_appender_log::OpenTelemetryLogBridge
#[must_use = "log records stop being exported once the guard is dropped"]
pub fn init_logging(env: env_logger::Env<'_>) -> LoggingGuard {
    let exporter = LogExporter::builder()
        .with_tonic()
        .with_protocol(Protocol::Grpc)
        .with_compression(Compression::Zstd)
        .with_tls_config(otlp_tls_config())
        .build()
        .expect("failed to create OTLP log exporter");

    let provider = SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(build_resource())
        .build();

    let console = env_logger::Builder::from_env(env).build();
    // Gate both sinks at the most verbose level env_logger is configured for.
    let max_level = console.filter();

    let logger = DualLogger {
        console,
        otel: OpenTelemetryLogBridge::new(&provider),
    };
    log::set_boxed_logger(Box::new(logger)).expect("global logger already set");
    log::set_max_level(max_level);

    LoggingGuard(provider)
}
