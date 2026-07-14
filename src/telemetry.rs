//! OpenTelemetry plumbing shared by every signal this process emits: the OTLP
//! exporters and global providers for logs and traces, the shared resource, and a
//! couple of small helpers. Per-cgroup *metrics* providers live in
//! [`crate::cgroup`]; the IO and profiling features build their own instruments.

use std::ffi::CStr;
use std::time::Duration;

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
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{EnvFilter, LevelFilter, filter_fn};
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

/// The standard OTel SDK default for `OTEL_METRIC_EXPORT_INTERVAL` (60s), per
/// <https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/>.
const DEFAULT_METRIC_EXPORT_INTERVAL: Duration = Duration::from_secs(60);

/// The standard OTel SDK default for `OTEL_METRIC_EXPORT_TIMEOUT` (30s), per
/// <https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/>.
const DEFAULT_METRIC_EXPORT_TIMEOUT: Duration = Duration::from_secs(30);

/// Read a `Duration` from the standardized OTel env var `name`, whose value is a
/// count of milliseconds, falling back to `default` when unset. Panics on a value
/// that isn't a valid number, to fail fast at startup rather than silently ignore a
/// misconfiguration.
fn duration_from_env_millis(name: &str, default: Duration) -> Duration {
    match std::env::var(name) {
        Ok(val) => match val.parse::<u64>() {
            Ok(ms) => Duration::from_millis(ms.max(1)),
            Err(_) => panic!("{name}={val:?} is not a valid number of milliseconds"),
        },
        Err(_) => default,
    }
}

/// The interval between metrics collection/export ticks, taken from the
/// standardized `OTEL_METRIC_EXPORT_INTERVAL` env var (milliseconds).
pub(crate) fn metrics_export_interval() -> Duration {
    duration_from_env_millis(
        "OTEL_METRIC_EXPORT_INTERVAL",
        DEFAULT_METRIC_EXPORT_INTERVAL,
    )
}

/// The per-export timeout applied to each cgroup's OTLP metric export, taken from
/// the standardized `OTEL_METRIC_EXPORT_TIMEOUT` env var (milliseconds).
pub(crate) fn metrics_export_timeout() -> Duration {
    duration_from_env_millis("OTEL_METRIC_EXPORT_TIMEOUT", DEFAULT_METRIC_EXPORT_TIMEOUT)
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
/// code can create spans via [`opentelemetry::global::tracer`], and wires the
/// `tracing` subscriber that feeds it. The returned guard must be kept alive for
/// the process' lifetime; dropping it flushes and shuts the provider down so
/// buffered spans are exported on a clean exit.
///
/// Honours the standardized `OTEL_TRACES_EXPORTER` env var: when it is set to
/// `none`, neither the tracer provider nor the `tracing` subscriber is installed
/// and `None` is returned, so tracing is entirely opt-out. Any other value (or
/// unset) installs the OTLP exporter as usual.
#[must_use = "spans stop being exported once the guard is dropped"]
pub fn init_tracing() -> Option<TracingGuard> {
    // Per the OTel SDK spec, `OTEL_TRACES_EXPORTER=none` disables trace export.
    // We only support the OTLP exporter, so treat every other value (including
    // unset) as "install OTLP". Even when export is disabled we still install the
    // console `fmt` layer below, so the SDK's own diagnostics stay visible.
    let traces_disabled =
        std::env::var("OTEL_TRACES_EXPORTER").is_ok_and(|val| val.eq_ignore_ascii_case("none"));

    let (otel_layer, guard) = if traces_disabled {
        (None, None)
    } else {
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

        // Keep the SDK's own internal `tracing` events out of the OTLP trace layer:
        // exporting telemetry-about-telemetry risks a feedback loop. They still
        // reach the console `fmt` layer below.
        let layer = OpenTelemetryLayer::new(provider.tracer("hpc-otel-exporter")).with_filter(
            filter_fn(|meta| !meta.target().starts_with("opentelemetry")),
        );
        (Some(layer), Some(TracingGuard(provider)))
    };

    // Console sink for `tracing` events, honouring `RUST_LOG`. The OTel SDK emits
    // its internal diagnostics (exporter transport errors, retries, dropped
    // batches) through `tracing`, *not* `log`, so without this layer they never
    // reach the console however `RUST_LOG` is set. Defaults to INFO when `RUST_LOG`
    // is unset; scope the noise with e.g. `RUST_LOG=opentelemetry=debug`.
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        );

    let subscriber = tracing_subscriber::registry()
        .with(otel_layer)
        .with(fmt_layer);
    // Set the subscriber directly rather than via `.init()`: the latter also
    // installs a `tracing-log` `LogTracer` as the global `log` logger, which
    // collides with the `DualLogger` already installed by `init_logging` and
    // panics with `SetLoggerError`. We keep `log` records (-> DualLogger ->
    // console + OTLP logs) and `tracing` events (-> console + OTLP traces) on
    // separate pipelines on purpose.
    tracing::subscriber::set_global_default(subscriber)
        .expect("failed to set global default tracing subscriber");
    guard
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
    /// OTLP log bridge, or `None` when `OTEL_LOGS_EXPORTER=none` disables export.
    otel: Option<OpenTelemetryLogBridge<SdkLoggerProvider, SdkLogger>>,
}

impl log::Log for DualLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.console.enabled(metadata)
            || self
                .otel
                .as_ref()
                .is_some_and(|otel| otel.enabled(metadata))
    }

    fn log(&self, record: &log::Record) {
        // `env_logger` applies its own `RUST_LOG` filtering inside `log`; the
        // bridge exports whatever passed the global max level.
        self.console.log(record);
        if let Some(otel) = &self.otel {
            otel.log(record);
        }
    }

    fn flush(&self) {
        self.console.flush();
        if let Some(otel) = &self.otel {
            otel.flush();
        }
    }
}

/// Flushes and shuts the OpenTelemetry logger provider down when dropped, so
/// buffered log records are exported on a clean exit. Holds `None` when OTLP log
/// export is disabled via `OTEL_LOGS_EXPORTER=none`.
pub struct LoggingGuard(Option<SdkLoggerProvider>);

impl Drop for LoggingGuard {
    fn drop(&mut self) {
        if let Some(provider) = &self.0
            && let Err(e) = provider.shutdown()
        {
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
/// Honours the standardized `OTEL_LOGS_EXPORTER` env var: when it is set to
/// `none`, no logger provider or OTLP exporter is installed and only the console
/// sink remains, so OTLP log export is entirely opt-out. This matters when the
/// collector has no logs pipeline: otherwise the batch processor keeps trying to
/// export and the collector answers with gRPC `Unimplemented`. Any other value
/// (or unset) installs the OTLP exporter as usual.
///
/// [appender bridge]: opentelemetry_appender_log::OpenTelemetryLogBridge
#[must_use = "log records stop being exported once the guard is dropped"]
pub fn init_logging(env: env_logger::Env<'_>) -> LoggingGuard {
    // Per the OTel SDK spec, `OTEL_LOGS_EXPORTER=none` disables log export. We
    // only support the OTLP exporter, so treat every other value (including
    // unset) as "install OTLP".
    let logs_disabled =
        std::env::var("OTEL_LOGS_EXPORTER").is_ok_and(|val| val.eq_ignore_ascii_case("none"));

    let provider = (!logs_disabled).then(|| {
        let exporter = LogExporter::builder()
            .with_tonic()
            .with_protocol(Protocol::Grpc)
            .with_compression(Compression::Zstd)
            .with_tls_config(otlp_tls_config())
            .build()
            .expect("failed to create OTLP log exporter");

        SdkLoggerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(build_resource())
            .build()
    });

    let console = env_logger::Builder::from_env(env).build();
    // Gate both sinks at the most verbose level env_logger is configured for.
    let max_level = console.filter();

    let logger = DualLogger {
        console,
        otel: provider.as_ref().map(OpenTelemetryLogBridge::new),
    };
    log::set_boxed_logger(Box::new(logger)).expect("global logger already set");
    log::set_max_level(max_level);

    LoggingGuard(provider)
}
