use std::sync::Arc;

use anyhow::{Context, Result};
use time::{UtcOffset, format_description};
use tracing_log::LogTracer;
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::filter::dynamic_filter_fn;
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::fmt::format::{DefaultFields, Writer};
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};
use warpgate_common::{LogFormat, WarpgateConfig};
use warpgate_core::logging::{
    make_database_logger_layer, make_json_console_logger_layer, make_socket_logger_layer,
};

use crate::Cli;

pub async fn init_logging(config: Option<&WarpgateConfig>, cli: &Cli) -> Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        #[allow(unsafe_code)]
        unsafe {
            match cli.debug {
                0 => std::env::set_var("RUST_LOG", "audit=info,warpgate=info"),
                1 => std::env::set_var("RUST_LOG", "audit=info,warpgate=debug"),
                2 => std::env::set_var("RUST_LOG", "audit=info,warpgate=debug,russh=debug"),
                _ => std::env::set_var("RUST_LOG", "debug"),
            }
        }
    }

    LogTracer::init().context("Failed to initialize log compatibility layer")?;

    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);

    let env_filter = Arc::new(EnvFilter::from_default_env());
    let enable_colors = console::user_attended();

    // Determine effective log format (CLI overrides config)
    let log_format = cli
        .log_format
        .or_else(|| config.map(|c| c.store.log.format))
        .unwrap_or_default();

    let registry = tracing_subscriber::registry();

    // #[cfg(all(debug_assertions, feature = "tokio-console"))]
    // let console_layer = console_subscriber::spawn();
    // #[cfg(all(debug_assertions, feature = "tokio-console"))]
    // let registry = registry.with(console_layer);

    let socket_layer = match config {
        Some(config) => Some(make_socket_logger_layer(config).await),
        None => None,
    };

    // Create JSON console layer (only active when format is JSON)
    let json_layer = (log_format == LogFormat::Json).then(|| {
        let env_filter = env_filter.clone();
        make_json_console_logger_layer().with_filter(dynamic_filter_fn(move |m, c| {
            env_filter.enabled(m, c.clone())
        }))
    });

    // Create text console layers (only active when format is Text)
    let text_layer_non_interactive = (log_format == LogFormat::Text && !console::user_attended())
        .then({
            let env_filter = env_filter.clone();
            || {
                tracing_subscriber::fmt::layer()
                    .fmt_fields(LineSafeFields::default())
                    .with_ansi(enable_colors)
                    .with_timer(OffsetTime::new(
                        offset,
                        #[allow(clippy::unwrap_used)]
                        format_description::parse_borrowed::<1>(
                            "[day].[month].[year] [hour]:[minute]:[second]",
                        )
                        .unwrap(),
                    ))
                    .with_filter(dynamic_filter_fn(move |m, c| {
                        env_filter.enabled(m, c.clone())
                    }))
            }
        });

    let text_layer_interactive =
        (log_format == LogFormat::Text && console::user_attended()).then(|| {
            tracing_subscriber::fmt::layer()
                .fmt_fields(LineSafeFields::default())
                .compact()
                .with_ansi(enable_colors)
                .with_target(false)
                .with_timer(OffsetTime::new(
                    offset,
                    #[allow(clippy::unwrap_used)]
                    format_description::parse_borrowed::<1>("[hour]:[minute]:[second]").unwrap(),
                ))
                .with_filter(dynamic_filter_fn(move |m, c| {
                    env_filter.enabled(m, c.clone())
                }))
        });

    let registry = registry
        .with(json_layer)
        .with(text_layer_non_interactive)
        .with(text_layer_interactive);

    let registry = registry
        .with(make_database_logger_layer())
        .with(socket_layer);

    registry.init();
    Ok(())
}

/// Formats fields as the default formatter does, then escapes every control
/// character it leaves alone, line breaks above all. A logged value can come
/// from a client (a username, a command), and one with a newline in it would
/// otherwise start a log line of its own.
#[derive(Default)]
struct LineSafeFields(DefaultFields);

impl<'writer> FormatFields<'writer> for LineSafeFields {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> std::fmt::Result {
        // A plain inner writer emits no ANSI styling of its own, so every
        // control character in `formatted` came from a value.
        let mut formatted = String::new();
        self.0.format_fields(Writer::new(&mut formatted), fields)?;
        write_line_safe(&mut writer, &formatted)
    }
}

fn write_line_safe(out: &mut impl std::fmt::Write, s: &str) -> std::fmt::Result {
    for c in s.chars() {
        match c {
            '\n' => out.write_str("\\n")?,
            '\r' => out.write_str("\\r")?,
            '\t' => out.write_char(c)?,
            c if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') => {
                write!(out, "\\u{{{:x}}}", u32::from(c))?
            }
            c => out.write_char(c)?,
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn logged(f: impl FnOnce()) -> String {
        let buf = Buf::default();
        let subscriber = tracing_subscriber::fmt()
            .fmt_fields(LineSafeFields::default())
            .with_ansi(false)
            .with_writer({
                let buf = buf.clone();
                move || buf.clone()
            })
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        String::from_utf8(buf.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn unit_a_client_value_never_starts_a_log_line() {
        let username = "alice\nINFO forged: client_ip=203.0.113.7\r\u{0}\u{2028}x";
        let out = logged(|| {
            let span = tracing::info_span!("session", user = %username);
            let _e = span.enter();
            tracing::info!(username = %username, "login as {username}");
            tracing::warn!("Selected user not found: {}", username);
        });
        assert_eq!(out.lines().count(), 2, "{out}");
        assert!(out.contains("alice\\nINFO forged"), "{out}");
        assert!(out.contains("\\r\\u{0}\\u{2028}x"), "{out}");
    }

    #[test]
    fn unit_ordinary_fields_are_unchanged() {
        let out = logged(|| tracing::info!(user = %"bob", n = 3, "Exec command\tdone"));
        assert!(out.contains("Exec command\tdone user=bob n=3"), "{out}");
    }
}
