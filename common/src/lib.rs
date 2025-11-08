pub mod logging {
    use std::sync::Once;
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::{fmt, EnvFilter};

    static INIT: Once = Once::new();

    /// Initialize global tracing subscriber with env-driven config.
    ///
    /// Env:
    /// - RUST_LOG   (e.g., "info,axum=warn,tower_http=off")
    /// - LOG_FORMAT ("plain" [default] | "json")
    ///
    /// `default_filter` is used if RUST_LOG is unset.
    pub fn init(default_filter: &str) {
        INIT.call_once(|| {
            // Build env filter with sane fallback
            let env_filter = EnvFilter::try_from_env("RUST_LOG")
                .or_else(|_| EnvFilter::try_new(default_filter))
                .unwrap_or_else(|_| EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into()));

            let json = std::env::var("LOG_FORMAT")
                .map(|v| v.eq_ignore_ascii_case("json"))
                .unwrap_or(false);

            if json {
                // JSON formatter branch
                fmt()
                    .with_env_filter(env_filter)
                    .json()
                    .with_timer(fmt::time::UtcTime::rfc_3339())
                    .with_file(true)
                    .with_line_number(true)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_thread_names(true)
                    .with_ansi(false)
                    .init();
            } else {
                // Plain formatter branch
                fmt()
                    .with_env_filter(env_filter)
                    .with_timer(fmt::time::UtcTime::rfc_3339())
                    .with_file(true)
                    .with_line_number(true)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_thread_names(true)
                    .with_ansi(cfg!(unix))
                    .init();
            }

            tracing::info!("logging initialized");
        });
    }
}
