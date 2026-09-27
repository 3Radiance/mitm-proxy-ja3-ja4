use tracing_subscriber::{fmt, EnvFilter};

#[macro_export]
macro_rules! log_tag {
    ($level:ident, $tag:expr, $($arg:tt)*) => {
        tracing::$level!(target: $tag, "[{}] {}", $tag, format_args!($($arg)*));
    };
}

pub fn init_logging() {
    let _ = fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("info"))
                .expect("valid tracing env filter"),
        )
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::ChronoLocal::rfc_3339())
        .event_format(tracing_subscriber::fmt::format().pretty())
        .try_init();
}

#[cfg(test)]
mod tests {
    #[test]
    fn logging_smoke_test() {
        super::init_logging();
        crate::log_tag!(info, "TCP", "smoke test message");
    }
}
