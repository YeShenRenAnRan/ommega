use std::sync::OnceLock;

use anyhow::Result;
use log::LevelFilter;

const DEFAULT_LOG_PATH: &str = "/data/adb/ommega-b/logs/relay.log";
/// 时间 | 级别 | pid/tid | 模块 | 消息。
///
/// 这个文件是好几个线程共写的（relay 主循环、hal_restart 的重试、keymaster 转发），
/// 不带 pid/tid 就分不清“哪行是哪个阶段写的”，而排查时最需要的正是这个。
/// 跟 A 端 `logging.rs` 的 PATTERN 保持同形。
const PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S)(utc)} [{h({l})}] [{P}/{T}] {M} - {m}{n}";

static LOGGER_INIT: OnceLock<()> = OnceLock::new();

/// Initialize the relay logger. All log sinks are controlled from the single
/// config file (`/data/adb/ommega-b/relay.conf`) via the `OMMEGA_RELAY_LOG_*`
/// and `OMMEGA_RELAY_LOGCAT_*` keys:
///
/// * `file_enabled` + `file_level` — on-disk log at `DEFAULT_LOG_PATH`
///   (`OMMEGA_RELAY_LOG_ENABLED` / `OMMEGA_RELAY_LOG_LEVEL`).
/// * `logcat_enabled` + `logcat_level` — Android logcat (tag `ommega-b`)
///   (`OMMEGA_RELAY_LOGCAT_ENABLED` / `OMMEGA_RELAY_LOGCAT_LEVEL`).
///
/// Either sink can be silenced independently; if both are `Off` the relay is
/// completely silent.
pub fn init_logger(
    file_enabled: bool,
    file_level: LevelFilter,
    logcat_enabled: bool,
    logcat_level: LevelFilter,
) {
    let _ = LOGGER_INIT.get_or_init(|| {
        if let Err(error) =
            init_logger_inner(file_enabled, file_level, logcat_enabled, logcat_level)
        {
            eprintln!("relay logging failed to initialize: {error:#}");
        }
    });
}

fn init_logger_inner(
    file_enabled: bool,
    file_level: LevelFilter,
    logcat_enabled: bool,
    logcat_level: LevelFilter,
) -> Result<()> {
    // Ensure the log directory exists (e.g. /data/adb/ommega-b/logs). Created as
    // root by the relay daemon; failure is non-fatal (logcat still works).
    if let Some(dir) = std::path::Path::new(DEFAULT_LOG_PATH).parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    let mut loggers: Vec<Box<dyn log::Log>> = Vec::new();
    let mut min_level = LevelFilter::Off;
    let mut logcat_ready = false;
    let mut file_logging_ready = false;

    if logcat_enabled && logcat_level != LevelFilter::Off {
        let config = android_logger::Config::default()
            .with_max_level(logcat_level)
            .with_tag("ommega-b");
        loggers.push(Box::new(android_logger::AndroidLogger::new(config)));
        min_level = min_level.max(logcat_level);
        logcat_ready = true;
    }

    if file_enabled && file_level != LevelFilter::Off {
        let (config, ready) = kmr_common::runtime::logging::build_console_file_config(
            DEFAULT_LOG_PATH,
            PATTERN,
            file_level,
            "relay logging",
        )?;
        if ready {
            loggers.push(Box::new(log4rs::Logger::new(config)));
            min_level = min_level.max(file_level);
            file_logging_ready = true;
        }
    }

    if loggers.is_empty() {
        // Everything disabled: stay fully silent.
        log::set_max_level(LevelFilter::Off);
        return Ok(());
    }

    multi_log::MultiLogger::init(loggers, log::Level::Trace)?;
    log::set_max_level(min_level);

    if !logcat_ready {
        log::info!("logcat logging disabled by config (file only)");
    } else if !file_logging_ready {
        log::info!("file logging disabled by config (logcat only)");
    } else {
        log::info!(
            "file logging enabled at {} with level {:?}",
            DEFAULT_LOG_PATH,
            file_level
        );
    }

    Ok(())
}
