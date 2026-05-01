use foundations::telemetry::log;
use foundations::telemetry::settings::Level;

pub struct H3ConnectionLogger;

impl H3ConnectionLogger {
    pub fn log(level: Level, message: impl AsRef<str>) {
        match level {
            Level::Warning => log::warn!("---HTTP/3--- {}", message.as_ref()),
            Level::Info => log::info!("---HTTP/3--- {}", message.as_ref()),
            Level::Debug => log::debug!("---HTTP/3--- {}", message.as_ref()),
            Level::Trace => log::trace!("---HTTP/3--- {}", message.as_ref()),
            _ => log::error!("---HTTP/3--- {}", message.as_ref()),
        }
    }
}
