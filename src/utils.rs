use log::LevelFilter as LogLevelFilter;
use std::env::var;

#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq, Hash)]
pub enum LevelFilter {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Into<LogLevelFilter> for LevelFilter {
    fn into(self) -> LogLevelFilter {
        match self {
            LevelFilter::Debug => LogLevelFilter::Debug,
            LevelFilter::Warn => LogLevelFilter::Warn,
            LevelFilter::Error => LogLevelFilter::Error,
            LevelFilter::Trace => LogLevelFilter::Trace,
            LevelFilter::Info => LogLevelFilter::Info,
            LevelFilter::Off => LogLevelFilter::Off,
        }
    }
}

pub fn non_empty_env_var(name: &str) -> Option<String> {
    match var(name) {
        Ok(value) => {
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        }
        Err(_) => None,
    }
}
