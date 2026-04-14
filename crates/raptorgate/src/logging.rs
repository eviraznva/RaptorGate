use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::path::{Path, PathBuf};
use time::{Date, OffsetDateTime};
use std::fs::{self, File, OpenOptions};
use tracing_subscriber::fmt::MakeWriter;

const DEFAULT_FIREWALL_LOG_DIR: &str = "/var/log/raptorgate/firewall";
const FIREWALL_LOG_DIR_ENV: &str = "RAPTORGATE_FIREWALL_LOG_DIR";

pub fn init() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let log_dir = std::env::var(FIREWALL_LOG_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_FIREWALL_LOG_DIR));

    let writer = DailyLogMakeWriter::new(log_dir)?;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_writer(writer)
        .try_init()?;

    Ok(())
}

#[derive(Clone)]
struct DailyLogMakeWriter {
    state: Arc<Mutex<DailyLogState>>,
}

impl DailyLogMakeWriter {
    fn new(log_dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&log_dir)?;

        Ok(Self {
            state: Arc::new(Mutex::new(DailyLogState::new(log_dir))),
        })
    }
}

impl<'a> MakeWriter<'a> for DailyLogMakeWriter {
    type Writer = DailyLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        DailyLogWriter {
            state: Arc::clone(&self.state),
        }
    }
}

struct DailyLogWriter {
    state: Arc<Mutex<DailyLogState>>,
}

impl Write for DailyLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("daily log writer lock poisoned"))?;
            state.write(buf)?
        };

        let _ = io::stdout().write_all(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("daily log writer lock poisoned"))?;
            state.flush()?;
        }

        let _ = io::stdout().flush();
        Ok(())
    }
}

struct DailyLogState {
    log_dir: PathBuf,
    current_file_name: Option<String>,
    file: Option<File>,
}

impl DailyLogState {
    fn new(log_dir: PathBuf) -> Self {
        Self {
            log_dir,
            current_file_name: None,
            file: None,
        }
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ensure_current_file()?;
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("daily log file was not opened"))?
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.flush()?;
        }

        Ok(())
    }

    fn ensure_current_file(&mut self) -> io::Result<()> {
        let file_name = current_log_file_name();

        if self.current_file_name.as_deref() == Some(file_name.as_str()) {
            return Ok(());
        }

        fs::create_dir_all(&self.log_dir)?;
        self.file = Some(open_log_file(&self.log_dir, &file_name)?);
        self.current_file_name = Some(file_name);

        Ok(())
    }
}

fn current_log_file_name() -> String {
    let date = OffsetDateTime::now_local()
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
        .date();

    log_file_name_for_date(date)
}

fn open_log_file(log_dir: &Path, file_name: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o640);
    }

    options.open(log_dir.join(file_name))
}

fn log_file_name_for_date(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}.log",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

#[cfg(test)]
mod tests {
    use super::log_file_name_for_date;
    use time::{Date, Month};

    #[test]
    fn names_log_file_with_iso_calendar_date() {
        let date =
            Date::from_calendar_date(2026, Month::April, 14).expect("test date should be valid");

        assert_eq!(log_file_name_for_date(date), "2026-04-14.log");
    }
}
