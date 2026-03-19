//! PTY session management.

use portable_pty::{native_pty_system, CommandBuilder, PtyPair, PtySize};
use std::io::{Read, Write};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::shell::ShellInfo;

/// Errors that can occur during PTY operations.
#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    #[error("Failed to create PTY: {0}")]
    Creation(String),

    #[error("Failed to spawn shell: {0}")]
    Spawn(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PTY not initialized")]
    NotInitialized,
}

/// A PTY session wrapping a shell process.
pub struct PtySession {
    pair: PtyPair,
    reader: Arc<Mutex<Box<dyn Read + Send>>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    shell: ShellInfo,
    size: PtySize,
}

impl PtySession {
    /// Create a new PTY session with the given shell.
    pub fn new(shell: &ShellInfo, cols: u16, rows: u16) -> Result<Self, PtyError> {
        let pty_system = native_pty_system();

        let size = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };

        let pair = pty_system
            .openpty(size)
            .map_err(|e| PtyError::Creation(e.to_string()))?;

        // Build the command
        let mut cmd = CommandBuilder::new(&shell.path);

        // Set up environment
        #[cfg(windows)]
        {
            // Windows-specific setup
            cmd.env("TERM", "xterm-256color");
        }

        #[cfg(unix)]
        {
            cmd.env("TERM", "xterm-256color");
            cmd.env("COLORTERM", "truecolor");
        }

        // Spawn the shell
        let _child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| PtyError::Spawn(e.to_string()))?;

        // Get reader and writer
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| PtyError::Creation(e.to_string()))?;

        let writer = pair
            .master
            .take_writer()
            .map_err(|e| PtyError::Creation(e.to_string()))?;

        Ok(Self {
            pair,
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            shell: shell.clone(),
            size,
        })
    }

    /// Get the shell info for this session.
    pub fn shell(&self) -> &ShellInfo {
        &self.shell
    }

    /// Get the current terminal size.
    pub fn size(&self) -> (u16, u16) {
        (self.size.cols, self.size.rows)
    }

    /// Resize the terminal.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<(), PtyError> {
        self.size = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };

        self.pair
            .master
            .resize(self.size)
            .map_err(|e| PtyError::Creation(e.to_string()))?;

        Ok(())
    }

    /// Write data to the PTY (send input to the shell).
    pub async fn write(&self, data: &[u8]) -> Result<(), PtyError> {
        let mut writer = self.writer.lock().await;
        writer.write_all(data)?;
        writer.flush()?;
        Ok(())
    }

    /// Read available data from the PTY (get output from the shell).
    ///
    /// This is a blocking read that should be called from a dedicated thread/task.
    /// Returns the number of bytes read, or 0 if the PTY is closed.
    pub fn read_blocking(&self, buf: &mut [u8]) -> Result<usize, PtyError> {
        // We need to use try_lock here since this is called from sync context
        let mut reader = self.reader.blocking_lock();
        match reader.read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(PtyError::Io(e)),
        }
    }

    /// Get a clone of the reader for async reading.
    pub fn reader(&self) -> Arc<Mutex<Box<dyn Read + Send>>> {
        Arc::clone(&self.reader)
    }

    /// Get a clone of the writer for async writing.
    pub fn writer(&self) -> Arc<Mutex<Box<dyn Write + Send>>> {
        Arc::clone(&self.writer)
    }
}

impl std::fmt::Debug for PtySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtySession")
            .field("shell", &self.shell)
            .field("size", &format!("{}x{}", self.size.cols, self.size.rows))
            .finish()
    }
}
