//! Terminal state management.

use iced::{Subscription, Task};
use netsec_pty::{detect_available_shells, PtySession, ShellInfo};

use crate::message::{Message, TabId};

/// State for a single terminal tab.
pub struct TerminalTab {
    /// Unique identifier
    pub id: TabId,
    /// Shell information
    pub shell: ShellInfo,
    /// Display title
    pub title: String,
    /// PTY session (None if not yet created or closed)
    pub session: Option<PtySession>,
    /// Terminal state parser
    pub parser: vt100::Parser,
    /// Connection status
    pub status: TerminalStatus,
}

/// Terminal connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalStatus {
    Connecting,
    Connected,
    Disconnected,
    Error,
}

impl TerminalTab {
    /// Create a new terminal tab.
    pub fn new(shell: ShellInfo) -> Self {
        let id = TabId::new();
        let title = shell.name.clone();

        Self {
            id,
            shell,
            title,
            session: None,
            parser: vt100::Parser::new(24, 80, 1000), // rows, cols, scrollback
            status: TerminalStatus::Connecting,
        }
    }

    /// Get the rendered terminal content.
    pub fn screen_content(&self) -> String {
        let screen = self.parser.screen();
        let mut content = String::new();

        for row in 0..screen.size().0 {
            let row_content = screen.contents_between(
                row, 0,
                row, screen.size().1,
            );
            content.push_str(&row_content);
            content.push('\n');
        }

        content
    }

    /// Get the cursor position.
    pub fn cursor_position(&self) -> (u16, u16) {
        self.parser.screen().cursor_position()
    }
}

/// State for all terminals.
pub struct TerminalState {
    /// All terminal tabs
    pub tabs: Vec<TerminalTab>,
    /// Currently active tab index
    pub active_index: Option<usize>,
    /// Available shells on this system
    pub available_shells: Vec<ShellInfo>,
}

impl TerminalState {
    /// Create new terminal state.
    pub fn new() -> Self {
        Self {
            tabs: Vec::new(),
            active_index: None,
            available_shells: detect_available_shells(),
        }
    }

    /// Create a tab with the default shell.
    pub fn create_default_tab(&mut self) -> Task<Message> {
        if let Some(shell) = self.available_shells.first().cloned() {
            self.create_tab(shell)
        } else {
            Task::none()
        }
    }

    /// Create a new terminal tab with the given shell.
    pub fn create_tab(&mut self, shell: ShellInfo) -> Task<Message> {
        let mut tab = TerminalTab::new(shell.clone());

        // Try to create PTY session
        match PtySession::new(&shell, 80, 24) {
            Ok(session) => {
                tab.session = Some(session);
                tab.status = TerminalStatus::Connected;
                tracing::info!("Created terminal session for {}", shell.name);
            }
            Err(e) => {
                tracing::error!("Failed to create PTY session: {}", e);
                tab.status = TerminalStatus::Error;
            }
        }

        self.tabs.push(tab);
        self.active_index = Some(self.tabs.len() - 1);

        Task::none()
    }

    /// Close a terminal tab.
    pub fn close_tab(&mut self, tab_id: TabId) {
        if let Some(pos) = self.tabs.iter().position(|t| t.id == tab_id) {
            self.tabs.remove(pos);

            // Adjust active index
            if self.tabs.is_empty() {
                self.active_index = None;
            } else if let Some(idx) = self.active_index {
                if idx >= self.tabs.len() {
                    self.active_index = Some(self.tabs.len() - 1);
                } else if pos <= idx && idx > 0 {
                    self.active_index = Some(idx - 1);
                }
            }
        }
    }

    /// Select a terminal tab.
    pub fn select_tab(&mut self, tab_id: TabId) {
        if let Some(pos) = self.tabs.iter().position(|t| t.id == tab_id) {
            self.active_index = Some(pos);
        }
    }

    /// Get the active tab.
    pub fn active_tab(&self) -> Option<&TerminalTab> {
        self.active_index.and_then(|idx| self.tabs.get(idx))
    }

    /// Get the active tab mutably.
    pub fn active_tab_mut(&mut self) -> Option<&mut TerminalTab> {
        self.active_index.and_then(|idx| self.tabs.get_mut(idx))
    }

    /// Write input to a terminal's PTY.
    pub fn write_input(&mut self, tab_id: TabId, input: &str) -> Task<Message> {
        if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == tab_id) {
            if let Some(ref session) = tab.session {
                let writer = session.writer();
                let input_bytes = input.as_bytes().to_vec();

                return Task::perform(
                    async move {
                        let mut w = writer.lock().await;
                        if let Err(e) = std::io::Write::write_all(&mut *w, &input_bytes) {
                            tracing::error!("PTY write error: {}", e);
                        }
                        let _ = std::io::Write::flush(&mut *w);
                    },
                    |_| Message::Tick,
                );
            }
        }
        Task::none()
    }

    /// Handle output from a terminal.
    pub fn handle_output(&mut self, tab_id: TabId, data: &[u8]) {
        if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == tab_id) {
            tab.parser.process(data);
        }
    }

    /// Handle terminal closed.
    pub fn handle_closed(&mut self, tab_id: TabId) {
        if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == tab_id) {
            tab.session = None;
            tab.status = TerminalStatus::Disconnected;
        }
    }

    /// Resize a terminal.
    pub fn resize_tab(&mut self, tab_id: TabId, cols: u16, rows: u16) {
        if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == tab_id) {
            tab.parser.set_size(rows, cols);
            if let Some(ref mut session) = tab.session {
                let _ = session.resize(cols, rows);
            }
        }
    }

    /// Get subscriptions for terminal output — polls each PTY reader.
    pub fn subscription(&self) -> Subscription<Message> {
        use std::io::Read;

        let subs: Vec<Subscription<Message>> = self
            .tabs
            .iter()
            .filter_map(|tab| {
                let session = tab.session.as_ref()?;
                if tab.status != TerminalStatus::Connected {
                    return None;
                }
                let reader = session.reader();
                let tab_id = tab.id;

                let stream = iced::stream::channel(64, move |mut sender| {
                    let reader = reader.clone();
                    async move {
                        loop {
                            let reader_clone = reader.clone();
                            let result = tokio::task::spawn_blocking(move || {
                                let mut buf = [0u8; 4096];
                                let mut r = reader_clone.blocking_lock();
                                r.read(&mut buf).map(|n| buf[..n].to_vec())
                            })
                            .await;

                            match result {
                                Ok(Ok(data)) if !data.is_empty() => {
                                    let _ = sender
                                        .try_send(Message::TerminalOutput(tab_id, data));
                                }
                                Ok(Ok(_)) => {
                                    let _ = sender
                                        .try_send(Message::TerminalClosed(tab_id));
                                    break;
                                }
                                Ok(Err(_)) | Err(_) => {
                                    let _ = sender
                                        .try_send(Message::TerminalClosed(tab_id));
                                    break;
                                }
                            }
                        }
                        std::future::pending::<()>().await;
                        unreachable!()
                    }
                });

                Some(Subscription::run_with_id(tab_id.0, stream))
            })
            .collect();

        Subscription::batch(subs)
    }
}

impl Default for TerminalState {
    fn default() -> Self {
        Self::new()
    }
}
