//! CanvasWebview - Wry webview manager for the React NetworkCanvas.
//!
//! This module manages the lifecycle of a Wry webview that renders
//! the React NetworkCanvas component within the Iced application.

use std::sync::mpsc;
use wry::{WebView, WebViewBuilder, Rect, dpi::LogicalPosition, dpi::LogicalSize};
use crate::webview::ipc::{NetworkStateJson, WebviewEvent};

/// Error type for webview operations.
#[derive(Debug, thiserror::Error)]
pub enum WebviewError {
    #[error("Wry error: {0}")]
    Wry(#[from] wry::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Webview not ready")]
    NotReady,
    #[error("{0}")]
    Custom(String),
}

/// Manages the Wry webview for the NetworkCanvas.
pub struct CanvasWebview {
    webview: WebView,
    is_ready: bool,
    bounds: Rect,
}

impl CanvasWebview {
    /// Create a new CanvasWebview with the given parent window.
    ///
    /// On Windows, `parent` should be HWND.
    /// The webview will be created but not immediately visible.
    #[cfg(target_os = "windows")]
    pub fn new(
        parent_hwnd: isize,
        event_tx: mpsc::Sender<WebviewEvent>,
    ) -> Result<Self, WebviewError> {

        // Build the webview with the embedded HTML + inlined widget JS.
        // We must inline widget.js because with_html() has no base URL,
        // so relative <script src="./widget.js"> would never resolve.
        let html_template = include_str!("../../assets/webview/index.html");
        let widget_js = include_str!("../../assets/webview/widget.js");
        let html_content = html_template.replace(
            r#"<script src="./widget.js" onerror="console.warn('Widget bundle not found')"></script>"#,
            &format!("<script>{}</script>", widget_js),
        );

        // Create the IPC handler closure
        let webview = WebViewBuilder::new()
            .with_html(&html_content)
            .with_transparent(true)
            .with_bounds(Rect {
                position: LogicalPosition::new(0.0, 0.0).into(),
                size: LogicalSize::new(800.0, 600.0).into(),
            })
            .with_ipc_handler(move |request| {
                // The request body contains the JSON message from JavaScript
                let msg_str = request.body();

                // Parse JSON message from JavaScript
                match serde_json::from_str::<WebviewEvent>(msg_str) {
                    Ok(event) => {
                        if let Err(e) = event_tx.send(event) {
                            tracing::error!("Failed to send webview event: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse webview message: {} - {}", e, msg_str);
                    }
                }
            })
            .build_as_child(&ParentWindow(parent_hwnd))?;

        Ok(Self {
            webview,
            is_ready: false,
            bounds: Rect {
                position: LogicalPosition::new(0.0, 0.0).into(),
                size: LogicalSize::new(800.0, 600.0).into(),
            },
        })
    }

    /// Create a new CanvasWebview on Linux (X11).
    #[cfg(target_os = "linux")]
    pub fn new(
        parent_xwindow: isize,
        event_tx: mpsc::Sender<WebviewEvent>,
    ) -> Result<Self, WebviewError> {
        // Ensure GTK is initialized (required by webkit2gtk)
        if gtk::init().is_err() {
            tracing::warn!("GTK already initialized or init failed, continuing anyway");
        }

        let html_template = include_str!("../../assets/webview/index.html");
        let widget_js = include_str!("../../assets/webview/widget.js");
        let needle = r#"<script src="./widget.js" onerror="console.warn('Widget bundle not found')"></script>"#;
        let match_count = html_template.matches(needle).count();
        tracing::info!("widget.js tag match_count={}", match_count);
        if match_count != 1 {
            tracing::error!("widget.js replacement needle matched {} times (expected 1)", match_count);
        }

        let html_content = html_template.replace(needle, &format!("<script>{}</script>", widget_js));

        if html_content.contains(r#"src="./widget.js""#) {
            tracing::error!("external widget.js tag still present after replacement!");
        }
        tracing::info!(
            "final_html length={} contains_bundle_boot={}",
            html_content.len(),
            html_content.contains("__widgetBundleLoaded")
        );

        let webview = WebViewBuilder::new()
            .with_html(&html_content)
            .with_transparent(true)
            .with_bounds(Rect {
                position: LogicalPosition::new(0.0, 0.0).into(),
                size: LogicalSize::new(800.0, 600.0).into(),
            })
            .with_ipc_handler(move |request| {
                let msg_str = request.body();
                match serde_json::from_str::<WebviewEvent>(msg_str) {
                    Ok(event) => {
                        if let Err(e) = event_tx.send(event) {
                            tracing::error!("Failed to send webview event: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse webview message: {} - {}", e, msg_str);
                    }
                }
            })
            .build_as_child(&ParentWindow(parent_xwindow))?;

        Ok(Self {
            webview,
            is_ready: false,
            bounds: Rect {
                position: LogicalPosition::new(0.0, 0.0).into(),
                size: LogicalSize::new(800.0, 600.0).into(),
            },
        })
    }

    /// Create a new CanvasWebview (unsupported platforms).
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    pub fn new(
        _parent_handle: isize,
        _event_tx: mpsc::Sender<WebviewEvent>,
    ) -> Result<Self, WebviewError> {
        Err(WebviewError::Custom("Unsupported platform".into()))
    }

    /// Mark the webview as ready (called when we receive Ready event).
    pub fn set_ready(&mut self) {
        self.is_ready = true;
        tracing::info!("Canvas webview is ready");
    }

    /// Check if the webview is ready to receive state updates.
    pub fn is_ready(&self) -> bool {
        self.is_ready
    }

    /// Update the network state in the webview.
    pub fn update_state(&self, state: &NetworkStateJson) -> Result<(), WebviewError> {
        if !self.is_ready {
            return Err(WebviewError::NotReady);
        }

        let json = serde_json::to_string(state)?;
        let seq = state.seq;

        // Wrap in try/catch so we can detect JS-side failures.
        // Also log which bridge variant (placeholder vs React) receives the call.
        let script = format!(
            r#"(function() {{
  var seq = {seq};
  try {{
    var payload = {json};
    var fnType = typeof window.updateNetworkState;
    console.log("[rust->js] seq=" + seq + " fn=" + fnType +
                " nodes=" + (payload.nodes ? payload.nodes.length : "?") +
                " conns=" + (payload.connections ? payload.connections.length : "?"));
    if (fnType !== "function") {{
      throw new Error("window.updateNetworkState is " + fnType);
    }}
    window.updateNetworkState(payload);
    return JSON.stringify({{ ok: true, seq: seq, fnType: fnType }});
  }} catch (e) {{
    console.error("[rust->js] FAILED seq=" + seq, e);
    return JSON.stringify({{
      ok: false,
      seq: seq,
      err: String(e),
      stack: e && e.stack ? e.stack : null
    }});
  }}
}})()"#
        );

        self.webview.evaluate_script(&script)?;
        Ok(())
    }

    /// Set the bounds of the webview within the parent window.
    pub fn set_bounds(&mut self, x: f64, y: f64, width: f64, height: f64) -> Result<(), WebviewError> {
        let new_bounds = Rect {
            position: LogicalPosition::new(x, y).into(),
            size: LogicalSize::new(width, height).into(),
        };

        // Only update if bounds have changed
        if self.bounds.position != new_bounds.position || self.bounds.size != new_bounds.size {
            self.bounds = new_bounds;
            self.webview.set_bounds(self.bounds)?;
        }

        Ok(())
    }

    /// Get the current bounds.
    pub fn bounds(&self) -> &Rect {
        &self.bounds
    }

    /// Focus the webview.
    pub fn focus(&self) -> Result<(), WebviewError> {
        self.webview.focus()?;
        Ok(())
    }

    /// Execute arbitrary JavaScript in the webview.
    pub fn evaluate_script(&self, script: &str) -> Result<(), WebviewError> {
        self.webview.evaluate_script(script)?;
        Ok(())
    }
}

/// Wrapper for parent window handle on Windows.
#[cfg(target_os = "windows")]
struct ParentWindow(isize);

#[cfg(target_os = "windows")]
impl raw_window_handle::HasWindowHandle for ParentWindow {
    fn window_handle(&self) -> Result<raw_window_handle::WindowHandle<'_>, raw_window_handle::HandleError> {
        use raw_window_handle::{RawWindowHandle, Win32WindowHandle};
        use std::num::NonZeroIsize;

        let handle = Win32WindowHandle::new(
            NonZeroIsize::new(self.0).expect("Invalid HWND")
        );

        let raw = RawWindowHandle::Win32(handle);
        // Safety: The handle is valid for the lifetime of the parent window
        Ok(unsafe { raw_window_handle::WindowHandle::borrow_raw(raw) })
    }
}

/// Wrapper for parent window handle on Linux (X11).
#[cfg(target_os = "linux")]
struct ParentWindow(isize);

#[cfg(target_os = "linux")]
impl raw_window_handle::HasWindowHandle for ParentWindow {
    fn window_handle(&self) -> Result<raw_window_handle::WindowHandle<'_>, raw_window_handle::HandleError> {
        use raw_window_handle::{RawWindowHandle, XlibWindowHandle};

        let handle = XlibWindowHandle::new(self.0 as u64);
        let raw = RawWindowHandle::Xlib(handle);
        // Safety: The handle is valid for the lifetime of the parent window
        Ok(unsafe { raw_window_handle::WindowHandle::borrow_raw(raw) })
    }
}

/// Factory function to create the webview assets directory path.
#[allow(dead_code)]
pub fn assets_dir() -> std::path::PathBuf {
    // In development, assets are in the crate's assets directory
    // In production, they would be embedded or in the executable's directory
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    exe_dir.join("assets").join("webview")
}
