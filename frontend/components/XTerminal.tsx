import React, { useEffect, useRef, useCallback, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';
import { ShellInfo, TerminalSessionState } from '../types';
import { RefreshCw } from 'lucide-react';

const API_ORIGIN = (import.meta.env.VITE_NETSEC_API_ORIGIN as string | undefined)?.replace(/\/$/, '') || 'http://127.0.0.1:8420';
const API_BASE = `${API_ORIGIN}/api`;
const WS_BASE = (import.meta.env.VITE_NETSEC_WS_URL as string | undefined)?.replace(/\/ws$/, '') || API_ORIGIN.replace(/^http/, 'ws');
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_BASE_DELAY_MS = 1000;
const RESIZE_DEBOUNCE_MS = 150;
const CLIENT_PING_INTERVAL_MS = 5000;

interface XTerminalProps {
  tabId: string;
  shell: ShellInfo | null;
  sessionId: string | null;
  onSessionCreated: (sessionId: string) => void;
  onStateChange: (state: TerminalSessionState) => void;
}

export const XTerminal: React.FC<XTerminalProps> = ({
  tabId,
  shell,
  sessionId,
  onSessionCreated,
  onStateChange,
}) => {
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const isCreatingSessionRef = useRef(false);
  const resizeTimerRef = useRef<number | null>(null);
  const pingIntervalRef = useRef<number | null>(null);

  const [connectionFailed, setConnectionFailed] = useState(false);

  // Debounced resize — avoids hammering the backend and FitAddon width-collapse bug
  const debouncedResize = useCallback(() => {
    if (resizeTimerRef.current) {
      clearTimeout(resizeTimerRef.current);
    }
    resizeTimerRef.current = window.setTimeout(() => {
      const fit = fitAddonRef.current;
      const term = xtermRef.current;
      if (!fit || !term) return;

      // Guard against zero-dimension containers (FitAddon returns undefined)
      const dims = fit.proposeDimensions();
      if (!dims || dims.cols < 2 || dims.rows < 1) return;

      fit.fit();

      // Send resize to backend only if WS is open
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({
          type: 'resize',
          cols: term.cols,
          rows: term.rows,
        }));
      }
    }, RESIZE_DEBOUNCE_MS);
  }, []);

  // Create a new terminal session
  const createSession = useCallback(async () => {
    if (isCreatingSessionRef.current) return null;
    isCreatingSessionRef.current = true;

    onStateChange('creating');

    try {
      const response = await fetch(`${API_BASE}/terminal/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ shell: shell?.path || null }),
      });

      if (!response.ok) {
        throw new Error('Failed to create session');
      }

      const data = await response.json();
      onSessionCreated(data.session_id);
      return data.session_id;
    } catch (e) {
      onStateChange('error');
      if (xtermRef.current) {
        xtermRef.current.writeln('\x1b[31mFailed to create terminal session.\x1b[0m');
      }
      return null;
    } finally {
      isCreatingSessionRef.current = false;
    }
  }, [shell, onSessionCreated, onStateChange]);

  // Initialize xterm.js terminal
  useEffect(() => {
    if (!terminalRef.current || xtermRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      cursorStyle: 'block',
      fontSize: 13,
      fontFamily: '"Cascadia Code", "Fira Code", "JetBrains Mono", Consolas, monospace',
      theme: {
        background: '#0a0a0a',
        foreground: '#e2e8f0',
        cursor: '#22d3ee',
        cursorAccent: '#0a0a0a',
        selectionBackground: '#334155',
        selectionForeground: '#e2e8f0',
        black: '#1e293b',
        red: '#ef4444',
        green: '#22c55e',
        yellow: '#eab308',
        blue: '#3b82f6',
        magenta: '#a855f7',
        cyan: '#22d3ee',
        white: '#e2e8f0',
        brightBlack: '#475569',
        brightRed: '#f87171',
        brightGreen: '#4ade80',
        brightYellow: '#facc15',
        brightBlue: '#60a5fa',
        brightMagenta: '#c084fc',
        brightCyan: '#67e8f9',
        brightWhite: '#f8fafc',
      },
      allowProposedApi: true,
      scrollback: 10000,
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();

    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);

    term.open(terminalRef.current);

    // Delay first fit() to ensure DOM is laid out
    requestAnimationFrame(() => {
      const dims = fitAddon.proposeDimensions();
      if (dims && dims.cols >= 2 && dims.rows >= 1) {
        fitAddon.fit();
      }
    });

    // Explicit focus so keyboard input works immediately
    term.focus();

    xtermRef.current = term;
    fitAddonRef.current = fitAddon;

    // Welcome message
    term.writeln('\x1b[36m╔══════════════════════════════════════╗\x1b[0m');
    term.writeln('\x1b[36m║\x1b[0m   \x1b[1;32mPanopticon Terminal\x1b[0m               \x1b[36m║\x1b[0m');
    term.writeln('\x1b[36m╚══════════════════════════════════════╝\x1b[0m');
    term.writeln('');

    if (shell) {
      term.writeln(`\x1b[90mShell: ${shell.name} (${shell.path})\x1b[0m`);
      term.writeln('');
    }

    // Create session if we don't have one
    if (!sessionId) {
      term.writeln('\x1b[33mConnecting...\x1b[0m');
      createSession();
    }

    return () => {
      term.dispose();
      xtermRef.current = null;
      fitAddonRef.current = null;
    };
  }, [tabId]); // Only reinitialize on tabId change

  // Handle resize with debouncing
  useEffect(() => {
    window.addEventListener('resize', debouncedResize);

    const observer = new ResizeObserver(debouncedResize);
    if (terminalRef.current) {
      observer.observe(terminalRef.current);
    }

    return () => {
      window.removeEventListener('resize', debouncedResize);
      observer.disconnect();
      if (resizeTimerRef.current) clearTimeout(resizeTimerRef.current);
    };
  }, [debouncedResize]);

  // Manual reconnect handler
  const handleManualReconnect = useCallback(() => {
    setConnectionFailed(false);
    reconnectAttemptsRef.current = 0;

    if (xtermRef.current) {
      xtermRef.current.writeln('');
      xtermRef.current.writeln('\x1b[36mReconnecting...\x1b[0m');
    }

    createSession();
  }, [createSession]);

  // Stable refs for callbacks to avoid effect re-triggers
  const onStateChangeRef = useRef(onStateChange);
  onStateChangeRef.current = onStateChange;

  // Connect to WebSocket when sessionId is available
  useEffect(() => {
    if (!sessionId || !xtermRef.current) return;

    const term = xtermRef.current;

    const connect = () => {
      const ws = new WebSocket(`${WS_BASE}/api/terminal/ws/${sessionId}`);
      wsRef.current = ws;

      ws.onopen = () => {
        reconnectAttemptsRef.current = 0;
        setConnectionFailed(false);
        onStateChangeRef.current('connected');
        term.writeln('\x1b[32mConnected.\x1b[0m');
        term.writeln('');

        // Focus terminal on connect
        term.focus();

        // Send initial resize after connection is open
        requestAnimationFrame(() => {
          if (fitAddonRef.current) {
            const dims = fitAddonRef.current.proposeDimensions();
            if (dims && dims.cols >= 2 && dims.rows >= 1) {
              fitAddonRef.current.fit();
              ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
            }
          }
        });

        // Start client-side ping keep-alive
        pingIntervalRef.current = window.setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, CLIENT_PING_INTERVAL_MS);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);

          switch (msg.type) {
            case 'output':
            case 'buffered_output': {
              // Decode base64 output and write to terminal
              const bytes = atob(msg.data);
              term.write(bytes);
              break;
            }
            case 'exit':
              term.writeln('');
              term.writeln(`\x1b[33mProcess exited with code ${msg.code}\x1b[0m`);
              onStateChangeRef.current('disconnected');
              break;
            case 'error':
              term.writeln(`\x1b[31mError: ${msg.message}\x1b[0m`);
              break;
            case 'pong':
            case 'ping':
              // Keep-alive, ignore
              break;
          }
        } catch (e) {
          // If not JSON, write raw data
          term.write(event.data);
        }
      };

      ws.onclose = () => {
        // Stop ping
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current);
          pingIntervalRef.current = null;
        }

        term.writeln('');
        term.writeln('\x1b[33mDisconnected.\x1b[0m');
        onStateChangeRef.current('disconnected');

        // Exponential backoff reconnection
        if (reconnectAttemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
          reconnectAttemptsRef.current++;
          const delay = RECONNECT_BASE_DELAY_MS * Math.pow(2, reconnectAttemptsRef.current - 1);
          term.writeln(`\x1b[90mReconnecting in ${(delay / 1000).toFixed(1)}s... (${reconnectAttemptsRef.current}/${MAX_RECONNECT_ATTEMPTS})\x1b[0m`);

          reconnectTimeoutRef.current = window.setTimeout(() => {
            connect();
          }, delay);
        } else {
          term.writeln('');
          term.writeln('\x1b[31mConnection failed after maximum retries.\x1b[0m');
          term.writeln('\x1b[90mClick the reconnect button to try again.\x1b[0m');
          setConnectionFailed(true);
          onStateChangeRef.current('error');
        }
      };

      ws.onerror = () => {
        // onclose will fire after this — avoid duplicate messages
      };
    };

    connect();

    // Handle user input
    const inputDisposable = term.onData((data) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({
          type: 'input',
          data: btoa(data), // base64 encode input
        }));
      }
    });

    return () => {
      inputDisposable.dispose();
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [sessionId]);

  // Re-fit when session becomes available (with guard)
  useEffect(() => {
    if (sessionId && fitAddonRef.current) {
      requestAnimationFrame(() => {
        const dims = fitAddonRef.current?.proposeDimensions();
        if (dims && dims.cols >= 2 && dims.rows >= 1) {
          fitAddonRef.current?.fit();
        }
      });
    }
  }, [sessionId]);

  return (
    <div className="h-full w-full relative" onClick={() => xtermRef.current?.focus()}>
      <div
        ref={terminalRef}
        className="h-full w-full bg-[#0a0a0a]"
        style={{ padding: '4px' }}
      />

      {/* Reconnect overlay */}
      {connectionFailed && (
        <div className="absolute inset-0 flex items-center justify-center bg-black/80">
          <button
            type="button"
            onClick={handleManualReconnect}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors text-sm"
          >
            <RefreshCw size={16} />
            Reconnect
          </button>
        </div>
      )}
    </div>
  );
};
