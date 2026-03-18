"""Terminal session manager for interactive PTY shells."""
from __future__ import annotations

import asyncio
import collections
import logging
import os
import signal
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

# Platform-specific PTY imports
if sys.platform == "win32":
    try:
        import winpty
        HAS_WINPTY = True
    except ImportError:
        HAS_WINPTY = False
        winpty = None
else:
    import pty
    import fcntl
    import termios
    import struct
    HAS_WINPTY = False

logger = logging.getLogger(__name__)

# Server-side output buffer size for reconnection replay
OUTPUT_BUFFER_SIZE = 1000
# Ping interval in seconds
PING_INTERVAL = 5
# Idle session timeout in minutes
DEFAULT_IDLE_TIMEOUT_MINUTES = 30


@dataclass
class TerminalSession:
    """Represents an active terminal session."""
    session_id: str
    shell: str
    cols: int = 120
    rows: int = 30
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)

    # Platform-specific handles
    _pty: object | None = field(default=None, repr=False)
    _process: object | None = field(default=None, repr=False)
    _master_fd: int | None = field(default=None, repr=False)
    _read_task: asyncio.Task | None = field(default=None, repr=False)
    _output_callback: Callable[[bytes], None] | None = field(default=None, repr=False)
    _exit_callback: Callable[[int], None] | None = field(default=None, repr=False)

    # Output buffer for reconnection replay
    _output_buffer: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=OUTPUT_BUFFER_SIZE),
        repr=False,
    )
    _alive: bool = field(default=True, repr=False)


class TerminalManager:
    """Manages multiple terminal sessions with PTY support."""

    def __init__(self) -> None:
        self._sessions: dict[str, TerminalSession] = {}
        self._lock = asyncio.Lock()
        logger.info("TerminalManager initialized")

    def _get_default_shell(self) -> str:
        """Get the default shell for the current platform."""
        if sys.platform == "win32":
            pwsh_paths = [
                r"C:\Program Files\PowerShell\7\pwsh.exe",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ]
            for path in pwsh_paths:
                if os.path.exists(path):
                    return path
            return os.environ.get("COMSPEC", "cmd.exe")
        else:
            return os.environ.get("SHELL", "/bin/bash")

    def get_available_shells(self) -> list[dict[str, str]]:
        """Return list of available shells for current platform."""
        shells: list[dict[str, str]] = []

        if sys.platform == "win32":
            pwsh7_path = r"C:\Program Files\PowerShell\7\pwsh.exe"
            if os.path.exists(pwsh7_path):
                shells.append({"id": "pwsh", "name": "PowerShell 7", "path": pwsh7_path})

            pwsh5_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            if os.path.exists(pwsh5_path):
                shells.append({"id": "powershell", "name": "Windows PowerShell", "path": pwsh5_path})

            cmd_path = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
            if os.path.exists(cmd_path):
                shells.append({"id": "cmd", "name": "Command Prompt", "path": cmd_path})

            git_bash_paths = [
                r"C:\Program Files\Git\bin\bash.exe",
                r"C:\Program Files (x86)\Git\bin\bash.exe",
            ]
            for git_bash in git_bash_paths:
                if os.path.exists(git_bash):
                    shells.append({"id": "git-bash", "name": "Git Bash", "path": git_bash})
                    break

            wsl_path = r"C:\Windows\System32\wsl.exe"
            if os.path.exists(wsl_path):
                shells.append({"id": "wsl", "name": "WSL", "path": wsl_path})
        else:
            unix_shells = [
                ("bash", "Bash", "/bin/bash"),
                ("zsh", "Zsh", "/bin/zsh"),
                ("fish", "Fish", "/usr/bin/fish"),
                ("sh", "Shell", "/bin/sh"),
            ]
            for shell_id, name, path in unix_shells:
                if os.path.exists(path):
                    shells.append({"id": shell_id, "name": name, "path": path})

            homebrew_shells = [
                ("bash", "Bash (Homebrew)", "/usr/local/bin/bash"),
                ("zsh", "Zsh (Homebrew)", "/usr/local/bin/zsh"),
                ("fish", "Fish (Homebrew)", "/usr/local/bin/fish"),
            ]
            for shell_id, name, path in homebrew_shells:
                if os.path.exists(path) and not any(s["path"] == path for s in shells):
                    shells.append({"id": f"{shell_id}-homebrew", "name": name, "path": path})

        logger.debug("Available shells: %s", [s["name"] for s in shells])
        return shells

    async def create_session(
        self,
        shell: str | None = None,
        cols: int = 120,
        rows: int = 30,
        output_callback: Callable[[bytes], None] | None = None,
        exit_callback: Callable[[int], None] | None = None,
    ) -> TerminalSession:
        """Create a new terminal session with PTY."""
        session_id = str(uuid.uuid4())
        shell = shell or self._get_default_shell()

        session = TerminalSession(
            session_id=session_id,
            shell=shell,
            cols=cols,
            rows=rows,
            _output_callback=output_callback,
            _exit_callback=exit_callback,
        )

        logger.info("Creating terminal session %s with shell=%s cols=%d rows=%d", session_id, shell, cols, rows)

        if sys.platform == "win32":
            await self._create_windows_pty(session)
        else:
            await self._create_unix_pty(session)

        async with self._lock:
            self._sessions[session_id] = session

        logger.info("Terminal session %s created successfully", session_id)
        return session

    async def _create_windows_pty(self, session: TerminalSession) -> None:
        """Create PTY on Windows using winpty."""
        if not HAS_WINPTY:
            raise RuntimeError("winpty not installed. Install with: pip install pywinpty")

        pty_process = winpty.PtyProcess.spawn(
            session.shell,
            dimensions=(session.rows, session.cols),
        )
        session._pty = pty_process

        session._read_task = asyncio.create_task(
            self._read_windows_output(session)
        )

    async def _read_windows_output(self, session: TerminalSession) -> None:
        """Read output from Windows PTY in background."""
        pty_process = session._pty
        loop = asyncio.get_event_loop()

        try:
            while pty_process.isalive():
                try:
                    data = await loop.run_in_executor(
                        None,
                        lambda: pty_process.read(4096, timeout=100)
                    )
                    if data:
                        encoded = data.encode() if isinstance(data, str) else data
                        session._output_buffer.append(encoded)
                        if session._output_callback:
                            session._output_callback(encoded)
                except TimeoutError:
                    continue
                except Exception:
                    break
        finally:
            session._alive = False
            exit_code = pty_process.exitstatus or 0
            logger.info("Terminal session %s exited with code %d", session.session_id, exit_code)
            if session._exit_callback:
                session._exit_callback(exit_code)

    async def _create_unix_pty(self, session: TerminalSession) -> None:
        """Create PTY on Unix using pty module."""
        import subprocess

        master_fd, slave_fd = pty.openpty()

        # Set terminal size
        winsize = struct.pack("HHHH", session.rows, session.cols, 0, 0)
        fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)

        # Spawn shell process
        process = subprocess.Popen(
            [session.shell],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            preexec_fn=os.setsid,
            env={**os.environ, "TERM": "xterm-256color"},
        )

        os.close(slave_fd)

        # Set master to non-blocking
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        session._master_fd = master_fd
        session._process = process

        # Use asyncio add_reader for efficient non-blocking reads
        session._read_task = asyncio.create_task(
            self._read_unix_output(session)
        )

    async def _read_unix_output(self, session: TerminalSession) -> None:
        """Read output from Unix PTY using asyncio event loop fd reader."""
        loop = asyncio.get_event_loop()
        master_fd = session._master_fd
        process = session._process
        output_ready = asyncio.Event()

        def _fd_readable():
            output_ready.set()

        loop.add_reader(master_fd, _fd_readable)

        try:
            while process.poll() is None:
                output_ready.clear()
                try:
                    await asyncio.wait_for(output_ready.wait(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue

                try:
                    data = os.read(master_fd, 16384)
                    if data:
                        session._output_buffer.append(data)
                        if session._output_callback:
                            session._output_callback(data)
                except BlockingIOError:
                    pass
                except OSError:
                    break
        finally:
            try:
                loop.remove_reader(master_fd)
            except Exception:
                pass
            session._alive = False
            exit_code = process.returncode or 0
            logger.info("Terminal session %s exited with code %d", session.session_id, exit_code)
            if session._exit_callback:
                session._exit_callback(exit_code)

    def get_output_buffer(self, session_id: str) -> list[bytes]:
        """Get buffered output for reconnection replay."""
        session = self._sessions.get(session_id)
        if not session:
            return []
        return list(session._output_buffer)

    async def write_input(self, session_id: str, data: bytes) -> bool:
        """Write input to terminal session."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

        session.last_activity = datetime.utcnow()

        if sys.platform == "win32" and session._pty:
            try:
                session._pty.write(data.decode() if isinstance(data, bytes) else data)
                return True
            except Exception:
                logger.warning("Failed to write to Windows PTY session %s", session_id)
                return False
        elif session._master_fd is not None:
            try:
                os.write(session._master_fd, data)
                return True
            except Exception:
                logger.warning("Failed to write to Unix PTY session %s", session_id)
                return False

        return False

    async def resize(self, session_id: str, cols: int, rows: int) -> bool:
        """Resize terminal session."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

        session.cols = cols
        session.rows = rows
        session.last_activity = datetime.utcnow()
        logger.debug("Resized session %s to %dx%d", session_id, cols, rows)

        if sys.platform == "win32" and session._pty:
            try:
                session._pty.setwinsize(rows, cols)
                return True
            except Exception:
                return False
        elif session._master_fd is not None:
            try:
                winsize = struct.pack("HHHH", rows, cols, 0, 0)
                fcntl.ioctl(session._master_fd, termios.TIOCSWINSZ, winsize)
                return True
            except Exception:
                return False

        return False

    async def close_session(self, session_id: str) -> bool:
        """Close and cleanup a terminal session with graceful kill escalation."""
        async with self._lock:
            session = self._sessions.pop(session_id, None)
            if not session:
                return False

        logger.info("Closing terminal session %s", session_id)
        session._alive = False

        # Cancel read task
        if session._read_task:
            session._read_task.cancel()
            try:
                await session._read_task
            except asyncio.CancelledError:
                pass

        # Close platform-specific resources with graceful kill escalation
        if sys.platform == "win32" and session._pty:
            try:
                session._pty.terminate()
            except Exception:
                pass
        elif session._master_fd is not None:
            try:
                os.close(session._master_fd)
            except Exception:
                pass
            if session._process:
                await self._graceful_kill(session._process, session_id)

        logger.info("Terminal session %s closed", session_id)
        return True

    async def _graceful_kill(self, process, session_id: str) -> None:
        """Graceful kill escalation: SIGHUP -> SIGTERM -> SIGKILL."""
        pid = process.pid
        pgid = None
        try:
            pgid = os.getpgid(pid)
        except OSError:
            pass

        kill_target = -pgid if pgid and pgid != os.getpid() else pid

        for sig, name, wait_secs in [
            (signal.SIGHUP, "SIGHUP", 1),
            (signal.SIGTERM, "SIGTERM", 2),
            (signal.SIGKILL, "SIGKILL", 1),
        ]:
            try:
                os.kill(kill_target, sig)
                logger.debug("Sent %s to session %s (pid=%d)", name, session_id, pid)
            except OSError:
                return  # Process already gone

            try:
                process.wait(timeout=wait_secs)
                logger.debug("Session %s terminated after %s", session_id, name)
                return
            except Exception:
                continue

        logger.warning("Session %s: process %d did not terminate after escalation", session_id, pid)

    async def get_session(self, session_id: str) -> TerminalSession | None:
        """Get session by ID."""
        async with self._lock:
            return self._sessions.get(session_id)

    async def list_sessions(self) -> list[TerminalSession]:
        """List all active sessions."""
        async with self._lock:
            return list(self._sessions.values())

    async def cleanup_idle_sessions(self, max_idle_minutes: int = DEFAULT_IDLE_TIMEOUT_MINUTES) -> int:
        """Close sessions that have been idle for too long."""
        now = datetime.utcnow()
        to_close = []

        async with self._lock:
            for session_id, session in self._sessions.items():
                idle_seconds = (now - session.last_activity).total_seconds()
                if idle_seconds > max_idle_minutes * 60:
                    to_close.append(session_id)

        for session_id in to_close:
            logger.info("Closing idle session %s", session_id)
            await self.close_session(session_id)

        return len(to_close)


# Global terminal manager instance
_terminal_manager: TerminalManager | None = None


def get_terminal_manager() -> TerminalManager:
    """Get or create the global terminal manager."""
    global _terminal_manager
    if _terminal_manager is None:
        _terminal_manager = TerminalManager()
    return _terminal_manager
