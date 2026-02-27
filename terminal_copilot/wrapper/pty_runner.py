"""
PTY-based terminal wrapper: runs a shell in a pseudo-terminal, forwards all I/O,
and captures commands + output for insight providers (e.g. AI or rule-based).
"""
from __future__ import annotations

import os
import pty
import shutil
import sys
from dataclasses import dataclass, field
from typing import Callable

from .ring_buffer import RingBuffer


@dataclass
class TerminalContext:
    """Recent terminal activity for insight providers."""
    # Last N lines of output (from shell)
    output_lines: list[str] = field(default_factory=list)
    # Last N user input lines (commands)
    input_lines: list[str] = field(default_factory=list)
    # Full raw tail of output (e.g. last 4KB) for AI
    output_tail: str = ""

    def last_command(self) -> str | None:
        if not self.input_lines:
            return None
        return self.input_lines[-1].strip() or None

    def recent_output(self) -> str:
        return "\n".join(self.output_lines) if self.output_lines else self.output_tail


def _find_shell() -> str:
    shell = os.environ.get("SHELL", "sh")
    path = shutil.which(shell)
    return path or shell


def _ensure_bashrc_tc_prompt() -> None:
    """
    Ensure the user's ~/.bashrc contains a small TC_CONTEXT-aware prompt
    snippet. This lets terminal-copilot mark the inner shell prompt with
    [tc] transparently, without the user having to edit their config.
    """
    bashrc = os.path.expanduser("~/.bashrc")
    snippet_tag = "# terminal-copilot prompt integration"
    snippet = (
        snippet_tag
        + "\n"
        + 'if [[ -n "$TC_CONTEXT" ]]; then\n'
        + '  PS1="[tc] $PS1"\n'
        + "fi\n"
    )
    try:
        try:
            with open(bashrc, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            content = ""
        if snippet_tag in content:
            return
        with open(bashrc, "a", encoding="utf-8") as f:
            if content and not content.endswith("\n"):
                f.write("\n")
            f.write("\n" + snippet + "\n")
    except OSError:
        # If we can't write to .bashrc, just skip; the wrapper still works,
        # but the prompt won't be auto-prefixed.
        return


def run_wrapped_shell(
    *,
    shell: str | None = None,
    on_context: Callable[[TerminalContext], list] | None = None,
    output_line_limit: int = 100,
    output_tail_bytes: int = 4096,
    debounce_seconds: float = 0.5,
) -> int:
    """
    Run an interactive shell in a PTY with full passthrough. Optionally call
    `on_context(context)` with recent input/output; any returned insights
    are surfaced (e.g. notifications). Returns shell exit code.
    """
    shell = shell or _find_shell()

    # Best-effort: make sure the user's bashrc has a TC_CONTEXT-aware prompt
    # snippet so we can show [tc] in the inner shell prompt automatically.
    _ensure_bashrc_tc_prompt()
    buf_out = RingBuffer(max_lines=output_line_limit, max_bytes=output_tail_bytes)
    buf_in: list[str] = []
    last_insight_check = 0.0
    import time

    def make_context() -> TerminalContext:
        return TerminalContext(
            output_lines=buf_out.get_lines(),
            input_lines=buf_in[-50:] if len(buf_in) > 50 else buf_in.copy(),
            output_tail=buf_out.get_tail(),
        )

    def maybe_run_insights() -> None:
        nonlocal last_insight_check
        if not on_context:
            return
        now = time.monotonic()
        if now - last_insight_check < debounce_seconds:
            return
        last_insight_check = now
        try:
            ctx = make_context()
            insights = on_context(ctx)
            for insight in insights or []:
                from .insights import notify_insight
                notify_insight(insight)
        except Exception as e:
            # Don't break the terminal; log to stderr
            print(f"\r\n[tc] insight error: {e}\n", file=sys.stderr, flush=True)

    def master_read(fd: int) -> bytes:
        """Read from child PTY, buffer, maybe run insights, and pass through."""
        try:
            data = os.read(fd, 4096)
        except OSError:
            return b""
        if not data:
            return b""

        # Buffer output for context
        buf_out.append_bytes(data)
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        for line in text.splitlines():
            if line.strip():
                buf_out.append_line(line)

        maybe_run_insights()
        return data

    def stdin_read(fd: int) -> bytes:
        """Read from our stdin, track commands, and pass through."""
        try:
            data = os.read(fd, 4096)
        except OSError:
            return b""
        if not data:
            return b""

        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        for line in text.splitlines():
            line = line.strip()
            if line and not line.isspace():
                buf_in.append(line)
        return data

    # Mark this PTY as a terminal-copilot context so shell config (e.g. ~/.bashrc)
    # can adjust the prompt (PS1) accordingly.
    orig_tc = os.environ.get("TC_CONTEXT")
    os.environ["TC_CONTEXT"] = "1"

    # Optional one-time header so it's obvious when you enter the wrapped shell.
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or "?"
    host = os.uname().nodename
    cwd = os.getcwd()
    print(f"[tc] Dropping into terminal-copilot shell... 🚀", file=sys.stderr, flush=True)

    # Use pty.spawn to handle PTY setup, line discipline, and job control.
    argv = [shell, "-i"]
    try:
        status = pty.spawn(argv, master_read=master_read, stdin_read=stdin_read)
    except OSError as e:
        print(f"terminal-copilot: pty.spawn failed: {e}", file=sys.stderr)
        return 127
    finally:
        # Restore TC_CONTEXT in the parent environment.
        if orig_tc is None:
            os.environ.pop("TC_CONTEXT", None)
        else:
            os.environ["TC_CONTEXT"] = orig_tc

    # pty.spawn returns wait status from os.waitpid; convert to exit code.
    try:
        return os.waitstatus_to_exitcode(status)
    except Exception:
        return 0
