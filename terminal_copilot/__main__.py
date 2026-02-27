"""
Entry point: run the terminal wrapper with optional AI insights.
  python -m terminal_copilot
  python -m terminal_copilot --no-ai   # rule-based only
"""
import argparse
import sys

from .wrapper.pty_runner import run_wrapped_shell
from .wrapper.providers import combined_insights, rule_based_insights


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Terminal copilot: PTY wrapper that monitors commands and output, surfaces security/insight notifications."
    )
    ap.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI-backed insights (use only rule-based heuristics).",
    )
    ap.add_argument(
        "--shell",
        default=None,
        help="Shell to run (default: $SHELL or sh).",
    )
    ap.add_argument(
        "--debounce",
        type=float,
        default=0.8,
        help="Seconds between insight checks (default: 0.8).",
    )
    args = ap.parse_args()
    on_context = rule_based_insights if args.no_ai else combined_insights
    return run_wrapped_shell(
        shell=args.shell or None,
        on_context=on_context,
        debounce_seconds=args.debounce,
    )


if __name__ == "__main__":
    sys.exit(main())
