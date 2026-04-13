"""Utility helpers for recon framework."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List

from recon.errors import ErrorType
from recon.models import ToolResult


def command_exists(command: str) -> bool:
    """Return whether executable exists in PATH."""
    return shutil.which(command) is not None


def normalize_argv(argv: List[str]) -> List[str]:
    """Normalize single-dash long options into argparse-compatible form."""
    normalized: List[str] = []
    for arg in argv:
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 2 and not arg[1].isdigit():
            normalized.append(f"--{arg[1:]}")
        else:
            normalized.append(arg)
    return normalized


def safe_shlex_join(parts: List[str]) -> str:
    """Render shell-safe command string."""
    return " ".join(shlex.quote(part) for part in parts)


def run_subprocess(
    *,
    module_name: str,
    target: str,
    command: List[str],
    timeout: int,
    parse_fn: Callable[[str], Dict[str, Any]] | None = None,
    dry_run: bool = False,
) -> ToolResult:
    """Execute subprocess and normalize output into ToolResult."""
    if dry_run:
        return ToolResult(
            module_name=module_name,
            target=target,
            command=command,
            returncode=0,
            output=f"[dry-run] {safe_shlex_join(command)}",
            duration_seconds=0.0,
        )

    start = datetime.now(timezone.utc)
    stdout_data = ""
    stderr_data = ""
    returncode = 1
    error_type = ErrorType.EXECUTION_FAILURE

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout_data = completed.stdout or ""
        stderr_data = completed.stderr or ""
        returncode = completed.returncode
        if completed.returncode == 0:
            error_type = ErrorType.NONE
    except subprocess.TimeoutExpired:
        returncode = 124
        error_type = ErrorType.TIMEOUT
        stderr_data = f"Command timed out after {timeout}s"
    except Exception as exc:
        returncode = 1
        error_type = ErrorType.EXECUTION_FAILURE
        stderr_data = f"Failed to run command: {exc}"

    end = datetime.now(timezone.utc)
    output = stdout_data + (f"\n{stderr_data}" if stderr_data else "")
    output = output.strip() or "(no output)"

    parsed: Dict[str, Any] = {}
    if parse_fn:
        try:
            parsed = parse_fn(stdout_data)
        except Exception as exc:
            parsed = {"parse_error": str(exc)}

    return ToolResult(
        module_name=module_name,
        target=target,
        command=command,
        returncode=returncode,
        output=output,
        duration_seconds=(end - start).total_seconds(),
        error_type=error_type,
        parsed=parsed,
    )
