"""Error taxonomy used by recon execution results."""

from __future__ import annotations

from enum import Enum


class ErrorType(str, Enum):
    """Structured categories for module execution outcomes."""

    NONE = "none"
    TOOL_MISSING = "tool_missing"
    TIMEOUT = "timeout"
    EXECUTION_FAILURE = "execution_failure"
    INVALID_TARGET = "invalid_target"
