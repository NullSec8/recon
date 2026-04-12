"""Datamodels for targets, tasks, and tool results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from recon.errors import ErrorType


@dataclass(slots=True)
class TargetInfo:
    """Normalized target information used by modules."""

    raw: str
    target_type: str
    host: str
    primary_ip: str | None = None
    resolved_ips: list[str] = field(default_factory=list)
    url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize target info to JSON-friendly dict."""
        return {
            "raw": self.raw,
            "target_type": self.target_type,
            "host": self.host,
            "primary_ip": self.primary_ip,
            "resolved_ips": list(self.resolved_ips),
            "url": self.url,
        }


@dataclass(slots=True)
class TaskRequest:
    """One plugin execution request for one target."""

    module_name: str
    target_info: TargetInfo
    resolved_target: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ToolResult:
    """Normalized result from one plugin invocation."""

    module_name: str
    target: str
    command: list[str]
    returncode: int
    output: str
    duration_seconds: float
    error_type: ErrorType = ErrorType.NONE
    error_message: str | None = None
    parsed: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    executed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def tool_missing(cls, module_name: str, target: str, message: str) -> "ToolResult":
        """Build a structured missing-tool result."""
        return cls(
            module_name=module_name,
            target=target,
            command=[],
            returncode=127,
            output=message,
            duration_seconds=0.0,
            error_type=ErrorType.TOOL_MISSING,
            error_message=message,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize result to JSON-friendly dict."""
        return {
            "module_name": self.module_name,
            "target": self.target,
            "command": list(self.command),
            "returncode": self.returncode,
            "output": self.output,
            "duration_seconds": self.duration_seconds,
            "error_type": self.error_type.value,
            "error_message": self.error_message,
            "parsed": self.parsed,
            "metadata": self.metadata,
            "executed_at": self.executed_at,
        }
