"""Plugin interface for recon modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Sequence

from recon.context import RunContext
from recon.models import TaskRequest, ToolResult


class ReconPlugin(ABC):
    """Common plugin interface for all recon modules."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique module name used in CLI and reports."""

    @property
    def description(self) -> str:
        """Human-readable plugin description."""
        return self.name

    @property
    def default_enabled(self) -> bool:
        """Whether plugin should run when no explicit module is selected."""
        return False

    @property
    def supported_target_types(self) -> set[str]:
        """Target types this plugin can handle."""
        return {"domain", "ip", "url"}

    def required_binaries(self) -> Sequence[str]:
        """External tools required by plugin."""
        return ()

    def can_run(self, task: TaskRequest) -> bool:
        """Check if plugin supports this task target type."""
        return task.target_info.target_type in self.supported_target_types

    @abstractmethod
    def run(self, task: TaskRequest, context: RunContext) -> ToolResult:
        """Execute plugin task and return ToolResult."""
