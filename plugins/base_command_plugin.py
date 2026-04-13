"""Shared base plugin for command-driven modules."""

from __future__ import annotations

from abc import abstractmethod
from typing import Sequence

from recon.context import RunContext
from recon.models import TaskRequest, ToolResult
from recon.plugin_base import ReconPlugin
from recon.utils import run_subprocess


class BaseCommandPlugin(ReconPlugin):
    """Base plugin that runs exactly one command."""

    @abstractmethod
    def build_command(self, task: TaskRequest, context: RunContext) -> Sequence[str]:
        """Build command argv for this plugin."""

    def parse_hint(self, task: TaskRequest, context: RunContext) -> str | None:
        """Optional parse hint consumed by shared command executor."""
        return None

    def run(self, task: TaskRequest, context: RunContext) -> ToolResult:
        """Execute plugin command and normalize output."""
        command = list(self.build_command(task, context))
        parse_fn = self.parse_output if self.parse_hint(task, context) else None
        return run_subprocess(
            module_name=self.name,
            target=task.target_info.raw,
            command=command,
            timeout=context.timeout,
            parse_fn=parse_fn,
            dry_run=context.dry_run,
        )

    def parse_output(self, output: str) -> dict:
        """Return parsed output for plugins with parsing support."""
        return {}
