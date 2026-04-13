"""nslookup plugin."""

from __future__ import annotations

from plugins.base_command_plugin import BaseCommandPlugin
from recon.context import RunContext
from recon.models import TaskRequest


class NslookupPlugin(BaseCommandPlugin):
    """DNS lookup plugin using nslookup."""

    @property
    def name(self) -> str:
        return "nslookup"

    @property
    def description(self) -> str:
        return "DNS lookup via nslookup."

    def required_binaries(self) -> tuple[str, ...]:
        return ("nslookup",)

    def build_command(self, task: TaskRequest, context: RunContext) -> list[str]:
        return ["nslookup", task.resolved_target or task.target_info.host]


def register():
    """Plugin discovery entry point."""
    return NslookupPlugin()
