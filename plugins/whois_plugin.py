"""whois plugin implementation."""

from __future__ import annotations

from typing import Sequence

from recon.context import RunContext
from recon.models import TaskRequest

from .base_command_plugin import BaseCommandPlugin


class WhoisPlugin(BaseCommandPlugin):
    """Run whois on host/IP targets."""

    @property
    def name(self) -> str:
        return "whois"

    @property
    def description(self) -> str:
        return "WHOIS lookup."

    def required_binaries(self) -> Sequence[str]:
        return ("whois",)

    def build_command(self, task: TaskRequest, context: RunContext) -> list[str]:
        target = task.resolved_target or task.target_info.primary_ip or task.target_info.host
        return ["whois", target]


def register() -> WhoisPlugin:
    """Discovery entrypoint."""
    return WhoisPlugin()
