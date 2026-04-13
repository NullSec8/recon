"""dig plugin with structured DNS answer parsing."""

from __future__ import annotations

from typing import Sequence

from plugins.base_command_plugin import BaseCommandPlugin
from recon.context import RunContext
from recon.models import TaskRequest


class DigPlugin(BaseCommandPlugin):
    """Resolve DNS records using dig +short output."""

    @property
    def name(self) -> str:
        return "dig"

    @property
    def description(self) -> str:
        return "Resolve DNS records using dig."

    @property
    def default_enabled(self) -> bool:
        return True

    @property
    def supported_target_types(self) -> set[str]:
        return {"domain", "url"}

    def required_binaries(self) -> Sequence[str]:
        return ("dig",)

    def build_command(self, task: TaskRequest, context: RunContext) -> list[str]:
        record_type = str(context.plugin_args.get("dig_record_type", "A"))
        return ["dig", task.target_info.host, record_type, "+short"]

    def parse_hint(self, task: TaskRequest, context: RunContext) -> str | None:
        return "dig"


def register() -> DigPlugin:
    """Plugin discovery entrypoint."""
    return DigPlugin()
