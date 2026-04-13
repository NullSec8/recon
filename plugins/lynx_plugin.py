"""Lynx plugin for HTTP content dumps."""

from __future__ import annotations

from recon.context import RunContext
from recon.models import TaskRequest

from .base_command_plugin import BaseCommandPlugin


class LynxPlugin(BaseCommandPlugin):
    """Dump web content using lynx -dump."""

    @property
    def name(self) -> str:
        return "lynx"

    @property
    def description(self) -> str:
        return "HTTP content dump using lynx -dump."

    @property
    def default_enabled(self) -> bool:
        return False

    def required_binaries(self) -> tuple[str, ...]:
        return ("lynx",)

    def build_command(self, task: TaskRequest, context: RunContext) -> list[str]:
        url_override = str(context.plugin_args.get("url") or "").strip()
        url = url_override or task.target_info.url or f"http://{task.target_info.host}"
        return ["lynx", "-dump", url]


def register() -> LynxPlugin:
    """Plugin discovery entrypoint."""
    return LynxPlugin()
