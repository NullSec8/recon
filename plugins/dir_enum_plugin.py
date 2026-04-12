"""Directory enumeration plugin using available backend tools."""

from __future__ import annotations

from typing import Sequence

from recon.context import RunContext
from recon.models import TaskRequest
from recon.utils import command_exists

from .base_command_plugin import BaseCommandPlugin


class DirEnumPlugin(BaseCommandPlugin):
    """Run directory brute force with an available backend."""

    @property
    def name(self) -> str:
        return "dir-enum"

    @property
    def description(self) -> str:
        return "Directory enumeration via feroxbuster/dirsearch/dirbuster/gobuster."

    @property
    def default_enabled(self) -> bool:
        return False

    @property
    def supported_target_types(self) -> set[str]:
        return {"domain", "ip", "url"}

    def required_binaries(self) -> Sequence[str]:
        return ()

    def build_command(self, task: TaskRequest, context: RunContext) -> list[str]:
        url = str(context.plugin_args.get("url") or task.target_info.url or f"http://{task.target_info.host}")
        wordlist = str(context.plugin_args.get("wordlist") or "/usr/share/wordlists/dirb/common.txt")
        extra = list(context.plugin_args.get("dir_enum_args") or [])

        if command_exists("feroxbuster"):
            return ["feroxbuster", "-u", url, "-w", wordlist, *extra]
        if command_exists("dirsearch"):
            return ["dirsearch", "-u", url, "-w", wordlist, *extra]
        if command_exists("dirbuster"):
            return ["dirbuster", *extra, task.target_info.host]
        if command_exists("gobuster"):
            return ["gobuster", "dir", "-u", url, "-w", wordlist, *extra]

        return ["echo", "No directory enumeration backend found."]


def register() -> DirEnumPlugin:
    """Plugin discovery entrypoint."""
    return DirEnumPlugin()
