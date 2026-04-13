"""nmap plugin with optional XML output parsing."""

from __future__ import annotations

import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from recon.context import RunContext
from recon.models import TaskRequest, ToolResult
from recon.plugin_base import ReconPlugin
from recon.utils import run_subprocess


class NmapPlugin(ReconPlugin):
    """Run nmap scans and parse open ports from XML results."""

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def description(self) -> str:
        return "Network scanning with nmap."

    def required_binaries(self) -> list[str]:
        return ["nmap"]

    def build_command(self, task: TaskRequest, context: RunContext) -> list[str]:
        target = task.resolved_target or task.target_info.primary_ip or task.target_info.host
        command = ["nmap", *list(context.plugin_args.get("nmap_args", ["-sV", "-Pn"]))]
        scripts = context.plugin_args.get("nmap_scripts")
        top_ports = context.plugin_args.get("top_ports")
        if scripts:
            command.extend(["--script", str(scripts)])
        if top_ports:
            command.extend(["--top-ports", str(top_ports)])
        command.append(target)
        return command

    def run(self, task: TaskRequest, context: RunContext) -> ToolResult:
        base_command = self.build_command(task, context)
        parse_structured = bool(context.plugin_args.get("parse_structured", True))
        if not parse_structured or context.dry_run:
            return run_subprocess(
                module_name=self.name,
                target=task.target_info.raw,
                command=base_command,
                timeout=context.timeout,
                dry_run=context.dry_run,
            )

        with tempfile.NamedTemporaryFile(prefix="recon_nmap_", suffix=".xml", delete=False) as handle:
            xml_path = Path(handle.name)
        command_with_xml = [*base_command, "-oX", str(xml_path)]
        result = run_subprocess(
            module_name=self.name,
            target=task.target_info.raw,
            command=command_with_xml,
            timeout=context.timeout,
            dry_run=False,
        )
        parsed = self._parse_xml(xml_path)
        if parsed:
            result.parsed.update(parsed)
        xml_path.unlink(missing_ok=True)
        return result

    def _parse_xml(self, xml_path: Path) -> dict[str, Any]:
        """Parse nmap XML into open port entries."""
        if not xml_path.exists():
            return {}
        try:
            root = ET.fromstring(xml_path.read_text(encoding="utf-8", errors="replace"))
        except ET.ParseError:
            return {}

        open_ports: list[dict[str, Any]] = []
        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue
                service = port.find("service")
                open_ports.append(
                    {
                        "port": int(port.attrib.get("portid", "0")),
                        "protocol": port.attrib.get("protocol", ""),
                        "service": service.attrib.get("name", "") if service is not None else "",
                    }
                )
        return {"open_ports": open_ports}


def register() -> NmapPlugin:
    """Plugin discovery entrypoint."""
    return NmapPlugin()
