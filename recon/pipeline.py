"""Simple scan chaining pipeline."""

from __future__ import annotations

from typing import Sequence

from recon.models import TargetInfo, TaskRequest, ToolResult


def build_initial_tasks(targets: Sequence[TargetInfo], enabled_modules: set[str]) -> list[TaskRequest]:
    """Build initial task list from targets and selected modules."""
    tasks: list[TaskRequest] = []
    for target in targets:
        for module_name in sorted(enabled_modules):
            tasks.append(TaskRequest(module_name=module_name, target_info=target))
    return tasks


def extend_tasks_from_pipeline(
    results: Sequence[ToolResult],
    enabled_modules: set[str],
    known_targets: Sequence[TargetInfo],
) -> list[TaskRequest]:
    """Create follow-up tasks from previous parsed output.

    Current chain:
    - dig parsed IPs -> nmap scans of those IPs.
    """
    if "nmap" not in enabled_modules:
        return []

    existing_targets = {target.raw for target in known_targets}
    planned: set[tuple[str, str]] = set()
    tasks: list[TaskRequest] = []

    for result in results:
        if result.module_name != "dig":
            continue
        ips = result.parsed.get("ips")
        if not isinstance(ips, list):
            continue
        for ip in ips:
            ip_text = str(ip)
            key = ("nmap", ip_text)
            if ip_text in existing_targets or key in planned:
                continue
            planned.add(key)
            tasks.append(
                TaskRequest(
                    module_name="nmap",
                    target_info=TargetInfo(raw=ip_text, target_type="ip", host=ip_text, primary_ip=ip_text),
                    resolved_target=ip_text,
                    metadata={"source": "pipeline:dig"},
                )
            )

    return tasks

