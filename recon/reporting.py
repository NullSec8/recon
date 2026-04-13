"""JSON/Markdown reporting and console summary helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from recon.errors import ErrorType
from recon.models import ToolResult


def summarize_results(results: Sequence[ToolResult]) -> dict[str, Any]:
    """Create aggregate summary for report outputs."""
    failures = [result for result in results if result.error_type != ErrorType.NONE]
    open_ports: list[str] = []
    discovered_urls: set[str] = set()
    errors: list[str] = []

    for result in results:
        parsed = result.parsed or {}
        for entry in parsed.get("open_ports", []):
            if not isinstance(entry, dict):
                continue
            port = entry.get("port", "?")
            proto = entry.get("protocol", "tcp")
            service = entry.get("service", "")
            line = f"{result.target} {proto}/{port}"
            if service:
                line += f" ({service})"
            open_ports.append(line)

        for url in parsed.get("urls", []):
            if isinstance(url, str):
                discovered_urls.add(url)

        if result.error_type != ErrorType.NONE:
            errors.append(f"{result.module_name}@{result.target}: {result.error_type.value} ({result.returncode})")

    return {
        "total_results": len(results),
        "success_count": len(results) - len(failures),
        "failure_count": len(failures),
        "open_ports": sorted(set(open_ports)),
        "discovered_urls": sorted(discovered_urls),
        "errors": errors,
    }


def build_json_payload(
    *,
    generated_at: str,
    targets: list[dict[str, Any]],
    config: dict[str, Any],
    results: Sequence[ToolResult],
) -> dict[str, Any]:
    """Build full JSON payload including summary and raw results."""
    return {
        "generated_at": generated_at,
        "targets": targets,
        "config": config,
        "summary": summarize_results(results),
        "results": [result.to_dict() for result in results],
    }


def write_json_report(path: str, payload: dict[str, Any]) -> None:
    """Write structured JSON report to disk."""
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def build_markdown_report(payload: dict[str, Any]) -> str:
    """Render markdown report from JSON payload."""
    summary = payload.get("summary", {})
    targets = payload.get("targets", [])
    config = payload.get("config", {})
    results = payload.get("results", [])

    lines: list[str] = []
    lines.append("# Recon Report")
    lines.append("")
    lines.append(f"Generated: {payload.get('generated_at', datetime.now(timezone.utc).isoformat())}")
    lines.append(f"Targets: {', '.join(target.get('raw', '') for target in targets)}")
    lines.append(f"Modules: {', '.join(config.get('enabled_modules', []))}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total results: {summary.get('total_results', 0)}")
    lines.append(f"- Success: {summary.get('success_count', 0)}")
    lines.append(f"- Failures: {summary.get('failure_count', 0)}")
    lines.append("")
    lines.append("### Open Ports")
    ports = summary.get("open_ports", [])
    if ports:
        lines.extend(f"- {line}" for line in ports)
    else:
        lines.append("- None discovered")
    lines.append("")
    lines.append("### Discovered URLs")
    urls = summary.get("discovered_urls", [])
    if urls:
        lines.extend(f"- {url}" for url in urls)
    else:
        lines.append("- None discovered")
    lines.append("")
    lines.append("### Errors")
    error_lines = summary.get("errors", [])
    if error_lines:
        lines.extend(f"- {line}" for line in error_lines)
    else:
        lines.append("- No structured errors reported")
    lines.append("")
    lines.append("## Module Results")
    lines.append("")
    lines.append("| Target | Module | Status | Duration (s) | Command |")
    lines.append("|---|---|---|---:|---|")
    for result in results:
        command = " ".join(result.get("command", []))
        status = "OK" if result.get("error_type") == ErrorType.NONE.value else f"ERROR ({result.get('error_type')})"
        lines.append(
            f"| {result.get('target', '')} | {result.get('module_name', '')} | {status} | "
            f"{float(result.get('duration_seconds', 0.0)):.2f} | `{command}` |"
        )
    lines.append("")
    return "\n".join(lines)


def write_markdown_report(path: str, report: str) -> None:
    """Write markdown report to disk."""
    Path(path).write_text(report, encoding="utf-8")


def print_console_summary(results: Sequence[ToolResult], *, verbose: bool, failures_only: bool) -> None:
    """Print concise console status and optional output snippets."""
    print("\nRecon results:")
    for result in sorted(results, key=lambda item: (item.target, item.module_name)):
        status = "OK" if result.error_type == ErrorType.NONE else f"ERR:{result.error_type.value}"
        print(
            f"  - [{result.target}] {result.module_name:<10} {status:<18} "
            f"{result.duration_seconds:>6.2f}s | {' '.join(result.command)}"
        )

    print("\nOutput details:")
    for result in sorted(results, key=lambda item: (item.target, item.module_name)):
        if failures_only and result.error_type == ErrorType.NONE:
            continue
        print(f"\n[{result.target}] {result.module_name}:")
        if verbose:
            print(result.output)
            continue
        lines = result.output.splitlines()
        clipped = lines[:12]
        if len(lines) > 12:
            clipped.append(f"... ({len(lines) - 12} more lines)")
        print("\n".join(clipped) if clipped else "(no output)")
