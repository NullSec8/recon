#!/usr/bin/env python3
"""Production-grade modular recon orchestrator.

Use only on systems you own or have explicit written authorization to assess.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Sequence

from recon.context import RunContext
from recon.errors import ErrorType
from recon.executor import TaskExecutor
from recon.pipeline import build_initial_tasks, extend_tasks_from_pipeline
from recon.plugin_loader import discover_plugins
from recon.reporting import (
    build_json_payload,
    build_markdown_report,
    print_console_summary,
    write_json_report,
    write_markdown_report,
)
from recon.targeting import analyze_target
from recon.utils import normalize_argv

LOG = logging.getLogger("recon")
PLUGIN_DIRECTORY = Path(__file__).with_name("plugins")
DEFAULT_NMAP_ARGS = ["-sV", "-Pn"]
SAFE_MAX_JOBS = 8


def setup_logging(debug: bool) -> None:
    """Configure logging output and verbosity."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )


def parse_list_arg(value: str | None) -> set[str]:
    """Parse comma-separated module lists."""
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def _detect_default_jobs() -> int:
    """Choose a conservative default worker count from CPU count."""
    count = os.cpu_count() or 2
    return max(1, min(4, count))


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parse command-line arguments with grouped UX."""
    parser = argparse.ArgumentParser(
        description="Modular recon framework with plugin execution pipeline.",
    )

    target_group = parser.add_argument_group("Target Selection")
    target_group.add_argument("target", nargs="?", help="Single target (domain, IP, or URL)")
    target_group.add_argument("--targets-file", help="File containing targets, one per line")
    target_group.add_argument("--url", help="Override URL for web-centric modules")

    module_group = parser.add_argument_group("Module Controls")
    module_group.add_argument("--all", action="store_true", help="Enable all discovered modules")
    module_group.add_argument("--profile", choices=["quick", "web", "full"], help="Apply module presets")
    module_group.add_argument("--enable", help="Comma-separated modules to enable")
    module_group.add_argument("--disable", help="Comma-separated modules to disable")
    module_group.add_argument("--list-modules", action="store_true", help="List discovered modules and exit")

    perf_group = parser.add_argument_group("Performance & Safety")
    perf_group.add_argument("--timeout", type=int, default=120, help="Per command timeout in seconds")
    perf_group.add_argument("--jobs", type=int, default=_detect_default_jobs(), help="Concurrent task workers")
    perf_group.add_argument(
        "--max-jobs",
        type=int,
        default=SAFE_MAX_JOBS,
        help=f"Safety cap for workers (default: {SAFE_MAX_JOBS})",
    )
    perf_group.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        help="Maximum command starts per second (0 disables).",
    )
    perf_group.add_argument(
        "--task-delay",
        type=float,
        default=0.0,
        help="Delay in seconds before each command starts.",
    )
    perf_group.add_argument("--dry-run", action="store_true", help="Print planned tasks without executing")

    plugin_arg_group = parser.add_argument_group("Plugin Arguments")
    plugin_arg_group.add_argument("--nmap-args", nargs="*", default=DEFAULT_NMAP_ARGS, help="Extra nmap args")
    plugin_arg_group.add_argument("--nmap-scripts", help="Nmap script categories, e.g. default,vuln")
    plugin_arg_group.add_argument("--top-ports", type=int, help="Nmap top ports")
    plugin_arg_group.add_argument(
        "--dir-enum-args",
        nargs="*",
        default=[],
        help="Additional args for selected directory enumeration backend",
    )
    plugin_arg_group.add_argument("--wordlist", help="Wordlist path for dir enumeration")
    plugin_arg_group.add_argument(
        "--dig-record-type",
        default="A",
        help="Record type for dig (A, AAAA, CNAME, etc). Default: A",
    )
    plugin_arg_group.add_argument(
        "--parse-structured",
        action="store_true",
        default=True,
        help="Enable structured parsing for supported modules (default enabled)",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument("--json-out", help="Write structured JSON output to file")
    output_group.add_argument("--md-out", help="Write markdown report to file")
    output_group.add_argument("--verbose", action="store_true", help="Print full module outputs")
    output_group.add_argument("--failures-only", action="store_true", help="Show details only for failures")
    output_group.add_argument("--debug", action="store_true", help="Enable debug logs")

    args = parser.parse_args(normalize_argv(list(argv)))
    args.enable_set = parse_list_arg(args.enable)
    args.disable_set = parse_list_arg(args.disable)
    return args


def _load_targets(args: argparse.Namespace) -> list[str]:
    """Load and deduplicate targets from positional and file input."""
    targets: list[str] = []
    if args.target:
        targets.append(args.target.strip())
    if args.targets_file:
        for line in Path(args.targets_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    deduped: list[str] = []
    seen: set[str] = set()
    for target in targets:
        if target and target not in seen:
            seen.add(target)
            deduped.append(target)
    if not deduped:
        raise ValueError("No targets supplied. Provide positional target and/or --targets-file.")
    return deduped


def _profile_modules(profile: str | None) -> set[str]:
    """Map profile names to module sets."""
    if profile == "quick":
        return {"nslookup", "dig", "nmap"}
    if profile == "web":
        return {"whois", "nslookup", "lynx", "dir-enum"}
    if profile == "full":
        return {"whois", "nslookup", "dig", "nmap", "lynx", "dir-enum"}
    return set()


def _compute_enabled_modules(args: argparse.Namespace, available_modules: set[str]) -> set[str]:
    """Resolve final module set after profile/all/enable/disable flags."""
    enabled: set[str] = set()
    if args.all:
        enabled = set(available_modules)
    if args.profile:
        enabled |= _profile_modules(args.profile)
    enabled |= args.enable_set
    enabled -= args.disable_set
    if not enabled:
        raise ValueError("No modules selected. Use --all, --profile, or --enable.")
    unknown = enabled - available_modules
    if unknown:
        raise ValueError(f"Unknown enabled module(s): {', '.join(sorted(unknown))}")
    return enabled


def _validate_safety(args: argparse.Namespace) -> None:
    """Validate concurrency and timing safety constraints."""
    if args.timeout <= 0:
        raise ValueError("--timeout must be > 0")
    if args.jobs <= 0:
        raise ValueError("--jobs must be >= 1")
    if args.max_jobs <= 0:
        raise ValueError("--max-jobs must be >= 1")
    if args.jobs > args.max_jobs:
        raise ValueError(f"--jobs ({args.jobs}) exceeds --max-jobs ({args.max_jobs})")
    if args.jobs > SAFE_MAX_JOBS:
        raise ValueError(f"--jobs exceeds safe hard cap ({SAFE_MAX_JOBS})")
    if args.rate_limit < 0:
        raise ValueError("--rate-limit must be >= 0")
    if args.task_delay < 0:
        raise ValueError("--task-delay must be >= 0")


def _print_modules(plugin_map: dict[str, object]) -> None:
    """Print discovered module names and basic metadata."""
    print("Discovered modules:")
    for name in sorted(plugin_map):
        plugin = plugin_map[name]
        deps = ", ".join(plugin.required_binaries()) or "(none)"
        print(f"  - {name:<12} | needs: {deps}")


def _print_dry_run(tasks, contexts) -> None:
    """Print dry-run plan output."""
    print("[DRY-RUN] Planned targets:")
    for item in contexts:
        print(f"  - {item.raw} ({item.target_type}) host={item.host} ip={item.primary_ip or '-'}")
    print("\n[DRY-RUN] Planned tasks:")
    for task in tasks:
        resolved = task.resolved_target or task.target_info.host
        print(f"  - module={task.module_name:<10} target={task.target_info.raw:<25} resolved={resolved}")


def run(argv: Sequence[str]) -> int:
    """CLI entry point returning process code."""
    args = parse_args(argv)
    setup_logging(args.debug)
    _validate_safety(args)

    LOG.warning("Authorized-use only: run this tool only against approved targets.")

    plugin_map = discover_plugins(PLUGIN_DIRECTORY)
    if args.list_modules:
        _print_modules(plugin_map)
        return 0

    try:
        targets = _load_targets(args)
    except Exception as exc:
        LOG.error("Target loading failed: %s", exc)
        return 2

    available_modules = set(plugin_map.keys())
    try:
        enabled_modules = _compute_enabled_modules(args, available_modules)
    except Exception as exc:
        LOG.error("Module selection invalid: %s", exc)
        return 2

    LOG.info("Enabled modules: %s", ", ".join(sorted(enabled_modules)))

    target_contexts = [analyze_target(target) for target in targets]
    context = RunContext.from_args(
        timeout=args.timeout,
        jobs=args.jobs,
        max_jobs=args.max_jobs,
        rate_limit=args.rate_limit,
        task_delay=args.task_delay,
        dry_run=args.dry_run,
        verbose=args.verbose,
        failures_only=args.failures_only,
        plugin_args=vars(args),
    )

    tasks = build_initial_tasks(target_contexts, enabled_modules)
    if args.dry_run:
        _print_dry_run(tasks, target_contexts)
        return 0

    executor = TaskExecutor(plugin_map=plugin_map, context=context)
    all_results = executor.run_tasks(tasks)

    pipeline_tasks = extend_tasks_from_pipeline(all_results, enabled_modules, target_contexts)
    if pipeline_tasks:
        LOG.info("Pipeline generated %d follow-up task(s)", len(pipeline_tasks))
        all_results.extend(executor.run_tasks(pipeline_tasks))

    config = {
        "timeout": args.timeout,
        "jobs": args.jobs,
        "max_jobs": args.max_jobs,
        "rate_limit": args.rate_limit,
        "task_delay": args.task_delay,
        "profile": args.profile,
        "enabled_modules": sorted(enabled_modules),
    }
    payload = build_json_payload(
        generated_at=context.generated_at,
        targets=[target.to_dict() for target in target_contexts],
        config=config,
        results=all_results,
    )
    markdown_report = build_markdown_report(payload)

    print_console_summary(all_results, verbose=args.verbose, failures_only=args.failures_only)

    if args.json_out:
        write_json_report(args.json_out, payload)
        LOG.info("JSON report written: %s", args.json_out)
    if args.md_out:
        write_markdown_report(args.md_out, markdown_report)
        LOG.info("Markdown report written: %s", args.md_out)

    failed = [result for result in all_results if result.error_type != ErrorType.NONE]
    if failed:
        LOG.error("Completed with %d failed module run(s).", len(failed))
        return 1
    LOG.info("Completed successfully with %d module run(s).", len(all_results))
    return 0


def main() -> int:
    """System entry point."""
    return run(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
