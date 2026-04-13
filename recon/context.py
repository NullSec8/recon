"""Execution context shared by orchestrator and plugins."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict


@dataclass(slots=True)
class RunContext:
    """Runtime execution configuration."""

    timeout: int
    jobs: int
    max_jobs: int
    rate_limit: float
    task_delay: float
    dry_run: bool
    verbose: bool
    failures_only: bool
    plugin_args: Dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def from_args(
        cls,
        *,
        timeout: int,
        jobs: int,
        max_jobs: int,
        rate_limit: float,
        task_delay: float,
        dry_run: bool,
        verbose: bool,
        failures_only: bool,
        plugin_args: Dict[str, Any],
    ) -> "RunContext":
        """Build context from parsed CLI values."""
        return cls(
            timeout=timeout,
            jobs=jobs,
            max_jobs=max_jobs,
            rate_limit=rate_limit,
            task_delay=task_delay,
            dry_run=dry_run,
            verbose=verbose,
            failures_only=failures_only,
            plugin_args=plugin_args,
        )
