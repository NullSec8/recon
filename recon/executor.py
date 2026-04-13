"""Concurrent task execution with rate and thread controls."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Iterable

from recon.context import RunContext
from recon.errors import ErrorType
from recon.models import TaskRequest, ToolResult
from recon.plugin_base import ReconPlugin


class RateLimiter:
    """Simple global limiter by minimum start interval."""

    def __init__(self, rate_per_second: float) -> None:
        self.rate_per_second = rate_per_second
        self._next_allowed = 0.0
        self._lock = Lock()

    def acquire(self) -> None:
        """Block until the next command start is permitted."""
        if self.rate_per_second <= 0:
            return
        min_interval = 1.0 / self.rate_per_second
        with self._lock:
            now = time.monotonic()
            wait_for = self._next_allowed - now
            if wait_for > 0:
                time.sleep(wait_for)
                now = time.monotonic()
            self._next_allowed = now + min_interval


class TaskExecutor:
    """Runs plugin tasks in a bounded thread pool."""

    def __init__(self, plugin_map: dict[str, ReconPlugin], context: RunContext) -> None:
        self.plugin_map = plugin_map
        self.context = context

    def run_tasks(self, tasks: Iterable[TaskRequest]) -> list[ToolResult]:
        """Execute tasks and return sorted results."""
        task_list = list(tasks)
        if not task_list:
            return []

        workers = min(self.context.jobs, self.context.max_jobs)
        limiter = RateLimiter(self.context.rate_limit)

        def _run(task: TaskRequest) -> ToolResult:
            plugin = self.plugin_map.get(task.module_name)
            if plugin is None:
                return ToolResult(
                    module_name=task.module_name,
                    target=task.target_info.raw,
                    command=[],
                    returncode=127,
                    output="Plugin not loaded",
                    duration_seconds=0.0,
                    error_type=ErrorType.TOOL_MISSING,
                )
            if not plugin.can_run(task):
                return ToolResult(
                    module_name=task.module_name,
                    target=task.target_info.raw,
                    command=[],
                    returncode=2,
                    output=f"Target type '{task.target_info.target_type}' unsupported by module.",
                    duration_seconds=0.0,
                    error_type=ErrorType.INVALID_TARGET,
                )

            if self.context.task_delay > 0:
                time.sleep(self.context.task_delay)
            limiter.acquire()
            return plugin.run(task, self.context)

        results: list[ToolResult] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_run, task) for task in task_list]
            for future in as_completed(futures):
                results.append(future.result())

        results.sort(key=lambda item: (item.target, item.module_name))
        return results

