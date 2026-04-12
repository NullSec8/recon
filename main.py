diff --git a/main.py b/main.py
index 2f9a147db12e882f0e2a73018937fd41ffbad3e5..2c165b2172b2ca03759c02facb5d5a8851dbfa6b 100644
--- a/main.py
+++ b/main.py
@@ -1 +1,368 @@
-print("Hello")
+#!/usr/bin/env python3
+"""Powerful recon orchestrator for Kali/Linux tools.
+
+Supported modules:
+- whois
+- nslookup
+- dig
+- nmap
+- lynx (HTTP content dump)
+- dir enumeration (dirbuster/feroxbuster/dirsearch/gobuster)
+
+Use only on assets you own or have explicit written authorization to test.
+"""
+
+from __future__ import annotations
+
+import argparse
+import json
+import shutil
+import subprocess
+import sys
+import textwrap
+from concurrent.futures import ThreadPoolExecutor, as_completed
+from dataclasses import asdict, dataclass
+from datetime import datetime, timezone
+from pathlib import Path
+from typing import Iterable, List, Sequence
+
+
+@dataclass
+class ToolResult:
+    name: str
+    target: str
+    command: List[str]
+    returncode: int
+    output: str
+    duration_seconds: float
+
+
+def command_exists(command: str) -> bool:
+    return shutil.which(command) is not None
+
+
+def normalize_argv(argv: Sequence[str]) -> List[str]:
+    """Accept common single-dash long options such as `-all` by normalizing to `--all`."""
+    normalized: List[str] = []
+    for arg in argv:
+        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 2 and not arg[1].isdigit():
+            normalized.append(f"--{arg[1:]}")
+        else:
+            normalized.append(arg)
+    return normalized
+
+
+def run_command(name: str, target: str, command: List[str], timeout: int) -> ToolResult:
+    start = datetime.now(timezone.utc)
+    try:
+        completed = subprocess.run(
+            command,
+            capture_output=True,
+            text=True,
+            timeout=timeout,
+            check=False,
+        )
+        output = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
+        end = datetime.now(timezone.utc)
+        return ToolResult(
+            name=name,
+            target=target,
+            command=command,
+            returncode=completed.returncode,
+            output=output.strip() or "(no output)",
+            duration_seconds=(end - start).total_seconds(),
+        )
+    except subprocess.TimeoutExpired:
+        end = datetime.now(timezone.utc)
+        return ToolResult(
+            name=name,
+            target=target,
+            command=command,
+            returncode=124,
+            output=f"Command timed out after {timeout}s",
+            duration_seconds=(end - start).total_seconds(),
+        )
+    except Exception as exc:  # defensive fallback
+        end = datetime.now(timezone.utc)
+        return ToolResult(
+            name=name,
+            target=target,
+            command=command,
+            returncode=1,
+            output=f"Failed to run command: {exc}",
+            duration_seconds=(end - start).total_seconds(),
+        )
+
+
+def print_result(result: ToolResult) -> None:
+    status = "OK" if result.returncode == 0 else f"EXIT {result.returncode}"
+    cmd = " ".join(result.command)
+    print(f"  - [{result.target}] {result.name:<12} {status:<9} {result.duration_seconds:>6.2f}s | {cmd}")
+
+
+def format_output_snippet(output: str, max_lines: int = 12, max_width: int = 120) -> str:
+    lines = output.splitlines()
+    clipped = lines[:max_lines]
+    if len(lines) > max_lines:
+        clipped.append(f"... ({len(lines) - max_lines} more lines)")
+    cleaned = [textwrap.shorten(line, width=max_width, placeholder=" ...") for line in clipped]
+    return "\n".join(cleaned) if cleaned else "(no output)"
+
+
+def print_result_details(result: ToolResult, verbose: bool) -> None:
+    print(f"\n[{result.target}] {result.name} output:")
+    if verbose:
+        print(result.output)
+    else:
+        print(format_output_snippet(result.output))
+
+
+def pick_dir_enum_command(args: argparse.Namespace, target: str) -> tuple[str, List[str]]:
+    url = args.url if args.url else f"http://{target}"
+
+    if command_exists("feroxbuster"):
+        wordlist = args.wordlist or "/usr/share/wordlists/dirb/common.txt"
+        return "feroxbuster", ["feroxbuster", "-u", url, "-w", wordlist] + args.dir_enum_args
+
+    if command_exists("dirsearch"):
+        wordlist = args.wordlist or "/usr/share/wordlists/dirb/common.txt"
+        return "dirsearch", ["dirsearch", "-u", url, "-w", wordlist] + args.dir_enum_args
+
+    if command_exists("dirbuster"):
+        return "dirbuster", ["dirbuster"] + args.dir_enum_args + [target]
+
+    if command_exists("gobuster"):
+        wordlist = args.wordlist or "/usr/share/wordlists/dirb/common.txt"
+        return "gobuster", ["gobuster", "dir", "-u", url, "-w", wordlist] + args.dir_enum_args
+
+    return "dir-enum", ["echo", "No directory enumeration tool found (feroxbuster/dirsearch/dirbuster/gobuster)."]
+
+
+def build_tasks_for_target(args: argparse.Namespace, target: str) -> Iterable[tuple[str, str, List[str]]]:
+    if args.whois:
+        yield "whois", target, ["whois", target]
+
+    if args.nslookup:
+        yield "nslookup", target, ["nslookup", target]
+
+    if args.dig:
+        yield "dig", target, ["dig", target, "+short"]
+
+    if args.nmap:
+        nmap_cmd = ["nmap"] + args.nmap_args + [target]
+        if args.nmap_scripts:
+            nmap_cmd += ["--script", args.nmap_scripts]
+        if args.top_ports:
+            nmap_cmd += ["--top-ports", str(args.top_ports)]
+        yield "nmap", target, nmap_cmd
+
+    if args.lynx:
+        lynx_url = args.url if args.url else f"http://{target}"
+        yield "lynx", target, ["lynx", "-dump", lynx_url]
+
+    if args.dir_enum:
+        mod_name, cmd = pick_dir_enum_command(args, target)
+        yield mod_name, target, cmd
+
+
+def load_targets(args: argparse.Namespace) -> List[str]:
+    targets: List[str] = []
+
+    if args.target:
+        targets.append(args.target)
+
+    if args.targets_file:
+        for line in Path(args.targets_file).read_text(encoding="utf-8").splitlines():
+            line = line.strip()
+            if line and not line.startswith("#"):
+                targets.append(line)
+
+    deduped = []
+    seen = set()
+    for item in targets:
+        if item not in seen:
+            seen.add(item)
+            deduped.append(item)
+
+    if not deduped:
+        raise ValueError("No targets supplied. Provide target positional arg and/or --targets-file.")
+
+    return deduped
+
+
+def apply_profile(args: argparse.Namespace) -> None:
+    if args.profile == "quick":
+        args.nslookup = True
+        args.dig = True
+        args.nmap = True
+        if args.nmap_args == ["-sV", "-Pn"]:
+            args.nmap_args = ["-sV", "-Pn", "-T4"]
+        if args.top_ports is None:
+            args.top_ports = 100
+    elif args.profile == "web":
+        args.whois = True
+        args.nslookup = True
+        args.lynx = True
+        args.dir_enum = True
+    elif args.profile == "full":
+        args.whois = args.nslookup = args.dig = args.nmap = args.lynx = args.dir_enum = True
+        if args.top_ports is None:
+            args.top_ports = 1000
+
+
+def parse_args() -> argparse.Namespace:
+    parser = argparse.ArgumentParser(
+        description="Powerful Kali/Linux recon helper. Run one or many recon modules across targets."
+    )
+    parser.add_argument("target", nargs="?", help="Domain/IP target (example.com or 10.10.10.10)")
+    parser.add_argument("--targets-file", help="File with targets, one per line")
+    parser.add_argument(
+        "--url",
+        help="Optional full URL for web modules (lynx/dir enum), e.g. https://example.com",
+    )
+    parser.add_argument("--timeout", type=int, default=120, help="Timeout seconds per command")
+    parser.add_argument("--jobs", type=int, default=2, help="Concurrent jobs (default: 2)")
+
+    parser.add_argument("--whois", action="store_true", help="Run whois")
+    parser.add_argument("--nslookup", action="store_true", help="Run nslookup")
+    parser.add_argument("--dig", action="store_true", help="Run dig +short")
+    parser.add_argument("--nmap", action="store_true", help="Run nmap")
+    parser.add_argument("--lynx", action="store_true", help="Run lynx -dump")
+    parser.add_argument("--dir-enum", action="store_true", help="Run directory enumeration module")
+    parser.add_argument("--all", action="store_true", help="Enable all modules")
+
+    parser.add_argument(
+        "--profile",
+        choices=["quick", "web", "full"],
+        help="Preset modules and defaults",
+    )
+
+    parser.add_argument("--nmap-args", nargs="*", default=["-sV", "-Pn"], help="Extra nmap args")
+    parser.add_argument("--nmap-scripts", help="Nmap script selector, e.g. default,vuln")
+    parser.add_argument("--top-ports", type=int, help="Nmap top ports count")
+
+    parser.add_argument(
+        "--dir-enum-args",
+        nargs="*",
+        default=[],
+        help="Extra args for selected directory enumeration backend",
+    )
+    parser.add_argument("--wordlist", help="Wordlist path for dir enum backends")
+
+    parser.add_argument("--json-out", help="Write structured JSON results to this file")
+    parser.add_argument(
+        "--verbose",
+        action="store_true",
+        help="Print full output for each module (default shows compact snippets)",
+    )
+    parser.add_argument(
+        "--failures-only",
+        action="store_true",
+        help="Print output details only for non-zero exit results",
+    )
+
+    args = parser.parse_args(normalize_argv(sys.argv[1:]))
+
+    if args.all:
+        args.whois = args.nslookup = args.dig = args.nmap = args.lynx = args.dir_enum = True
+
+    if args.profile:
+        apply_profile(args)
+
+    if not any([args.whois, args.nslookup, args.dig, args.nmap, args.lynx, args.dir_enum]):
+        parser.error("No modules selected. Use --all, --profile, or at least one module flag.")
+
+    if args.jobs < 1:
+        parser.error("--jobs must be >= 1")
+
+    return args
+
+
+def run_tasks(args: argparse.Namespace, tasks: Sequence[tuple[str, str, List[str]]]) -> List[ToolResult]:
+    results: List[ToolResult] = []
+
+    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
+        future_map = {}
+        for name, target, cmd in tasks:
+            executable = cmd[0]
+            if executable != "echo" and not command_exists(executable):
+                results.append(
+                    ToolResult(
+                        name=name,
+                        target=target,
+                        command=cmd,
+                        returncode=127,
+                        output=f"'{executable}' not found in PATH.",
+                        duration_seconds=0.0,
+                    )
+                )
+                continue
+
+            future = pool.submit(run_command, name, target, cmd, args.timeout)
+            future_map[future] = (name, target)
+
+        for future in as_completed(future_map):
+            results.append(future.result())
+
+    # Keep a stable readable order: target then module name
+    results.sort(key=lambda r: (r.target, r.name))
+    return results
+
+
+def write_json_report(args: argparse.Namespace, targets: Sequence[str], results: Sequence[ToolResult]) -> None:
+    if not args.json_out:
+        return
+
+    payload = {
+        "generated_at": datetime.now(timezone.utc).isoformat(),
+        "targets": list(targets),
+        "config": {
+            "timeout": args.timeout,
+            "jobs": args.jobs,
+            "profile": args.profile,
+        },
+        "results": [asdict(result) for result in results],
+    }
+
+    output_path = Path(args.json_out)
+    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
+    print(f"\n[+] JSON report written to {output_path}")
+
+
+def main() -> int:
+    args = parse_args()
+
+    print("[!] Authorized-use only: run this tool only against approved targets.")
+
+    try:
+        targets = load_targets(args)
+    except Exception as exc:
+        print(f"[-] Target loading error: {exc}", file=sys.stderr)
+        return 2
+
+    tasks = [task for target in targets for task in build_tasks_for_target(args, target)]
+    results = run_tasks(args, tasks)
+
+    print("\nRecon results:")
+    for result in results:
+        print_result(result)
+
+    print("\nOutput details:")
+    for result in results:
+        if args.failures_only and result.returncode == 0:
+            continue
+        print_result_details(result, verbose=args.verbose)
+
+    write_json_report(args, targets, results)
+
+    failed = [r for r in results if r.returncode != 0]
+    if failed:
+        print(f"\nCompleted with {len(failed)} warning/error module(s) across {len(targets)} target(s).")
+        return 1
+
+    print(f"\nCompleted successfully across {len(targets)} target(s).")
+    return 0
+
+
+if __name__ == "__main__":
+    sys.exit(main())
