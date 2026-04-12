#!/usr/bin/env python3
"""Simple recon orchestrator for Kali/Linux tools.

This script wraps common reconnaissance commands into one CLI:
- whois
- nslookup
- nmap
- lynx
- dirbuster (or gobuster fallback)

Use only on systems you own or have explicit permission to test.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, List


@dataclass
class ToolResult:
    name: str
    command: List[str]
    returncode: int
    output: str


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def run_command(name: str, command: List[str], timeout: int) -> ToolResult:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
        return ToolResult(
            name=name,
            command=command,
            returncode=completed.returncode,
            output=output.strip() or "(no output)",
        )
    except subprocess.TimeoutExpired:
        return ToolResult(
            name=name,
            command=command,
            returncode=124,
            output=f"Command timed out after {timeout}s",
        )
    except Exception as exc:  # defensive fallback
        return ToolResult(
            name=name,
            command=command,
            returncode=1,
            output=f"Failed to run command: {exc}",
        )


def print_result(result: ToolResult) -> None:
    status = "OK" if result.returncode == 0 else f"EXIT {result.returncode}"
    cmd = " ".join(result.command)
    print(f"\n{'=' * 80}\n[{result.name}] {status}\n$ {cmd}\n{'-' * 80}")
    print(result.output)


def build_tasks(args: argparse.Namespace) -> Iterable[tuple[str, List[str]]]:
    if args.whois:
        yield "whois", ["whois", args.target]

    if args.nslookup:
        yield "nslookup", ["nslookup", args.target]

    if args.nmap:
        nmap_cmd = ["nmap"] + args.nmap_args + [args.target]
        yield "nmap", nmap_cmd

    if args.lynx:
        lynx_url = args.url if args.url else f"http://{args.target}"
        yield "lynx", ["lynx", "-dump", lynx_url]

    if args.dirbuster:
        if command_exists("dirbuster"):
            # DirBuster is normally GUI-based, but some environments expose a CLI launcher.
            # We pass through provided args and keep target at the end.
            yield "dirbuster", ["dirbuster"] + args.dirbuster_args + [args.target]
        elif command_exists("gobuster"):
            wordlist = args.wordlist or "/usr/share/wordlists/dirb/common.txt"
            url = args.url if args.url else f"http://{args.target}"
            gobuster_cmd = [
                "gobuster",
                "dir",
                "-u",
                url,
                "-w",
                wordlist,
            ] + args.gobuster_args
            yield "gobuster (dirbuster fallback)", gobuster_cmd
        else:
            yield "dirbuster", ["echo", "Neither dirbuster nor gobuster is installed."]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recon helper for Kali/Linux. Run one or many tools against a target."
    )
    parser.add_argument("target", help="Domain or host target (example.com or 10.10.10.10)")
    parser.add_argument(
        "--url",
        help="Optional full URL for web tools (lynx/dirbuster/gobuster), e.g. https://example.com",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Timeout (seconds) for each tool command (default: 120)",
    )

    parser.add_argument("--whois", action="store_true", help="Run whois")
    parser.add_argument("--nslookup", action="store_true", help="Run nslookup")
    parser.add_argument("--nmap", action="store_true", help="Run nmap")
    parser.add_argument("--lynx", action="store_true", help="Run lynx -dump")
    parser.add_argument("--dirbuster", action="store_true", help="Run dirbuster (or gobuster fallback)")

    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all supported recon modules",
    )

    parser.add_argument(
        "--nmap-args",
        nargs="*",
        default=["-sV", "-Pn"],
        help="Extra args for nmap (default: -sV -Pn)",
    )
    parser.add_argument(
        "--dirbuster-args",
        nargs="*",
        default=[],
        help="Extra args for dirbuster",
    )
    parser.add_argument(
        "--gobuster-args",
        nargs="*",
        default=[],
        help="Extra args for gobuster fallback",
    )
    parser.add_argument(
        "--wordlist",
        default=None,
        help="Wordlist path for gobuster fallback",
    )

    args = parser.parse_args()

    if args.all:
        args.whois = args.nslookup = args.nmap = args.lynx = args.dirbuster = True

    if not any([args.whois, args.nslookup, args.nmap, args.lynx, args.dirbuster]):
        parser.error("No module selected. Use --all or pick at least one module flag.")

    return args


def main() -> int:
    args = parse_args()

    print("[!] Authorized-use only: run this tool only against approved targets.")

    results: List[ToolResult] = []
    for name, cmd in build_tasks(args):
        executable = cmd[0]
        if executable != "echo" and not command_exists(executable):
            results.append(
                ToolResult(
                    name=name,
                    command=cmd,
                    returncode=127,
                    output=f"'{executable}' not found in PATH.",
                )
            )
            continue

        results.append(run_command(name=name, command=cmd, timeout=args.timeout))

    for result in results:
        print_result(result)

    failed = [r for r in results if r.returncode != 0]
    if failed:
        print(f"\nCompleted with {len(failed)} warning/error module(s).")
        return 1

    print("\nCompleted successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
