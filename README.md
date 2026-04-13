# Recon Framework

A modular Python CLI for orchestrating reconnaissance tooling on Linux/Kali environments.

The project provides a plugin-based architecture for common recon modules (such as `nmap`, `dig`, `whois`, `nslookup`, `lynx`, and directory enumeration backends), structured results, scan chaining, and report generation.

> Authorized-use only: run this tool only against assets you own or have explicit written permission to test.

## Features

- Plugin auto-discovery from `plugins/`
- Concurrent execution with safety controls
  - job limits
  - rate limiting
  - inter-task delay
- Smart target handling
  - domain / IP / URL detection
  - domain resolution to IPs
- Scan chaining pipeline
  - `dig` discovered IPs can feed follow-up `nmap` tasks
- Structured parsing
  - `dig` output parsing (IPs/CNAMEs)
  - `nmap` XML parsing (open ports)
- Reporting
  - JSON report output
  - Markdown report output
- Improved CLI UX
  - module profiles
  - enable/disable controls
  - dry-run mode
  - debug logging

## Project Layout

```text
.
├── main.py
├── plugins/
│   ├── dig_plugin.py
│   ├── nmap_plugin.py
│   ├── whois_plugin.py
│   ├── nslookup_plugin.py
│   ├── lynx_plugin.py
│   └── dir_enum_plugin.py
└── recon/
    ├── context.py
    ├── errors.py
    ├── executor.py
    ├── models.py
    ├── pipeline.py
    ├── plugin_base.py
    ├── plugin_loader.py
    ├── reporting.py
    ├── targeting.py
    └── utils.py
```

## Requirements

- Python 3.10+ (3.11 recommended)
- Linux/Kali environment
- Optional external binaries depending on enabled modules:
  - `dig`
  - `nmap`
  - `whois`
  - `nslookup`
  - `lynx`
  - one of `feroxbuster`, `dirsearch`, `dirbuster`, or `gobuster` for `dir-enum`

## Quick Start

List available modules:

```bash
python3 main.py --list-modules
```

Dry-run a quick profile:

```bash
python3 main.py example.com --profile quick --dry-run --debug
```

Run selected modules and generate reports:

```bash
python3 main.py example.com \
  --enable dig,nmap \
  --json-out recon-report.json \
  --md-out recon-report.md
```

## CLI Usage

Show all options:

```bash
python3 main.py --help
```

Common patterns:

- Run all modules:

```bash
python3 main.py example.com --all
```

- Use a profile:

```bash
python3 main.py example.com --profile web
```

- Enable/disable modules explicitly:

```bash
python3 main.py example.com --enable dig,nmap,whois --disable whois
```

- Scan multiple targets from file:

```bash
python3 main.py --targets-file targets.txt --profile quick
```

- Apply performance controls:

```bash
python3 main.py example.com --enable dig,nmap --jobs 4 --max-jobs 8 --rate-limit 2 --task-delay 0.25
```

## Output and Reporting

- Console summary always includes module status and output snippets
- `--json-out <path>` writes structured report data
- `--md-out <path>` writes a human-readable markdown report with:
  - summary counts
  - open ports
  - discovered URLs
  - error list

## Safety Notes

- This tool can trigger active network probes.
- Always confirm legal authorization before scanning.
- Start with `--dry-run` to validate module selection and targets.
