# Bug Bounty Agent

Interactive bug bounty assistant focused on authorized testing workflows.

## What It Does

- Shows startup instructions + interactive workflow menu (`1/2/3/4/a/q`).
- Runs Step 1 intake:
  - gathers policy/scope/docs candidates,
  - downloads HackerOne scope artifacts when available (`CSV` + Burp JSON),
  - extracts in-scope/out-of-scope signals,
  - finds prior bug/write-up links and social discussions.
- Runs Step 2 recommendation:
  - suggests next target,
  - explains allowed vs blocked actions.
- Runs Step 3 analysis:
  - builds a 50-test matrix,
  - prints scope label meanings in terminal for clarity.
- Runs Step 4 compile-report view:
  - sources, notes, report paths, automated artifacts.
- Optional automated checks (`--run-automated test`) and optional scope-aware XSS step (`--xss_unified.py`).
- Saves reports and per-operator checkpoints (respawn continuity).

## Safety Model

- Requires HTTPS URL.
- Blocks localhost/private/loopback targets in intake.
- Emphasizes scope validation before active testing.
- Designed for authorized bug bounty programs only.

## Quick Start

```bash
chmod +x ./bug_bounty
./bug_bounty
```

On startup, the agent now checks required Python dependencies and auto-installs missing ones for the current interpreter.

Non-interactive:

```bash
./bug_bounty --program-url https://hackerone.com/<program> --operator-id <name>
```

With scope/policy files:

```bash
./bug_bounty \
  --program-url https://hackerone.com/<program> \
  --scope-file scope.txt \
  --policy-file policy.txt \
  --operator-id <name>
```

Run all output sections without the interactive menu:

```bash
./bug_bounty --program-url https://hackerone.com/<program> --non-interactive-output
```

Run built-in automated checks:

```bash
./bug_bounty --program-url https://hackerone.com/<program> --run-automated test
```

Run scope-aware unified XSS flow:

```bash
./bug_bounty --program-url https://hackerone.com/<program> --xss_unified.py
```

Disable dependency auto-install:

```bash
./bug_bounty --no-auto-install-deps
```

## Scope File Format

Examples:

```text
*.example.com
api.example.com
!blog.example.com
out-of-scope: support.example.com
```

## Scope Labels (Step 3)

- `verified_in_scope_from_policy_or_artifact`
  - Explicitly in scope from policy/scope artifacts.
- `verified_out_of_scope_from_policy_or_artifact`
  - Explicitly out of scope from policy/scope artifacts.
- `discovered_target_requires_scope_validation`
  - Found during discovery but not explicitly verified yet.

## Optional AI (GitHub Models)

Set token to enable model-based planning:

```bash
export GITHUB_TOKEN=...
./bug_bounty --program-url https://hackerone.com/<program>
```

Optional model cap:

```bash
export GITHUB_MODELS_MAX_MODELS=5
```

## Unified XSS Scanner

`xss_unified.py` supports both interactive and non-interactive modes.

Non-interactive example:

```bash
python3 xss_unified.py --target https://example.com --depth 1 --output xss_report.json
```

Features:

- Reflected/stored/DOM XSS probes.
- WordPress detection (`/wp-admin/`, `/wp-content/`, `/wp-includes/`, `/wp-login.php`).
- WordPress admin notice checks in `/wp-admin/` pages for risky HTML patterns.

## Output

- Reports: `.bug_bounty_agent/reports/<operator-id>/...`
- Checkpoints: `.bug_bounty_agent/checkpoints/<operator-id>/...`
- Learning memory: `.bug_bounty_agent/learning_memory.jsonl`
- Downloads: `.bug_bounty_agent/downloads/<program>/...`

## Repository

Public repo:

- https://github.com/Obsidian-Nyx1/bug-bounty-agent
