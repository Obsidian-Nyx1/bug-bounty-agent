# Bug Bounty Agent

Interactive bug bounty assistant focused on authorized testing workflows.

## What It Does

- Shows startup instructions + MSF-style console prompt (`bug_bounty>>`).
- Supports module-first workflow:
  - `RECON`
  - `TESTS`
  - `REPORTING`
- Runs RECON intake:
  - gathers policy/scope/docs candidates,
  - downloads HackerOne scope artifacts when available (`CSV` + Burp JSON),
  - extracts in-scope/out-of-scope signals,
  - finds prior bug/write-up links and social discussions.
- Runs target recommendation:
  - suggests next target,
  - explains allowed vs blocked actions.
- Runs analysis:
  - builds a 100-test matrix,
  - prints scope label meanings in terminal for clarity.
- Runs testing:
  - scope-aware XSS (`xss_unified.py`),
  - safe in-scope afrog baseline scan.
  - XSS saves one consolidated run report (not one file per target).
- Runs reporting:
  - compiles session report from persisted recon/tests artifacts.
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

When the console starts, use:

```bash
show options
recon
tests
report
quit
```

Inside TESTS console (`bug_bounty/tests>>`):

```bash
show options
list
suggested
xss
afrog
back
```

When starting `xss` from the agent, you now get:
- quick XSS option prompts (`--headless`, `--async-mode`, `--waf-evasion`, `--html-report`)
- runtime estimate
- optional background run when estimate is high
- running-status notifications in the main prompt
- non-empty HTML artifacts only (empty HTML files are discarded)

Inside REPORTING console (`bug_bounty/report>>`):

```bash
show options
download
custom
list
view
back
```

## CLI UX (Subcommands)

Run RECON:

```bash
./bug_bounty recon --program-url https://hackerone.com/<program>
```

Run TESTS (XSS):

```bash
./bug_bounty test --tool xss --program-url https://hackerone.com/<program>
```

Run TESTS (afrog):

```bash
./bug_bounty test --tool afrog --program-url https://hackerone.com/<program>
```

Run REPORTING:

```bash
./bug_bounty report --program-url https://hackerone.com/<program>
```

Run all modules:

```bash
./bug_bounty run-all --program-url https://hackerone.com/<program>
```

Legacy flags are still supported:

```bash
./bug_bounty --program-url https://hackerone.com/<program> --xss_unified.py
./bug_bounty --program-url https://hackerone.com/<program> --run-automated test
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

`xss_unified.py` supports interactive (V2 confirmation) and non-interactive modes.

When it starts, it prints a quick instructions panel with all major options.

Warning:
- Run only on systems you own or where you have explicit written authorization.
- Unauthorized scanning may violate law and bug bounty policy.

Non-interactive example:

```bash
python3 xss_unified.py https://example.com --non-interactive --depth 1 --output xss_report.json
```

Example with additional controls:

```bash
python3 xss_unified.py https://example.com \
  --headless \
  --async-mode \
  --ml \
  --proxy-file proxies.txt \
  --scope-file scope.txt \
  --html-report report.html \
  --output report.json
```

Features:

- V2 confirmation flow:
  - choose modules (`waf`, reflected URL/param, reflected forms, stored, blind, dom, wp),
  - choose profile (`balanced`, `aggressive`, `ultra`, `custom`),
  - explicit proceed confirmation.
- Scope-aware enforcement:
  - `--scope-file`, `--in-scope`, `--out-of-scope`, `--no-subdomains`,
  - scope filtering applied to crawl + test phases.
- Proxy support:
  - single proxy via `--proxy`,
  - rotating proxies via `--proxy-file` (one proxy per line).
- Async reflected scanning:
  - URL/param async probing,
  - async reflected form probing (v3.1).
- Reflected/stored/DOM XSS probes.
- WordPress detection (`/wp-admin/`, `/wp-content/`, `/wp-includes/`, `/wp-login.php`).
- WordPress admin notice checks in `/wp-admin/` pages for risky HTML patterns.
- Runtime knobs for depth/workers/delay/jitter/payload limits.
- Module toggles:
  - `--no-waf`, `--no-reflected`, `--no-forms`, `--no-stored`, `--no-blind`, `--no-dom`, `--no-wp`.
  - `--non-interactive` to bypass prompts in automation/CI.

## Output

- Session artifacts:
  - `reports/<operator-id>/<session-id>/recon/project.json`
  - `reports/<operator-id>/<session-id>/tests/index.json`
  - `reports/<operator-id>/<session-id>/tests/xss_unified/xss_unified_<timestamp>.json`
  - `reports/<operator-id>/<session-id>/tests/afrog/...`
  - `reports/<operator-id>/<session-id>/reports/final_*.md`
- Reports (legacy + additional):
  - `.bug_bounty_agent/reports/<operator-id>/...`
- Checkpoints: `.bug_bounty_agent/checkpoints/<operator-id>/...`
- Learning memory: `.bug_bounty_agent/learning_memory.jsonl`
- Downloads: `.bug_bounty_agent/downloads/<program>/...`

## Repository

Public repo:

- https://github.com/Obsidian-Nyx1/bug-bounty-agent
