# Bug Bounty Agent

Interactive bug bounty assistant focused on authorized testing workflows.

## What It Does

- Prompts for a target program URL.
- Runs Step 1 intake:
  - gathers policy/scope/docs candidates,
  - finds prior bug/write-up links,
  - finds public social discussion links,
  - extracts domain candidates.
- Builds a terminal checklist (`done` vs `pending`).
- Runs Step 2:
  - recommends a domain to test next,
  - labels in-scope/out-of-scope/unknown from scope patterns,
  - suggests allowed vs blocked actions.
- Saves a structured report per run.
- Stores per-operator checkpoints (respawn point) for continuity.

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

Non-interactive:

```bash
./bug_bounty --program-url https://hackerone.com/<program> --operator-id <name>
```

With scope patterns:

```bash
./bug_bounty \
  --program-url https://hackerone.com/<program> \
  --scope-file scope.txt \
  --operator-id <name>
```

## Scope File Format

Examples:

```text
*.example.com
api.example.com
!blog.example.com
out-of-scope: support.example.com
```

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

## Output

- Reports: `.bug_bounty_agent/reports/<operator-id>/...`
- Checkpoints: `.bug_bounty_agent/checkpoints/<operator-id>/...`
- Learning memory: `.bug_bounty_agent/learning_memory.jsonl`

## Repository

Public repo:

- https://github.com/Obsidian-Nyx1/bug-bounty-agent
