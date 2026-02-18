# Bug Bounty Intake Report: hackerone.com

- Generated: 2026-02-18T14:59:58.402946+00:00
- Operator: red
- Mode: balanced
- Project URL: https://hackerone.com

## Executive Summary
Project intake complete for hackerone.com. Collected candidate scope/policy/docs, prior bug context, social signals, and domains.

## Step 2 Recommendation
- Recommended domain: hackerone.com
- Scope status: in-scope
- Why: hackerone.com matches provided in-scope domain patterns.

### Allowed Tests (Next)
- Start with passive recon and endpoint inventory
- Map auth/session flows and access control
- Test IDOR, rate-limit, business-logic, and injection safely
### Blocked / Not Allowed
- No DoS or traffic flooding unless explicitly allowed
- No social engineering or physical attacks
- No testing third-party assets not listed in scope

## Parsed Scope Data
### In-Scope Patterns
- hackerone.com
- api.hackerone.com
### Out-of-Scope Patterns
- support.hackerone.com
- blog.hackerone.com

## Collected Information
### Policy Links
- None found in this run.
### Scope Links
- None found in this run.
### Documentation Links
- None found in this run.
### Previous Bug/Write-up Links
- None found in this run.
### Social Discussion Links (Public)
- None found in this run.
### Domain Candidates
- None found in this run.

## Checklist
- [x] Program URL captured
- [x] Initial web context scan executed
- [ ] Policy links not discovered yet
- [ ] Scope links not discovered yet
- [ ] Technical documentation links not discovered yet
- [ ] Previous bug/write-up context not discovered yet
- [ ] Public social discussion links not discovered yet
- [ ] Candidate in-scope domains not extracted yet
- [ ] Validate all discovered links manually
- [ ] Build definitive in-scope asset list
- [ ] Start recon and testing against validated in-scope assets
- [ ] Collect evidence and draft report templates

## Recommended Next Actions
1. Manually locate scope page/assets tab from the program portal.
2. Manually locate policy/guidelines page from the program portal.
3. Confirm policy and scope URLs before any active testing.
4. Create in-scope and out-of-scope lists from verified sources.
5. Map high-value assets (auth, APIs, uploads, payment, admin).
6. Launch recon pipeline only against approved assets.
7. Track findings in reproducible checklist format.

## Notes
- Operator profile: red
- Learning profile runs for this project: 8
- Respawn checkpoint saved: .bug_bounty_agent/checkpoints/red/hackerone.com.json
- Scope and policy findings are best-effort; verify before active testing.
- Previous checkpoint restored and used for planning.
- GITHUB_TOKEN missing. Skipped GitHub Models inference.
- Step 2 recommendation generated from checklist/discovery + parsed scope patterns.

## Source Index
- https://hackerone.com
