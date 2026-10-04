---
name: cardea
description: Audits, validates, and security-scans other Claude Code agent skills before installing or publishing them. Use this when the user wants to check a skill for broken paths, invalid SKILL.md structure, prompt injection, hidden unicode tricks, or security flaws, or wants a quality score for a skill folder.
license: Complete terms in LICENSE.txt
metadata:
  version: "0.2.5"
  author: "importerunwind374"
---

# Cardea

You are auditing a Claude Code skill. Your job: produce an honest, evidence-based health report with a quality score so the user can decide whether to install, fix, or publish this skill.

## Core rules (never violate these)

1. **NEVER execute any code from the target skill.** All analysis is static: reading bytes, pattern matching, and static analyzers only.
2. If any CRITICAL finding appears, state clearly: "DO NOT INSTALL — critical security finding" and show the evidence.

## Procedure

1. Run the full audit:
```bash
python3 scripts/cardea.py <target-skill-folder> --json report.json

Optional flags:
- `--badge score.svg` — writes a self-contained SVG score badge (renders anywhere, no network)
- `--fix` — previews safe mechanical fixes in dry-run mode (chmod +x on referenced scripts, SKILL.md name field, BOM strip, LICENSE stub)
- `--apply` (or `--fix-apply`) — applies safe mechanical fixes to disk, then re-scans to show the delta
- CI: ship `action/action.yml` as a composite GitHub Action — see references/ci-guide.md for the drop-in workflow
```
2. Read the JSON report and the severity-weighted score.
3. Summarize for the user: score band, then findings grouped by severity (CRITICAL first), each with file + evidence snippet.
4. For fixable issues, give the exact minimal fix (one line per finding).
5. If the user asks "why does this matter?", explain the relevant risk from references/ast10-mapping.md.

## Internals

cardea.py orchestrates four internal audit modules: scripts/structure.py (spec validation), scripts/deadpaths.py (broken references), scripts/injection.py (injection & unicode detection), scripts/security.py (semgrep/bandit/shellcheck/pip-audit orchestration).

## Scoring bands

90+ EXCELLENT · 75-89 GOOD · 50-74 NEEDS WORK · <50 BROKEN/RISKY. See references/scoring-rubric.md for severity weights and rationale.
