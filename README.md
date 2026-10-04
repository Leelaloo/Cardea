<p align="center">
  <img src="assets/branding/cardea-logo.png" alt="Cardea" width="360">
</p>

<p align="center"><b>A free security scanner for Claude Code skills.</b></p>

<p align="center">
  <img alt="License: Source-Available" src="https://img.shields.io/badge/license-source--available-B5563A?style=flat-square">
  <img alt="Python 3 standard library only" src="https://img.shields.io/badge/python-3%20stdlib%20only-20201E?style=flat-square">
  <img alt="Zero dependencies" src="https://img.shields.io/badge/dependencies-zero-2D6A4F?style=flat-square">
  <img alt="46 checks" src="https://img.shields.io/badge/checks-46-20201E?style=flat-square">
  <img alt="Self-scan 96/100" src="https://img.shields.io/badge/self--scan-96%2F100%20EXCELLENT-2D6A4F?style=flat-square">
</p>

Cardea reads a skill the way an attacker would: as files sitting on your disk. Point it at a folder and it runs 46 checks covering structure, broken references, prompt injection and hidden unicode, then hands you a 0-100 score, a findings list with file and line for everything, and if anything critical turns up, a DO NOT INSTALL verdict that no amount of good structure can talk its way out of.

```bash
python3 scripts/cardea.py <skill-folder>
```

It never runs the skill's code. Every finding comes from reading bytes, matching patterns, and handing the files to the static analyzers you already have installed (`bandit`, `semgrep`, `shellcheck`, `gitleaks`, `pip-audit`). Standard-library Python 3, zero dependencies, no API keys, no network. A skill that scores 98 really scored 98, and a skill flagged DO NOT INSTALL has the offending lines printed right there in the report.

Skills are just files anyone can publish, and nothing forces them to be safe or even functional before you install them. In our own Phase 1 audit of the ecosystem, 73% of sampled community skills came back broken or risky. Cardea is the check nobody was running.

*Tip: scan individual skill folders. Point it at a multi-skill collection and it will tell you and list the skill folders it found.*

## Demo: behind the scenes

![Cardea demo](https://github.com/user-attachments/assets/1e588b8f-3a72-495c-8e2e-eb17b811d348)


The recording is a real audit, not a mockup. It explains what Cardea is and what it checks, walks a benign fixture to a 98/100 EXCELLENT (its one LOW finding: a missing `LICENSE.txt`), then feeds it a deliberately malicious skill that scores 0/100 with the gate tripped on 6 CRITICAL findings, shows the `--fix` dry-run preview, and ends on the SVG badges. Every number on screen is the number Cardea actually wrote to its JSON report at recording time.

## What it checks

Structure first: does the `SKILL.md` frontmatter follow the official spec, does the name match the folder, are description and metadata where they belong. Then dead paths: every script and file the skill claims to exist gets checked against the disk, so a skill that breaks the moment you install it gets caught before you do. Then the part Cardea exists for: 31 behavioral patterns for prompt injection, instruction overrides, persona hijacking, credential harvesting and destructive commands, plus 15 unicode steganography characters that hide instructions in text that looks clean. Last, the security tooling pass: it runs the analyzers above when they are present, and treats a missing tool as information rather than a penalty, so a bare machine still gets a real scan.

## Quick start

```bash
# Full static audit, JSON report written to report.json
python3 scripts/cardea.py <target-skill-folder> --json report.json

# Self-contained SVG score badge
python3 scripts/cardea.py <target-skill-folder> --badge score.svg

# Preview safe mechanical fixes (dry-run, nothing touches disk)
python3 scripts/cardea.py <target-skill-folder> --fix

# Apply the fixes and see the re-scan score delta
python3 scripts/cardea.py <target-skill-folder> --fix --apply
```

`--fix` only touches the mechanical, unambiguous things: exec bits, a name field that does not match the folder, a UTF-8 BOM, a missing license stub. It never rewrites logic, and it refuses to follow symlinks outside the skill root.

## Scoring

Each finding deducts points by severity, with a cap per band so one messy-but-harmless area cannot sink an otherwise good skill: CRITICAL 25 points each and uncapped, HIGH 12 capped at 36, MEDIUM 6 capped at 18, LOW 2 capped at 10, INFO nothing.

A single CRITICAL also caps the whole score at 49 and sets DO NOT INSTALL, which is the point: a skill that exfiltrates credentials does not get to pass because it also had tidy frontmatter. The scanner exits 0 on a pass and 2 on DO NOT INSTALL, so a CI job can block on it with one line.

Bands: 90-100 EXCELLENT, 70-89 GOOD, 50-69 NEEDS WORK, below 50 BROKEN / RISKY.

### A real report

From the shipped benign fixture (`assets/demo/good-report.json`):

```json
{
  "target": "good-skill",
  "score": 98,
  "band": "EXCELLENT",
  "do_not_install": false,
  "counts": { "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "INFO": 2 },
  "findings": [
    { "severity": "LOW", "message": "no LICENSE file — marketplaces and buyers expect one" }
  ]
}
```

And the malicious skill from the demo video: 0/100, DO NOT INSTALL, 6 CRITICAL, 7 HIGH, 1 MEDIUM, 6 LOW, with dead references, a non-executable script and the injection evidence printed in full.

## The honest part

Cardea is static analysis. It never executes target code, so it cannot see what a skill does in a live conversation, and it does not pretend to: our own red-team rounds put its detection coverage at 3 of 5, because rules model skills as files while real attackers model them as conversational flows. We publish that number instead of hiding it. Scores are advisory pre-flight indicators, not guarantees; the install decision is yours. And Cardea scans itself before every release. The current release scores 96/100 EXCELLENT, which is what the badge above says.

## CI

`action/action.yml` is a drop-in composite GitHub Action that audits every pull request and fails the build on a DO-NOT-INSTALL verdict. The exact workflow snippet is in [`references/ci-guide.md`](references/ci-guide.md).

## Roadmap

The core scanner, the 46-check suite and the DO-NOT-INSTALL gate will never be paywalled. A Publisher Toolkit for people who ship skills for a living (CI action, `--fix` automation, priority threat updates) is coming next, and the check list grows every month, because the threat landscape does not sit still.

## License

Source-available. Free to download, run and modify, including at work, and free to fork for personal use or pull requests. Redistribution, rehosting or resale on any marketplace needs written permission. Full terms in [LICENSE.txt](LICENSE.txt).

## Documentation

[CHANGELOG.md](CHANGELOG.md) has every version. [SKILL.md](SKILL.md) is the skill contract itself. [references/ast10-mapping.md](references/ast10-mapping.md) maps findings to the OWASP Agentic Security Top 10, [references/scoring-rubric.md](references/scoring-rubric.md) is the full rubric, and [references/ci-guide.md](references/ci-guide.md) covers CI setup.
