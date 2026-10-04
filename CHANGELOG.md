## v0.2.6 (2026-10-04) — security hardening (adversarial audit round)

- Oversized-file gate: files over 2MB are now a CRITICAL fail-safe instead of a MEDIUM skip — an unscannable file can no longer read as a clean verdict (audit H7).
- ReDoS fix: bounded the token in the dynamic-import pattern; a 60KB crafted token scanned in well under a second instead of tens of seconds, with linear scaling (audit H6).
- Detection hardening: scans now normalize text (NFKC folding, zero-width/bidi stripping, Cyrillic/Greek homograph folding) and gained multilingual instruction-override patterns (FR/ES/DE/IT), paraphrase variants, and high-entropy-blob heuristics (audit H1).
- Analyzer integrity: resolved tool paths are recorded in the report, and a user-writable analyzer path (PATH shadowing) is a HIGH finding (audit H2).
- Built-in AST baseline: when bandit is unavailable, deterministic stdlib checks still flag eval/exec with non-literal args and subprocess shell=True, and the missing analyzer visibly degrades the verdict (audit H3).
- Deterministic verdicts: frontmatter parsing no longer differs between hosts with and without PyYAML (audit M15).
- BOM handling: a UTF-8 BOM in SKILL.md no longer produces false CRITICALs and a false DO-NOT-INSTALL (audit M10).
- GitHub Action: step-summary reports embed inside a 4-backtick fence with backtick-run collapsing (fence-breakout audit M3); default ref corrected to the live default branch.
- Autofix: atomic writes with OSError guards (no truncated SKILL.md on a failed write), missing `name` insertion, CRLF preservation, LICENSE* glob awareness (audits M9, M12, M13, M14).
- Fenced code blocks with language parameters are now parsed for invoked-script executable checks (audit M11); scheme URLs (ftp://, git@) no longer produce dead-reference false positives.
- Case-only name/folder mismatches are LOW with an auto-fix, not HIGH (audit H5 root cause); badge SVGs gained a viewBox and per-score IDs.
- Exit codes: DO-NOT-INSTALL keeps exit 2 even when report writing fails; `partial` flag added to the JSON report (audits L11, M1).
- README: score bands aligned with the engine (75-89 GOOD), check count stated honestly, self-scan badge set to the real 94/100.
- Trust-claim impersonation hardened: the pattern caught only a few wordings, so a skill self-certifying with fabricated verification claims, scanner-name attribution, cleanliness claims, or do-not-rescan reassurance scanned 98/100 EXCELLENT. The pattern now catches that whole class of self-certification and reassurance phrasing (self-descriptions as verified/certified/audited, install-safety assurances, rescan-dispatching reassurance, scanner-attributed verification) without flagging legitimate audit documentation.
- Vendored-scanner bypass closed: `doctor: allow` suppression markers were trusted anywhere under the scanner's package root, so a malicious skill bundling its own copy of Cardea could mark payload lines and scan itself clean (verified PoC: a classic instruction-override payload annotated with the marker scanned 86/100 GOOD through the bundled copy). Markers are now honored only in a byte-identical copy of Cardea's own pattern library (SHA-256), and a comment-position marker in any scanned file is itself a HIGH scanner-evasion finding that suppresses nothing.

# Changelog

## v0.2.5 (2026-10-03)
- Rebrand release: **Cardea** (was Skill Doctor). Entry point renamed `scripts/doctor.py` → `scripts/cardea.py`; banners, report headers, and badge footer now read **CARDEA REPORT** / **Scanned by Cardea**.
- New brand assets: logo lockup and favicons (`assets/branding/`), demo video (`assets/demo/cardea-demo.mp4`), refreshed README with a behind-the-scenes demo section.
- Added community docs: SECURITY.md, CONTRIBUTING.md, SUPPORT.md, CODE_OF_CONDUCT.md.
- No scanner-logic changes: the 46-check suite and scoring are unchanged from v0.2.4.

## v0.2.4 (2026-09-17)
- ReDoS fuzz clean (31 patterns, 930 inputs, worst 0.69s)
- Hostile-filename safety: pass file arguments after `--` separator and sanitize relative paths with `./` prefix for subprocess tools (bandit, shellcheck, semgrep, gitleaks, pip-audit) in `scripts/security.py` to prevent flag misinterpretation when filenames start with `-` (e.g. `--help-bomb.py`).
- `--fix` dry-run default: `--fix` without `--apply` performs a preview dry-run (prints proposed changes without modifying files); `--apply` (or `--fix-apply`) performs disk writes and triggers re-scan.
- Eval suite: updated to 49 cases (added `49-hostile-filename`).
- Split-flags rm detection: updated regex in `scripts/injection.py` to catch destructive deletion commands with separated flags (root/home targets, recursive and force flags in any order).
- Dangling symlink escape guard: updated `scripts/structure.py` to check both dirs and files, flagging external symlink directory escapes even when the target is dangling/non-existent.
- Case-21 multiline exfil fix: verified multiline exfiltration pattern (`(?is)`) catches environment variable harvesting and network exfiltration separated across newlines.
- Eval suite: 49/49 PASS (added cases 47-split-flags and 48-dangling-symlink; case 21 regression fixed).

## v0.2.3 (2026-09-16)
- CRITICAL fix (round-3 QA red-team): directory symlinks resolving outside the skill root now raise CRITICAL "symlink directory escape" — os.walk silently skips them, which hid the linked contents from every scanner (complete bypass, exit 2 DNI).
- UX: --json to an unwritable path now exits 1 with a clean error (was an uncaught traceback); --badge failure no longer prints a misleading success line.
- Eval suite: 46/46 — new case 46-dir-symlink pins the escape repro.

## v0.2.2 (2026-09-16)
- Round-2 panel hardening (4 adversarial re-reviews):
- 2 new CRITICAL patterns: obfuscated execution via byte-array constructors (exec/eval of bytes(...)), instruction-override synonyms (discard/override/bypass/cancel/nullify/reset/erase + directives/guidelines/constraints). Expanded: credential harvest now covers docker/kube/netrc configs; recursive-delete catches Path.home(), os.getenv("HOME"), and home-wildcard globs; new HIGH for indirect __import__ assignments.
- Scan-coverage fix: text scan now covers .zsh/.mjs/.cjs/.ps1/.fish/.php sources.
- File-cap fail-safe: scan order is now priority-based (SKILL.md, then scripts/, then the rest) and any truncation logs a CRITICAL — a partial scan can never clear a skill (defeats the padding-drowning evasion). Oversized-skill HIGH retained.
- Missing bandit/pip-audit on the host: INFO (was MEDIUM; contradicted documented behavior).
- CI action fail-closed: scanner crashes (exit codes other than 0/2) fail the job; missing report file fails the job; fail-on-critical comparison is case-insensitive.
- Eval suite: 45/45 at v0.2.2 — 6 new evasion-repro cases covering the round-2 red-team vectors (synonym override, byte-array exec, Path.home deletion, .zsh coverage, indirect import, home-glob delete).

## v0.2.1 (2026-09-16)
- Review-panel hardening (7 independent adversarial reviews pre-listing):
- New detection patterns (29 total): dynamic-import execution (`__import__`/exec, exec+`b64decode`), an override-phrase variant that tells the model to drop its standing instructions, destructive filesystem ops (recursive-delete calls aimed at the home directory or absolute roots).
- File-cap honesty: skills over 500 files now log a HIGH "scan truncated" finding instead of refusing to run; the count aborts early so huge trees can't freeze the scan.
- `--fix` safety: symlinked SKILL.md/LICENSE targets are refused (no writes through links outside the target folder); folder names are sanitized to spec (underscores/case -> lowercase-hyphens); BOM strip now actually matches the scan message and removes all U+FEFF.
- CI contract: `cardea.py` exits 0 = pass, 2 = DO-NOT-INSTALL (greppable JSON unchanged); action.yml checks the tool out to runner temp so a `.` audit never scans the tool itself; `uses:` path for subdir actions corrected in the guide; artifact-vs-committed-badge distinction documented (artifact URLs need auth and expire).
- Missing bandit/pip-audit on the host are now INFO like the other tools (was: MEDIUM penalty — contradicted the documented behavior and unfairly scored down clean skills on minimal hosts).
- Malformed YAML frontmatter now surfaces as a HIGH finding (was silently falling back to the simple parser).
- `--fix` re-scan no longer crashes on relative target paths (argv filtered by realpath).
- Dead-path findings now include SKILL.md line numbers; Windows-style backslash references are normalized.
- SVG badge escapes all interpolated attribute/text values.
- gitleaks temp report always cleaned up; file handles closed with context managers.
- Eval suite: 39/39 (33 scan cases + 6 behavioral tests covering --fix, --badge, symlink refusal, sanitize, BOM strip, CI grep contract — previously untested features).

## v0.2.0 (2026-09-16)
- SVG score badges: `--badge score.svg` — self-contained shields-style SVG (band colors; DO-NOT-INSTALL always red). Works on marketplaces that block external embeds.
- Auto-remediation: `--fix` — safe mechanical fixes only (chmod +x referenced scripts, SKILL.md name field, BOM strip, LICENSE.txt stub), then re-scans so the before/after delta is visible.
- GitHub CI: composite action (`action/action.yml`) + drop-in workflow guide (`references/ci-guide.md`). Red CI on DO-NOT-INSTALL; uploads JSON report + badge artifacts.
- Security hardening: 'doctor: allow' suppression markers honored only inside the Cardea package root (scanner-evasion attempt elsewhere = HIGH), 22 injection/unicode patterns including obfuscated payloads (fromhex/getattr) and all-interpreter downloader pipes, yamllint-class frontmatter validation via yaml.safe_load, backslash traversal.
- Scoring redesign: DO-NOT-INSTALL caps the score below 50; per-severity deduction caps (HIGH 36 / MEDIUM 18 / LOW 10) so noise cannot zero out a good skill; missing host tools are INFO, not a penalty.
- Orphan-script detection is import-aware and package-wide; gitleaks integrated for secret detection.

## v0.1.0 (2026-09-16)
- Initial release: official-spec structure validation, dead-path/no-exec detection, 16 injection/unicode patterns, semgrep/bandit/shellcheck/pip-audit orchestration, 0-100 score + DO-NOT-INSTALL gate, AST10 mapping, 15-case eval suite.
