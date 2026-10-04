#!/usr/bin/env python3
"""Cardea — audits a Claude Code skill folder: structure, dead paths, injection, security.
Usage: python3 cardea.py <target-skill-folder> [--json out.json]
Static analysis only — never executes target code.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import structure      # noqa: E402  (static imports on purpose: auditable, no dynamic loading)
import deadpaths      # noqa: E402
import injection      # noqa: E402
import security       # noqa: E402

CHECKS = [structure, deadpaths, injection, security]

SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 6, "LOW": 2, "INFO": 0}
BANDS = [(90, "EXCELLENT"), (75, "GOOD"), (50, "NEEDS WORK"), (0, "BROKEN / RISKY")]
MAX_FILES = 500


def band(score):
    for floor, label in BANDS:
        if score >= floor:
            return label
    return "BROKEN / RISKY"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="path to the skill folder to audit")
    ap.add_argument("--json", dest="json_out", metavar="FILE", help="also write JSON report to FILE")
    ap.add_argument("--badge", dest="badge_out", metavar="FILE", help="also write an SVG score badge to FILE")
    ap.add_argument("--fix", action="store_true", help="preview safe mechanical fixes (dry-run mode)")
    ap.add_argument("--apply", "--fix-apply", dest="apply", action="store_true", help="apply safe mechanical fixes to disk, then re-scan")
    args = ap.parse_args()

    target = os.path.realpath(args.target)
    if not os.path.isdir(target):
        sys.exit(f"error: target folder not found: {args.target}")
    json_failed = False  # L11: report-write failure must not erase the DO-NOT-INSTALL signal

    n = 0  # zip-bomb-ish cap, counted iteratively so a huge tree can't freeze the tool
    for _r, _d, files in os.walk(target):
        n += len(files)
        if n > MAX_FILES:
            break

    findings = []

    def log(severity, message, file=None, line=None):
        findings.append({"severity": severity, "message": message, "file": file, "line": line})

    # v0.2.5 — collection detection: a multi-skill repo ROOT is not a valid scan target.
    # Scanning a collection root used to drown the user in misleading repo-wide
    # findings (docs/ and CI files tripping patterns) with a confusing 0/100.
    # Instead: detect it, say it plainly, list the real skill folders, and skip the
    # per-module scans. Still DNI — it is not a single installable skill.
    collection = False
    if not os.path.isfile(os.path.join(target, "SKILL.md")):
        found = []
        for _r, _d, files in os.walk(target):
            if "SKILL.md" in files:
                found.append(os.path.relpath(os.path.join(_r, "SKILL.md"), target))
                if len(found) > 50:
                    break
        if len(found) >= 2:
            collection = True
            total = len(found)
            shown = ", ".join(found[:10]) + (f" (+{total - 10} more)" if total > 10 else "")
            log("CRITICAL",
                f"this folder is a skill COLLECTION ({total} skill folders found), not a single skill — "
                f"scan each skill folder individually (found: {shown})", "SKILL.md")

    if not collection:
        if n > MAX_FILES:
            findings.append({"severity": "HIGH", "message": f"oversized skill: more than {MAX_FILES} files — scan truncated, results are PARTIAL and deep files may be unscanned (also a common scanner-evasion tactic)", "file": None, "line": None})

        for mod in CHECKS:
            try:
                mod.check(target, log)
            except Exception as e:  # a broken check must not kill the audit
                findings.append({"severity": "MEDIUM",
                                 "message": f"check '{mod.__name__}' crashed: {e}",
                                 "file": None, "line": None})

    deduction = 0
    for sev, cap in (("CRITICAL", None), ("HIGH", 36), ("MEDIUM", 18), ("LOW", 10)):
        n = sum(1 for f in findings if f["severity"] == sev)
        w = SEVERITY_WEIGHT.get(sev, 0)
        deduction += n * w if cap is None else min(n * w, cap)
    score = max(0, 100 - deduction)
    criticals = [f for f in findings if f["severity"] == "CRITICAL"]
    if criticals:
        score = min(score, 49)  # a do-not-install package can never read as "GOOD"

    report = {
        "target": os.path.basename(target.rstrip("/")),
        "score": score,
        "band": band(score),
        "do_not_install": bool(criticals),
        "counts": {s: sum(1 for f in findings if f["severity"] == s)
                   for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "findings": findings,
        "partial": bool(n > MAX_FILES),
    }

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    print(f"\n=== CARDEA REPORT: {report['target']} ===")
    print(f"Score: {score}/100  [{report['band']}]")
    if report["do_not_install"]:
        print(">>> DO NOT INSTALL — critical security finding(s) below <<<")
    print(f"Findings: {report['counts']}\n")
    for f in sorted(findings, key=lambda f: order.index(f["severity"]) if f["severity"] in order else len(order)):
        loc = f" ({f['file']}" + (f":{f['line']}" if f.get("line") else "") + ")" if f.get("file") else ""
        print(f"  [{f['severity']:<8}] {f['message']}{loc}")

    if args.json_out:
        try:
            with open(args.json_out, "w") as fh:
                json.dump(report, fh, indent=2)
        except OSError as e:
            print(f"\nerror: could not write JSON report to {args.json_out}: {e}")
            json_failed = True
        print(f"\nJSON report written to {args.json_out}")

    if args.badge_out:
        import badge
        try:
            badge.write_badge(report, args.badge_out)
            print(f"\nSVG badge written to {args.badge_out}")
        except OSError as e:
            print(f"\nerror: could not write badge to {args.badge_out}: {e}")

    if args.fix or args.apply:
        import autofix
        if args.apply:
            fixes = autofix.apply_fixes(target, findings, dry_run=False)
            if fixes:
                print(f"\n--fix: applied {len(fixes)} safe fix(es):")
                for fx in fixes:
                    print(f"  [fixed] {fx}")
                print("\n--fix: re-scanning after fixes...")
                sys.stdout.flush()  # don't lose the before-report when execv replaces this process
                keep = [a for a in sys.argv[1:] if a not in ("--fix", "--apply", "--fix-apply") and os.path.realpath(a) != target]
                os.execv(sys.executable, [sys.executable, os.path.abspath(__file__), target, *keep])  # nosec B606 (deliberate: exec of trusted interpreter, no shell)
            else:
                print("\n--fix: no safe mechanical fixes available (content issues need manual edits)")
        else:
            fixes = autofix.apply_fixes(target, findings, dry_run=True)
            if fixes:
                print(f"\n--fix (dry-run): {len(fixes)} safe fix(es) available (pass --apply or --fix-apply to execute):")
                for fx in fixes:
                    print(f"  [would fix] {fx}")
            else:
                print("\n--fix (dry-run): no safe mechanical fixes available")

    # CI contract: 0 = pass, 2 = do-not-install, 1 = tool/config error.
    # DNI keeps priority over a failed report write (L11): an automation reading
    # exit codes still sees the security signal.
    sys.exit(2 if report["do_not_install"] else (1 if json_failed else 0))


if __name__ == "__main__":
    main()
