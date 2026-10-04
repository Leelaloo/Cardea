"""Safe auto-remediation for Cardea (--fix).

Applies ONLY mechanical, content-preserving fixes. Never rewrites prose,
never deletes lines, never touches files outside the target folder.
Fixable: missing exec bit on referenced scripts, SKILL.md name/folder
mismatch, UTF-8 BOM at file start, missing LICENSE stub.
"""

import os
import re
import stat

LICENSE_STUB = """LICENSE (placeholder)
Copyright (c) 2026 {author}
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, subject to the following conditions: the above
copyright notice and this permission notice shall be included in all copies.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
"""


def _safe_path(target, rel):
    """Resolve a fix target: refuse symlinks and anything resolving outside the target folder."""
    path = os.path.join(target, rel)
    if os.path.islink(path):
        return None
    real = os.path.realpath(path)
    base = os.path.realpath(target)
    if real == base or (real.startswith(base + os.sep) and base != os.sep):
        return real
    return None


def _sanitize_name(folder):
    """Folder name -> valid skill name: lowercase alphanumerics + single hyphens (spec)."""
    name = re.sub(r"[^a-z0-9-]+", "-", folder.lower()).strip("-")
    name = re.sub(r"-{2,}", "-", name)
    return name or "skill"


def _fix_exec_bit(target, findings, fixes, dry_run=False):
    for f in findings:
        if "not executable" in f["message"]:
            rel = f.get("file")
            if not rel:
                continue
            real = _safe_path(target, rel)
            if real and os.path.isfile(real):
                st = os.stat(real)
                if not dry_run:
                    os.chmod(real, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)  # nosemgrep
                fixes.append(f"chmod +x {rel}")


def _fix_name_field(target, findings, fixes, dry_run=False):
    for f in findings:
        if "does not match folder name" in f["message"]:
            folder = os.path.basename(os.path.realpath(target).rstrip("/"))
            name = _sanitize_name(folder)
            real = _safe_path(target, "SKILL.md")
            if not real or not os.path.isfile(real):
                return
            with open(real, "r", encoding="utf-8") as fh:
                text = fh.read()
            new, n = re.subn(r"(?m)^name:\s*.*$", f"name: {name}", text, count=1)
            if n:
                if not dry_run:
                    with open(real, "w", encoding="utf-8") as fh:
                        fh.write(new)
                fixes.append(f"SKILL.md: name field set to '{name}' (sanitized from folder '{folder}')")


def _fix_bom(target, findings, fixes, dry_run=False):
    for f in findings:
        if "BOM" in f["message"]:
            rel = f.get("file")
            real = _safe_path(target, rel) if rel else None
            if not real or not os.path.isfile(real):
                continue
            with open(real, "rb") as fh:
                raw = fh.read()
            n = raw.count(b"\xef\xbb\xbf")
            if n:
                if not dry_run:
                    with open(real, "wb") as fh:
                        fh.write(raw.replace(b"\xef\xbb\xbf", b""))
                fixes.append(f"stripped {n} U+FEFF BOM char(s) from {rel}")


def _fix_license(target, findings, fixes, dry_run=False):
    if any("no LICENSE" in f["message"] for f in findings):
        path = os.path.join(target, "LICENSE.txt")
        real = _safe_path(target, "LICENSE.txt")
        if real and not os.path.exists(path):
            if not dry_run:
                with open(real, "w", encoding="utf-8") as fh:
                    fh.write(LICENSE_STUB.format(author="the skill author"))
            fixes.append("created LICENSE.txt stub (edit author line before publishing)")


def apply_fixes(target, findings, dry_run=False):
    """Apply safe mechanical fixes. Returns list of human-readable fix messages."""
    fixes = []
    _fix_exec_bit(target, findings, fixes, dry_run=dry_run)
    _fix_name_field(target, findings, fixes, dry_run=dry_run)
    _fix_bom(target, findings, fixes, dry_run=dry_run)
    _fix_license(target, findings, fixes, dry_run=dry_run)
    return fixes
