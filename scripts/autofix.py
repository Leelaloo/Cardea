"""Safe auto-remediation for Cardea (--fix).

Applies ONLY mechanical, content-preserving fixes. Never rewrites prose,
never deletes lines, never touches files outside the target folder.
Fixable: missing exec bit on referenced scripts, SKILL.md name/folder
mismatch, missing `name` field, UTF-8 BOM at file start, missing LICENSE stub.

All writes are atomic (temp file + os.replace in the same directory) and
OSError-guarded: a write-protected file or full disk reports a fix failure
instead of crashing the CLI — and an interrupted write can never leave a
truncated SKILL.md behind (M9). Original line endings (CRLF) are preserved
(M14).
"""

import os
import re
import stat
import tempfile

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


def _write_atomic(real, data):
    """Atomic write: a crash or permission error can never leave a truncated file."""
    d = os.path.dirname(real) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".cardea-fix-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, real)
    except OSError:
        with open(os.devnull, "wb") as _null:  # cleanup best-effort, never raise
            pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _sanitize_name(folder):
    """Folder name -> valid skill name: lowercase alphanumerics + single hyphens (spec)."""
    name = re.sub(r"[^a-z0-9-]+", "-", folder.lower()).strip("-")
    name = re.sub(r"-{2,}", "-", name)
    return name or "skill"


def _line_ending(sample):
    return "\r\n" if "\r\n" in sample else "\n"


def _fix_exec_bit(target, findings, fixes, dry_run=False):
    for f in findings:
        if "not executable" in f["message"]:
            rel = f.get("file")
            if not rel:
                continue
            real = _safe_path(target, rel)
            if real and os.path.isfile(real):
                try:
                    st = os.stat(real)
                    if not dry_run:
                        os.chmod(real, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)  # nosemgrep
                    fixes.append(f"chmod +x {rel}")
                except OSError as e:
                    fixes.append(f"fix failed (chmod {rel}): {e}")


def _fix_name_field(target, findings, fixes, dry_run=False):
    """Two cases (M12): name mismatch with the folder (rewrite the value) and a
    completely missing `name` field (insert one below the opening `---`)."""
    folder = os.path.basename(os.path.realpath(target).rstrip("/"))
    name = _sanitize_name(folder)
    real = _safe_path(target, "SKILL.md")
    if not real or not os.path.isfile(real):
        return
    missing = any("name' field missing" in f["message"] for f in findings)
    mismatch = any("does not match folder name" in f["message"] for f in findings)
    if not (missing or mismatch):
        return
    try:
        with open(real, "r", encoding="utf-8", newline="") as fh:  # newline="": keep CRLF intact (M14)
            text = fh.read()
    except OSError as e:
        fixes.append(f"fix failed (read SKILL.md): {e}")
        return
    eol = _line_ending(text)
    lines = text.splitlines(keepends=True)
    changed = False
    for i, l in enumerate(lines):
        if re.match(r"(?i)^name:[^\r\n]*", l):
            keep = "\r\n" if l.endswith("\r\n") else ("\n" if l.endswith("\n") else "")
            lines[i] = f"name: {name}" + keep
            changed = True
            break
    if not changed and missing:
        # no name line at all: insert right after the opening `---`
        for i, l in enumerate(lines):
            if l.strip() == "---":
                lines.insert(i + 1, f"name: {name}" + eol)
                changed = True
                break
    if changed:
        new = "".join(lines)
        if new != text:
            if not dry_run:
                try:
                    _write_atomic(real, new.encode("utf-8"))
                except OSError as e:
                    fixes.append(f"fix failed (write SKILL.md): {e}")
                    return
            fixes.append(f"SKILL.md: name field set to '{name}' (sanitized from folder '{folder}')")


def _fix_bom(target, findings, fixes, dry_run=False):
    for f in findings:
        if "BOM" in f["message"]:
            rel = f.get("file")
            real = _safe_path(target, rel) if rel else None
            if not real or not os.path.isfile(real):
                continue
            try:
                with open(real, "rb") as fh:
                    raw = fh.read()
                n = raw.count(b"\xef\xbb\xbf")
                if n:
                    if not dry_run:
                        _write_atomic(real, raw.replace(b"\xef\xbb\xbf", b""))
                    fixes.append(f"stripped {n} U+FEFF BOM char(s) from {rel}")
            except OSError as e:
                fixes.append(f"fix failed (strip BOM {rel}): {e}")


def _fix_license(target, findings, fixes, dry_run=False):
    if any("no LICENSE" in f["message"] for f in findings):
        # M13: any LICENSE* file (LICENSE.md, LICENSE, LICENSE.txt) satisfies the check
        try:
            entries = os.listdir(target)
        except OSError as e:
            fixes.append(f"fix failed (list target): {e}")
            return
        if any(e == "LICENSE" or e.startswith("LICENSE.") for e in entries):
            return
        real = _safe_path(target, "LICENSE.txt")
        if real and not os.path.exists(real):
            if not dry_run:
                try:
                    _write_atomic(real, LICENSE_STUB.format(author="the skill author").encode("utf-8"))
                except OSError as e:
                    fixes.append(f"fix failed (create LICENSE.txt): {e}")
                    return
            fixes.append("created LICENSE.txt stub (edit author line before publishing)")


def apply_fixes(target, findings, dry_run=False):
    """Apply safe mechanical fixes. Returns list of human-readable fix messages."""
    fixes = []
    _fix_exec_bit(target, findings, fixes, dry_run=dry_run)
    _fix_name_field(target, findings, fixes, dry_run=dry_run)
    _fix_bom(target, findings, fixes, dry_run=dry_run)
    _fix_license(target, findings, fixes, dry_run=dry_run)
    return fixes
