"""Structure validation: SKILL.md frontmatter + layout per the official agentskills.io spec."""
import os
import re

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
DESC_MAX = 1024
NAME_MAX = 64
RECOMMENDED_LINES = 500
KNOWN_DIRS = {"scripts", "references", "assets", "evals"}
TRIGGER_HINTS = ("when", "use this", "for tasks", "whenever", "if the user")


def parse_frontmatter(text):
    """Return (fm_dict, body, yaml_error_or_None). Deterministic parser: verdicts derive
    from the stdlib fallback on EVERY host (environment-independent scores); PyYAML,
    when installed, is consulted only to detect malformed YAML — its values are
    never used, so a skill scores identically with or without PyYAML present."""
    if not text.startswith("---"):
        return {}, text, None
    try:
        end = text.index("\n---", 3)
    except ValueError:
        return {}, text, None
    block = text[3:end].strip("\n")
    body = text[end + 4:]
    yaml_error = None
    try:  # cross-check ONLY (never feeds the verdict): detect malformed YAML when PyYAML exists.
        import yaml
        parsed = yaml.safe_load(block)
        if not isinstance(parsed, dict):
            yaml_error = "parsed frontmatter is not a mapping"
    except ImportError:
        pass  # PyYAML absent: deterministic fallback below is authoritative on every host
    except Exception as e:  # malformed YAML: surface the error, still parse deterministically below
        yaml_error = f"{type(e).__name__}: {str(e)[:60]}"
    fm, key = {}, None
    for line in block.splitlines():
        if line[:1].isspace() and key:  # continuation of multi-line value
            fm[key] += "\n" + line.strip()
        elif ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            fm[key] = val.strip().strip('"').strip("'")
        # indented map values (e.g. metadata:) are folded into the last key
    return fm, body, yaml_error


def check_dir_symlinks(target, log):
    """Fail-safe: os.walk (followlinks=False) silently SKIPS directory symlinks, so a
    'scripts' dir pointing outside the skill root would hide its contents from every
    scanner. Any directory symlink resolving outside the skill root — existing or
    dangling target — is CRITICAL."""
    root_real = os.path.realpath(target)
    for root, dirs, files in os.walk(target):
        for item in dirs + files:
            p = os.path.join(root, item)
            if os.path.islink(p):
                rp = os.path.realpath(p)
                if rp != root_real and not rp.startswith(root_real + os.sep):
                    if os.path.isdir(rp) or not os.path.exists(rp):
                        log("CRITICAL", "directory resolves outside skill folder (symlink directory escape)",
                            os.path.relpath(p, target))


def check(target, log):
    """log(severity, message, file=None, line=None)"""
    check_dir_symlinks(target, log)
    skill_md = os.path.join(target, "SKILL.md")
    if not os.path.isfile(skill_md):
        log("CRITICAL", "SKILL.md missing — this is not a valid skill package", "SKILL.md")
        return
    with open(skill_md, "r", encoding="utf-8-sig", errors="replace") as f:  # strips a UTF-8 BOM (M10): a valid Windows-saved skill must not fail the gate
        text = f.read()
    fm, body, yaml_error = parse_frontmatter(text)
    if yaml_error:
        log("HIGH", f"SKILL.md frontmatter is not valid YAML ({yaml_error}) — parsed with a simple fallback; nested structures may be misread", "SKILL.md", 2)
    folder = os.path.basename(os.path.normpath(target))

    # name
    name = str(fm.get("name", ""))
    if not name:
        log("CRITICAL", "frontmatter 'name' field missing", "SKILL.md", 1)
    else:
        if len(name) > NAME_MAX:
            log("HIGH", f"name exceeds {NAME_MAX} chars ({len(name)})", "SKILL.md")
        if not NAME_RE.match(name):
            log("HIGH", f"name '{name}' violates spec (lowercase alphanumerics + single hyphens only)", "SKILL.md")
        if name != folder:
            if name.lower() == folder.lower():
                log("LOW", f"name '{name}' differs from folder name '{folder}' only by case — spec wants an exact match (fix with --apply)", "SKILL.md")
            else:
                log("HIGH", f"name '{name}' does not match folder name '{folder}' (required by spec)", "SKILL.md")

    # description
    desc = str(fm.get("description", ""))
    if not desc:
        log("CRITICAL", "frontmatter 'description' missing or empty — skill will never trigger", "SKILL.md")
    else:
        if len(desc) > DESC_MAX:
            log("HIGH", f"description exceeds {DESC_MAX} chars ({len(desc)})", "SKILL.md")
        if not any(h in desc.lower() for h in TRIGGER_HINTS):
            log("MEDIUM", "description states WHAT but not WHEN to activate — weak triggering", "SKILL.md")

    # body / layout
    nlines = len(text.splitlines())
    if nlines > RECOMMENDED_LINES:
        log("MEDIUM", f"SKILL.md has {nlines} lines (>{RECOMMENDED_LINES}) — context bloat; move detail to references/", "SKILL.md")
    # filename spoofing: SKILL.md look-alikes (homoglyphs/case) or non-ASCII names
    entries = sorted(os.listdir(target))
    lookalikes = [e for e in entries if e.lower().replace(" ", "") not in ("skill.md",)
                  and "skill" in e.lower() and e != "SKILL.md"]
    if lookalikes:
        log("HIGH", f"SKILL.md look-alike filenames present: {', '.join(lookalikes)} — possible filename spoofing", None)
    nonascii = [e for e in entries if any(ord(c) > 127 for c in e)]
    if nonascii:
        log("HIGH", f"non-ASCII filenames (homograph attack risk): {', '.join(nonascii)}", None)
    log("INFO", f"package contents: {', '.join(entries)}", None)
    unknown = [d for d in entries if os.path.isdir(os.path.join(target, d)) and d not in KNOWN_DIRS]
    if unknown:
        log("LOW", f"non-standard directories: {', '.join(unknown)} (fine, but unconventional)", None)
    if not any(e == "LICENSE" or e.startswith("LICENSE.") for e in entries):
        log("LOW", "no LICENSE file — marketplaces and buyers expect one", None)
