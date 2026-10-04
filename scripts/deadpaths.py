"""Dead-path detection: broken references, missing executables — the #1 skill breakage mode."""
import os
import re
import stat

# scheme URLs (ftp://, git@host:path, mailto:) are external, not package files
URLISH_RE = re.compile(r'^[a-zA-Z+.-]+://|^git@|^[a-zA-Z]+:[\\w./-]+$')

# patterns like scripts/foo.py, references/bar.md, assets/x.png — incl. backticked mentions
PATH_RE = re.compile(r"(?:scripts|references|assets|evals)/[\w./-]+\.[A-Za-z0-9]{1,8}")
EXT_RE = re.compile(r"[\w-]+\.(py|sh|bash|js|ts|rb|md|txt|json|csv|png|jpg|svg|pdf)\b")


SKIP_DIRS = {'__pycache__', '.git', 'node_modules', '.venv', 'venv'}


def check(target, log):
    skill_md = os.path.join(target, "SKILL.md")
    if not os.path.isfile(skill_md):
        return
    with open(skill_md, "r", errors="replace") as f:
        text = f.read()

    referenced, ref_lines = set(), {}
    for m in PATH_RE.finditer(text):
        ref = m.group(0).replace("\\", "/")
        referenced.add(ref)
    for m in re.finditer(r"`([^`\n]{2,80})`", text):
        for cand in m.group(1).split():  # commands: tokenize so 'python3 scripts/x.py' checks scripts/x.py only
            if "<" in cand or ">" in cand or "$" in cand or cand.startswith("~"):
                continue  # <placeholder>/$VAR/~ tokens are doc templates or env paths, not package files
            cand = cand.replace("\\", "/")  # Windows-style refs normalize to POSIX for checking
            if URLISH_RE.match(cand):
                continue  # ftp://, git@host:..., scheme URLs — external, not package files
            if EXT_RE.fullmatch(cand) or ("/" in cand and not cand.startswith("http")):
                ref = cand.lstrip("./")
                referenced.add(ref)
                ref_lines.setdefault(ref, text[: m.start()].count("\n") + 1)

    # scripts invoked inside fenced code blocks must be executable; prose mentions need only exist
    code_blocks = re.findall(r"```[^\n]*\n(.*?)```", text, re.DOTALL)
    invoked = set()
    direct_invoked = set()  # executed as the command itself -> exec bit required
    for block in code_blocks:
        invoked |= set(PATH_RE.findall(block))
        for m in re.finditer(r"\b(\S+\.(?:py|sh|bash|js|ts|rb))\b", block):
            if "/" not in m.group(1):
                invoked.add("scripts/" + m.group(1))
        for line in block.splitlines():
            stripped = line.strip()
            # interpreter invocation (python3 scripts/x.py, sh scripts/x.sh): the
            # interpreter reads the file, so the exec bit is NOT required (v0.2.6 —
            # GitHub web uploads strip the bit and a python3-run script never needs it)
            m = re.match(r"^(?:sudo\s+)?(?:env\s+\S+\s+|python3?|node|ruby|php|perl|(?:ba|z)?sh)\s+(?:\./)?((?:scripts)/[\w./-]+\.[A-Za-z0-9]{1,8})", stripped)
            if m:
                continue
            # direct invocation (./scripts/x.sh or scripts/x.sh as the command)
            m = re.match(r"^(?:sudo\s+)?(?:\./)?((?:scripts)/[\w./-]+\.[A-Za-z0-9]{1,8})(?:\s|$)", stripped)
            if m:
                direct_invoked.add(m.group(1))

    if re.search(r"\.\.[/\\]", text):
        log("CRITICAL", "path traversal reference (../) in SKILL.md — may read outside the skill folder", "SKILL.md")

    missing, non_exec = [], []
    for ref in sorted(referenced):
        if ".." in ref.replace("\\", "/").split("/"):
            log("CRITICAL", f"path traversal attempt in reference: '{ref}' — refuses scan outside skill folder", "SKILL.md")
            continue
        path = os.path.join(target, ref)
        if not os.path.exists(path):
            missing.append(ref)
        elif ref.startswith(("scripts/",)) and ref in direct_invoked and os.path.isfile(path):
            mode = os.stat(path).st_mode
            if not (mode & stat.S_IXUSR or os.access(path, os.X_OK)):
                non_exec.append(ref)

    for ref in missing:
        first = ref.split("/")[0]
        pkg_dir = os.path.isdir(os.path.join(target, first)) or first in ("scripts", "references", "assets")
        ln = ref_lines.get(ref)
        if "/" not in ref or not pkg_dir:
            log("LOW", f"'{ref}' referenced but not shipped — runtime-generated or external workspace path", "SKILL.md", ln)
        else:
            log("HIGH", f"dead reference: '{ref}' mentioned in SKILL.md but file does not exist", "SKILL.md", ln)
    for ref in non_exec:
        log("HIGH", f"script '{ref}' is not executable (chmod +x) — will fail at runtime", ref)

    # scripts/ dir existing but never referenced anywhere in the package (SKILL.md, references, agent files, other scripts)
    sdir = os.path.join(target, "scripts")
    if os.path.isdir(sdir):
        pkg_text = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fn in files:
                if len(pkg_text) >= 500:  # fail-safe cap: a padded skill cannot stall the orphan scan
                    break
                if os.path.splitext(fn)[1].lower() in (".md", ".py", ".sh", ".txt", ".json"):
                    try:
                        with open(os.path.join(root, fn), "r", encoding="utf-8", errors="replace") as fh:
                            pkg_text.append(fh.read())
                    except OSError:
                        pass
        haystack = "\n".join(pkg_text)
        for f in sorted(os.listdir(sdir)):
            if f in SKIP_DIRS or f.endswith(".pyc") or f == "__init__.py":
                continue
            rel = f"scripts/{f}"
            module = os.path.splitext(f)[0]
            imported = re.search(rf"(?:^|\n)\s*(?:from|import)\s+{re.escape(module)}\b", haystack, re.M) is not None
            if rel not in referenced and f not in haystack and not imported:
                log("MEDIUM", f"script '{rel}' exists but is never referenced in SKILL.md — orphaned code", rel)
