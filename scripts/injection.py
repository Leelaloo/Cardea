"""Prompt-injection & hidden-unicode detection, informed by Snyk ToxicSkills + SkillJect.
Static only: reads raw bytes, never executes target code.

Supports suppression markers (like bandit's `# nosec`): a line containing
`doctor: allow` will not be reported — lets skill authors annotate intentional
patterns in e.g. security-related skills (like this one).
"""
import os
import re

SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "venv", "__artifacts"}

# --- hidden / suspicious unicode ---
UNICODE_FINDINGS = {
    "\u200b": "zero-width space (U+200B)",
    "\u200c": "zero-width non-joiner (U+200C)",
    "\u200d": "zero-width joiner (U+200D)",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE (U+202E) — classic obfuscation attack",
    "\u2066": "LTR isolate (U+2066)",
    "\u2067": "RTL isolate (U+2067)",
    "\u2068": "first-strong isolate (U+2068)",
    "\u2069": "pop directional isolate (U+2069)",
    "\ufeff": "BOM/zero-width no-break space (U+FEFF)",
    "\u2060": "word joiner (U+2060)",
    "\u2063": "invisible separator (U+2063)",
    "\u202a": "LTR embedding (U+202A)",
    "\u202b": "RTL embedding (U+202B)",
    "\u202c": "pop directional formatting (U+202C)",
    "\u202d": "LTR override (U+202D)",
}

# --- behavioral patterns — each line marked `doctor: allow` (this file IS a pattern library)
PATTERNS = [
    (re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)"), "CRITICAL", "instruction-override phrase — classic prompt injection"),  # doctor: allow
    (re.compile(r"(?i)disregard\s+(your|all|any)\s+(system|previous|prior)"), "CRITICAL", "instruction-override phrase — classic prompt injection"),  # doctor: allow
    (re.compile(r"(?i)\byou\s+are\s+now\s+(?:a|an|operating\s+as)?\s*(?:new|unrestricted|admin|dan|root|system)\b"), "HIGH", "persona hijack attempt in instructions"),  # doctor: allow
    (re.compile(r"(?i)secretly|without\s+(the\s+)?user('s)?\s+(knowledge|consent)|without\s+telling\s+the\s+user"), "HIGH", "concealment language — behavior hidden from the user"),  # doctor: allow
    (re.compile(r"(?i)(?:curl|wget)\b[^|\n]{0,120}\|\s*(?:(?:ba|z)?sh|python[23]?|perl|ruby|php|env)\b"), "CRITICAL", "download pipe to interpreter — remote code execution pattern"),  # doctor: allow
    (re.compile(r"(?i)(?:curl|wget)\b[^&\n]{0,120}&&\s*(?:ba|z)?sh(?:\s|$)"), "CRITICAL", "download-then-execute — staged remote code execution"),  # doctor: allow
    (re.compile(r"(?i)(eval|exec)\s*\(\s*(base64|atob|zlib|codecs\.decode)"), "CRITICAL", "encoded-payload execution (base64/etc. then eval/exec)"),  # doctor: allow
    (re.compile(r"(?i)base64\s+(-d|--decode)[^|\n]{0,80}\|"), "CRITICAL", "base64 decode piped into execution"),  # doctor: allow
    (re.compile(r"(?i)/\.ssh/|id_rsa|\.aws/credentials|\.docker/config\.json|\.kube/config|\.netrc|\.env\b.{0,40}(send|post|upload|curl|fetch)"), "CRITICAL", "credential/secret harvesting pattern"),  # doctor: allow
    (re.compile(r"(?i)(os\.environ|process\.env)[^;\n]{0,80}(curl|requests\.|fetch\(|urllib|http)"), "CRITICAL", "environment variables sent to network — exfiltration pattern"),  # doctor: allow
    (re.compile(r"(?i)(curl|wget|requests\.|fetch\()[^)\n]{0,120}(webhook|hooks\.slack|discord\.com/api|pastebin|ngrok)"), "HIGH", "data posted to webhook/paste service — possible exfiltration channel"),  # doctor: allow
    (re.compile(r"(?i)\brm\s+(?:-[a-z0-9\=\-_]+\s+)*(?:-[a-z]*[rf][a-z]*|--recursive|--force)\b(?:\s+(?:-[a-z0-9\=\-_]+\s+)*(?:-[a-z]*[rf][a-z]*|--recursive|--force)\b)?.*?\s+(?:/|~(?:/\*)?|\$HOME(?:/\*)?)(?:\s|$|\*)"), "CRITICAL", "destructive command targeting root/home"),  # doctor: allow
    (re.compile(r"(?i)chmod\s+777"), "LOW", "world-writable permissions — bad hygiene"),  # doctor: allow
    (re.compile(r"(?i)(skip|ignore|bypass)\s+(the\s+)?(security|deep)?[- ]?(scan|audit|check)"), "CRITICAL", "auditor-directed instruction — attempting to steer the scanner itself"),  # doctor: allow
    (re.compile(r"(?i)(auditor|reviewer)\s+note|pre-?verified|already\s+(verified|approved|scanned)"), "CRITICAL", "trust-claim impersonation — unverifiable 'already verified' claims"),  # doctor: allow
    (re.compile(r"(?i)verified\s+by\s+(snyk|owasp|anthropic|agensi)"), "HIGH", "false provenance claim — attributing vetting to a real org without proof"),  # doctor: allow
    (re.compile(r"(?i)(download|install|fetch)[^\n]{0,100}(releases/download|\.zip|\.exe|\.dmg|\.bin)[^\n]{0,120}(run|execut)"), "HIGH", "external binary download-and-run instruction — unvetted executable"),  # doctor: allow
    (re.compile(r"(?i)extract[^\n]{0,50}pass(word)?\s*[:=]\s*[`\"']?[a-z0-9]{3,}"), "CRITICAL", "password-protected archive with exposed password — classic trojan delivery"),  # doctor: allow
    (re.compile(r"(?i)(visit|see|open|check)[^\n]{0,60}(page|link|snippet|url)[^\n]{0,60}(execute|run)"), "CRITICAL", "instructs running commands fetched from an external page — unvetted code execution"),  # doctor: allow
    (re.compile(r"(?i)(glot\.io|pastebin\.com|controlc\.com|rentry\.co|justpaste\.it)[^\n]{0,80}(execute|run|curl|bash)"), "CRITICAL", "paste-site delivery of executable instructions — supply-chain social engineering"),  # doctor: allow
    (re.compile(r"(?is)(?:os\.environ|process\.env|\.aws[/\\]credentials|[/\\]\.ssh[/\\]|\.env\b).{0,200}?(?:requests\.(?:post|put)|fetch\(|urllib|httpx|webhook|curl|POST)"), "CRITICAL", "multi-line credential/environment exfiltration flow"),  # doctor: allow
    (re.compile(r"(?i)(?:bytes\.fromhex|codecs\.decode|getattr\s*\(\s*__import__)"), "CRITICAL", "obfuscated payload execution — decoding/reflection to evade static checks"),  # doctor: allow
    (re.compile(r"(?i)__import__\s*\(\s*['\"]builtins['\"]"), "CRITICAL", "dynamic builtins import — common precursor to obfuscated exec"),  # doctor: allow
    (re.compile(r"(?i)(?:exec|eval)\s*\(\s*__import__"), "CRITICAL", "dynamic-import execution — payload evades static imports"),  # doctor: allow
    (re.compile(r"(?i)(?:exec|eval)\s*\([^\n]{0,80}b64decode|b64decode\s*\([^\n]{0,80}\)\s*[^\n]{0,40}(?:exec|eval)"), "CRITICAL", "base64-decoded payload executed at runtime"),  # doctor: allow
    (re.compile(r"(?i)(?:forget|discard|override|bypass|cancel|nullify|reset|erase)\s+(?:all\s+|any\s+|everything\s+|your\s+|the\s+)?(?:previous|prior|above|earlier|past|initial|system|standing)\s+(?:instructions?|prompts?|rules?|context|messages?|directives|guidelines|constraints)"), "CRITICAL", "instruction-override phrase — classic prompt injection"),  # doctor: allow
    (re.compile(r"(?i)(?:exec|eval)\s*\(\s*(?:bytes|bytearray)\s*\("), "CRITICAL", "obfuscated code execution via byte-array constructor"),  # doctor: allow
    (re.compile(r"(?i)\w+\s*=\s*__import__\s*\("), "HIGH", "indirect dynamic import — obfuscation precursor"),  # doctor: allow
    (re.compile(r"(?i)shutil\.rmtree\s*\(\s*(?:os\.path\.)?(?:expanduser|environ|Path\.home\(\)|os\.getenv\(\s*['\"]HOME|['\"]~|['\"]/)"), "CRITICAL", "destructive filesystem operation targeting home/absolute path"),  # doctor: allow
    (re.compile(r"(?i)(?:os\.(?:remove|unlink|rmdir)|Path\(\s*['\"]?~)\s*[^\n]{0,40}expanduser"), "HIGH", "deletion driven by user-home expansion — destructive filesystem pattern"),  # doctor: allow
    (re.compile(r"(?i)shutil\.rmtree\s*\(\s*['\"][^\n]{0,4}(?:/|~)"), "CRITICAL", "destructive rmtree against absolute/home path"),  # doctor: allow
]

MAX_SCAN_BYTES = 2 * 1024 * 1024
TEXT_EXTS = {".md", ".py", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".js", ".mjs", ".cjs", ".ts", ".rb", ".php", ".txt", ".json", ".yaml", ".yml", ".toml"}
ALLOW_MARKER = "doctor: allow"
SELF_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))  # Cardea package root; markers trusted only inside it


def collect_text_files(target, cap=500, hard_collect_cap=5000):
    """Priority order: SKILL.md first, then scripts/, then everything else.
    A round-2 red-team showed the old alphabetical walk could be drowned by
    padding files, hiding scripts/ from the scan. Returns (files, truncated):
    `files` are the first `cap` candidates in priority order, `truncated` is
    True whenever candidates were left unscanned (fail-safe signal)."""
    cands = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in sorted(files):
            if len(cands) >= hard_collect_cap:
                break
            p = os.path.join(root, fn)
            ext = os.path.splitext(fn)[1].lower()
            if ext in TEXT_EXTS or fn == "SKILL.md":
                cands.append(p)
            elif ext == "" and os.access(p, os.X_OK):
                with open(p, "rb") as f:  # shebang check: extensionless scripts must be audited too
                    if f.read(2) == b"#!":
                        cands.append(p)
        if len(cands) >= hard_collect_cap:
            break
    rel = lambda p: os.path.relpath(p, target)
    cands.sort(key=lambda p: (0 if os.path.basename(p) == "SKILL.md"
                              else 1 if rel(p).startswith("scripts" + os.sep) else 2, rel(p)))
    return cands[:cap], len(cands) > cap


def check(target, log):
    scanned = 0
    paths, truncated = collect_text_files(target)
    if truncated:
        log("CRITICAL", "injection scan truncated at the 500-file limit — results are PARTIAL; "
            "reduce the skill size or split it (fail-safe: this alone means do-not-install)")
    for path in paths:
        rel = os.path.relpath(path, target)
        real = os.path.realpath(path)
        if not real.startswith(os.path.realpath(target) + os.sep):
            log("CRITICAL", f"file resolves outside the skill folder (symlink escape): {rel}", rel)
            continue
        if os.path.getsize(path) > MAX_SCAN_BYTES:
            log("MEDIUM", f"file over 2MB, skipped deep scan: {rel}", rel)
            continue
        with open(path, "rb") as f:
            raw = f.read()
        scanned += 1
        for ch, label in UNICODE_FINDINGS.items():
            enc = ch.encode("utf-8")
            if enc in raw:
                if ch == "\ufeff" and path.endswith("SKILL.md") and raw.startswith(enc):
                    continue  # SKILL.md UTF-8 BOM handled in structure checks
                log("CRITICAL", f"contains hidden/suspicious unicode: {label}", rel)
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:  # nosec B112 (unreadable file must not kill the audit)
            continue
        lines = text.splitlines()
        target_real = os.path.realpath(target)
        self_real = os.path.realpath(SELF_DIR)
        trusted_self = (target_real == self_real or target_real.startswith(self_real + os.sep))
        if not trusted_self and ALLOW_MARKER in text:
            log("HIGH", f"file contains suppression marker '{ALLOW_MARKER}' — possible scanner-evasion attempt (ignored)", rel)
        for rx, sev, msg in PATTERNS:
            for m in rx.finditer(text):
                lineno = text[: m.start()].count("\n")
                if trusted_self and lineno < len(lines) and ALLOW_MARKER in lines[lineno]:
                    continue  # self-scan suppression (our pattern library)
                log(sev, f"{msg} — matched: {m.group(0)[:80]!r}", rel, lineno + 1)
    log("INFO", f"injection scan: {scanned} text files inspected", None)
