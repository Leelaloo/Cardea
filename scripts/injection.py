"""Prompt-injection & hidden-unicode detection, informed by Snyk ToxicSkills + SkillJect.
Static only: reads raw bytes, never executes target code.

Supports suppression markers (like bandit's `# nosec`): a line containing
`doctor: allow` will not be reported — lets skill authors annotate intentional
patterns in e.g. security-related skills (like this one).

Scans a NORMALIZED copy of the text: NFKC folding (defeats fullwidth/math
lookalikes), zero-width/bidi char stripping (defeats invisible-character
splitting), and Cyrillic/Greek homograph folding (defeats lookalike-letter
obfuscation). Line numbers are preserved because normalization never creates
or destroys newlines.
"""
import os
import re
import unicodedata

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
    "\u200e": "left-to-right mark (U+200E)",
    "\u200f": "right-to-left mark (U+200F)",
}

# suspicious but not outright malicious: MEDIUM, not CRITICAL
SOFT_SUSPECTS = {
    "\u00ad": "soft hyphen (U+00AD) — a legitimate hyphenation char in prose, but also usable to split keywords",
}

# combining diacritics: zero-width modifiers used to split keywords (e.g. "ig\u0301nore")
COMBINING_RE = re.compile(r"[\u0300-\u036f\u2061]")

# Cyrillic/Greek letters that look identical to Latin ones — folded before matching
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d", "ѵ": "v", "ԛ": "q", "ԝ": "w",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "В": "B",
    "М": "M", "Т": "T", "Н": "H", "К": "K", "І": "I",
    "ο": "o", "ι": "i", "ν": "v", "ρ": "p", "α": "a", "ε": "e", "υ": "u",
})


def _normalize_for_scan(text):
    """Fold the text so lookalike/invisible-char obfuscation cannot evade patterns.
    Never creates or destroys newlines, so line numbers remain valid."""
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(HOMOGLYPHS)
    for ch in list(UNICODE_FINDINGS) + list(SOFT_SUSPECTS):  # strip invisibles (reported separately)
        text = text.replace(ch, "")
    text = COMBINING_RE.sub("", text)
    return text


# --- behavioral patterns — each line marked `doctor: allow` (this file IS a pattern library)
PATTERNS = [
    (re.compile(r"(?i)ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)"), "CRITICAL", "instruction-override phrase — classic prompt injection"),  # doctor: allow
    (re.compile(r"(?i)disregard\s+(your|all|any)\s+(system|previous|prior)"), "CRITICAL", "instruction-override phrase — classic prompt injection"),  # doctor: allow
    (re.compile(r"(?i)\byou\s+are\s+now\s+(?:a|an|operating\s+as)?\s*(?:new|unrestricted|admin|dan|root|system)\b"), "HIGH", "persona hijack attempt in instructions"),  # doctor: allow
    (re.compile(r"(?i)secretly|without\s+(the\s+)?user('s)?\s+(knowledge|consent)|without\s+telling\s+the\s+user"), "HIGH", "concealment language — behavior hidden from the user"),  # doctor: allow
    (re.compile(r"(?i)do\s+not\s+(inform|notify|alert|tell)\s+the\s+user|without\s+(alerting|notifying|informing)\s+the\s+user"), "HIGH", "concealment language — behavior hidden from the user"),  # doctor: allow
    (re.compile(r"(?i)(?:curl|wget)\b[^|\n]{0,120}\|\s*(?:(?:ba|z)?sh|python[23]?|perl|ruby|php|env)\b"), "CRITICAL", "download pipe to interpreter — remote code execution pattern"),  # doctor: allow
    (re.compile(r"(?i)(?:curl|wget)\b[^&\n]{0,120}&&\s*(?:ba|z)?sh(?:\s|$)"), "CRITICAL", "download-then-execute — staged remote code execution"),  # doctor: allow
    (re.compile(r"(?i)(eval|exec)\s*\(\s*(base64|atob|zlib|codecs\.decode)"), "CRITICAL", "encoded-payload execution (base64/etc. then eval/exec)"),  # doctor: allow
    (re.compile(r"(?i)base64\s+(-d|--decode)[^|\n]{0,80}\|"), "CRITICAL", "base64 decode piped into execution"),  # doctor: allow
    (re.compile(r"(?i)/\.ssh/|id_rsa|\.aws/credentials|\.docker/config\.json|\.kube/config|\.netrc|\.env\b.{0,40}(send|post|upload|curl|fetch)"), "CRITICAL", "credential/secret harvesting pattern"),  # doctor: allow
    (re.compile(r"(?i)(os\.environ|process\.env)[^;\n]{0,80}(curl|requests\.|fetch\(|urllib|http)"), "CRITICAL", "environment variables sent to network — exfiltration pattern"),  # doctor: allow
    (re.compile(r"(?i)(curl|wget|requests\.|fetch\()[^)\n]{0,120}(webhook|hooks\.slack|discord\.com/api|pastebin|ngrok)"), "HIGH", "data posted to webhook/paste service — possible exfiltration channel"),  # doctor: allow
    (re.compile(r"(?i)\brm\s+(?:-[a-z0-9\=\-_]+\s+)*(?:-[a-z]*[rf][a-z]*|--recursive|--force)\b(?:\s+(?:-[a-z0-9\=\-_]+\s+)*(?:-[a-z]*[rf][a-z]*|--recursive|--force)\b)?.*?\s+(?:/|~/|\$HOME(?:/\*)?|~(?:/\*)?)(?:\s|$|\*|/)?"), "CRITICAL", "destructive command targeting root/home"),  # doctor: allow
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
    # bounded \w{0,63}: the unbounded \w+ version backtracked quadratically on
    # long single-token lines (50KB file -> 28s, 2MB -> hours). Verified fixed.
    (re.compile(r"(?i)[A-Za-z_]\w{0,63}\s*=\s*__import__\s*\("), "HIGH", "indirect dynamic import — obfuscation precursor"),  # doctor: allow
    (re.compile(r"(?i)shutil\.rmtree\s*\(\s*(?:os\.path\.)?(?:expanduser|environ|Path\.home\(\)|os\.getenv\(\s*['\"]HOME|['\"]~|['\"]/)"), "CRITICAL", "destructive filesystem operation targeting home/absolute path"),  # doctor: allow
    (re.compile(r"(?i)(?:os\.(?:remove|unlink|rmdir)|Path\(\s*['\"]?~)\s*[^\n]{0,40}expanduser"), "HIGH", "deletion driven by user-home expansion — destructive filesystem pattern"),  # doctor: allow
    (re.compile(r"(?i)shutil\.rmtree\s*\(\s*['\"][^\n]{0,4}(?:/|~)"), "CRITICAL", "destructive rmtree against absolute/home path"),  # doctor: allow
    # --- multilingual instruction-override: FR/ES/DE/PT/IT paraphrases of the classic override phrase
    (re.compile(r"(?i)ignor(?:ez|er|a|ai|e|iere)\s+(?:(?:toutes?|todos?|todas?|toda|alle|die|las?|les?|gli|le|os|as|jede|qualsiasi|tutti|tutte|tous)\s+)*(?:(?:vorherigen|pr\u00e9c\u00e9dentes?|previas?|anteriores?|anteriori)\s+)*(?:instructions?|instrucciones|instruktionen|anweisungen|directives?|indicaciones|indicazioni|reglas|r\u00e8gles|regeln|avis|prompts?)\b"), "CRITICAL", "multilingual instruction-override phrase — classic prompt injection"),  # doctor: allow
    (re.compile(r"(?i)(desobedezc[ao]s?|désobéi\w*|désobéis\s+pas|desobedecer|desobedec[ae]s?|desobeir|n'obéis\s+pas|n'obeissez\s+pas|non\s+obbedire|desobbedisci)\s+(?:à\s+|a\s+|alle\s+|aux?\s+|gli\s+|las?\s+|les?\s+|toutes?\s+|todos?\s+|todas?\s+|tutti\s+|tutte\s+)*(?:les?\s+)?(?:règles|reglas|regeln|rules|instructions?|instrucciones|indicaciones|indicazioni|directives?|anweisungen|reglas?|regeln|regole|regole|règles?)"), "CRITICAL", "multilingual instruction-override phrase — classic prompt injection"),  # doctor: allow
    (re.compile(r"(?i)vergiss(?:t|en)?\s+(?:(?:alle|die|deine)\s+)*(?:(?:vorherigen|bisherigen|fr\u00fcheren)\s+)*(?:anweisungen|instruktionen|regeln|hinweise)\b"), "CRITICAL", "multilingual instruction-override phrase (German) — classic prompt injection"),  # doctor: allow
    # --- persona / mode-escalation paraphrases
    (re.compile(r"(?i)(developer|god|jailbreak|unrestricted|dan)\s+mode|you\s+are\s+no\s+longer\s+(bound|restricted|constrained|limited)"), "HIGH", "mode-escalation / persona hijack attempt"),  # doctor: allow
    (re.compile(r"(?i)disobey\s+(all\s+|your\s+|the\s+|any\s+)?(rules|instructions|guidelines|directives|constraints)"), "CRITICAL", "instruction-override phrase — classic prompt injection"),  # doctor: allow
    # --- obfuscation heuristics: high-entropy blobs and decode directives
    (re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"), "MEDIUM", "high-entropy base64 blob (>=120 chars) — possible encoded payload; verify what decodes it"),  # doctor: allow
    (re.compile(r"[0-9a-fA-F]{160,}"), "MEDIUM", "high-entropy hex blob (>=160 chars) — possible encoded payload; verify what decodes it"),  # doctor: allow
    (re.compile(r"(?i)(decode|deobfuscate|unmask|reveal)\s+(this|the)\s+(payload|blob|message|token|code)"), "MEDIUM", "decode directive — instructs the agent to unpack an obfuscated payload"),  # doctor: allow
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
            # fail-safe (was MEDIUM): an unscannable file must never read as a clean scan —
            # an attacker can park any payload in a >2MB file. Verified bypass, now closed.
            log("CRITICAL", f"file over 2MB, deep scan skipped — results PARTIAL; verify this file manually "
                f"(fail-safe: oversized/unscannable content cannot read as a clean verdict)", rel)
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
        for ch, label in SOFT_SUSPECTS.items():
            if ch.encode("utf-8") in raw:
                log("MEDIUM", f"contains possibly-suspicious unicode: {label}", rel)
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:  # nosec B112 (unreadable file must not kill the audit)
            continue
        norm = _normalize_for_scan(text)
        norm_lines = norm.splitlines()
        changed_lines = set()
        for i, ln in enumerate(text.splitlines()):
            if _normalize_for_scan(ln) != ln:
                changed_lines.add(i)
        target_real = os.path.realpath(target)
        self_real = os.path.realpath(SELF_DIR)
        trusted_self = (target_real == self_real or target_real.startswith(self_real + os.sep))
        if not trusted_self and ALLOW_MARKER in text:
            log("HIGH", f"file contains suppression marker '{ALLOW_MARKER}' — possible scanner-evasion attempt (ignored)", rel)
        for rx, sev, msg in PATTERNS:
            for m in rx.finditer(norm):
                lineno = norm.count("\n", 0, m.start())
                if trusted_self and lineno < len(norm_lines) and ALLOW_MARKER in norm_lines[lineno]:
                    continue  # self-scan suppression (our pattern library)
                extra = " [normalized: source line contained lookalike/invisible chars]" if lineno in changed_lines else ""
                log(sev, f"{msg} — matched: {m.group(0)[:80]!r}{extra}", rel, lineno + 1)
    if scanned:
        log("INFO", f"injection scan: {scanned} text file(s) inspected", None)
