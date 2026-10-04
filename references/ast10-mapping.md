# OWASP Agentic Skills Top 10 (AST10) → Cardea Coverage

| AST10 Category | Cardea Check |
|---|---|
| AST01 Malicious Skills | injection.py (instruction-override, persona hijack patterns) |
| AST02 Supply Chain | security.py (pip-audit on requirements.txt) |
| AST03 Prompt Injection | injection.py (override phrases, hidden unicode, concealment) |
| AST04 Excessive Agency | deadpaths.py (orphaned scripts), structure.py (description vs body) |
| AST05 Tool/Permission Misuse | injection.py + security.py (env-to-network, webhook exfil, world-writable perms, destructive commands) |
| AST06–AST10 (data, identity, ecosystem risks) | Partial: security.py static findings; full mapping planned in v2 |

Severity alignment: CRITICAL findings map to the AST01/03/05 categories that Snyk's ToxicSkills
research found in 36% of scanned skills (Feb 2026) — treat them as "do not install" signals.

Known limits (honest scope): static analysis cannot catch all semantic backdoors; a clean
Cardea report means "no known dangerous patterns found", not a cryptographic guarantee.
