# Scoring Rubric

Start at 100. Deduct per finding: CRITICAL −25, HIGH −12, MEDIUM −6, LOW −2. Floor 0.

Bands: 90+ EXCELLENT · 75-89 GOOD · 50-74 NEEDS WORK · <50 BROKEN/RISKY.

Any CRITICAL finding also sets `do_not_install: true` regardless of score, because CRITICAL
means: prompt injection, remote code execution patterns, credential harvesting, exfiltration,
destructive commands, or a missing/invalid SKILL.md core — defects no install should proceed past.

Why severity-weighted (not category-averaged)? One injection pattern is disqualifying even in an
otherwise beautiful skill; quality issues compound but individually are survivable.

Suppression: NOT available to scanned skills. `doctor: allow` markers are honored only inside a
byte-identical copy of Cardea's own pattern library (verified by content hash); any marker found in a
scanned skill file is itself reported as a HIGH scanner-evasion finding and suppresses nothing.

## Deduction caps (v0.2.0+)

Severity deductions are capped per severity so noise cannot zero out a good skill:

- CRITICAL: uncapped — any critical finding caps the total score at **49** (a do-not-install package can never read as GOOD)
- HIGH: max −36
- MEDIUM: max −18
- LOW: max −10
- INFO: no deduction (informational only)

Example: 4 HIGHs (−12 each) deduct 36, not 48. Two CRITICALs still mean score ≤ 49 and `do_not_install: true`.
