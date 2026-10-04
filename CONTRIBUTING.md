# Contributing to Cardea

Thank you for your interest in improving Cardea! We welcome contributions that align with our core principles of standard-library Python, zero external dependencies, fast static analysis, and rigorous security verification.

## Development & Test Instructions

Cardea is built with pure Python 3 standard library. No third-party packages (such as `pip` dependencies) are required.

### Local Execution & Testing

To test Cardea against a target skill folder:

```bash
# Basic scan
python3 scripts/cardea.py <path-to-skill-folder>

# Export JSON report
python3 scripts/cardea.py <path-to-skill-folder> --json report.json

# Generate SVG score badge
python3 scripts/cardea.py <path-to-skill-folder> --badge score.svg

# Preview dry-run mechanical fixes
python3 scripts/cardea.py <path-to-skill-folder> --fix

# Apply mechanical fixes and re-scan
python3 scripts/cardea.py <path-to-skill-folder> --fix --apply
```

### Self-Audit Verification

Before opening a pull request, run Cardea against itself to ensure no regressions or self-scan warnings:

```bash
python3 scripts/cardea.py .
```

## Safe Malicious Fixture Handling

When adding test fixtures for prompt injection, steganography, or security detection:
- **Never execute untrusted fixture code.**
- Store test targets exclusively as static text files in dedicated fixture directories (e.g., `phase3/fixtures/`).
- Do **not** include live API keys, tokens, real credentials, or active malware payloads.
- Use sanitized synthetic examples representing attack patterns.

## Contribution Terms & Licensing

All contributions submitted to Cardea are governed by the repository's existing license terms:
- **License:** [Cardea Source-Available License](LICENSE.txt).
- By submitting a pull request, you agree that your contributions will be licensed under these existing terms.
- No separate Contributor License Agreement (CLA) signature is required.
