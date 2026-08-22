# Contributing

Contributions are welcome when they improve authorized, reproducible security
testing. Before opening a change:

1. Read the README and SECURITY.md.
2. Keep network tests local or clearly opt-in.
3. Add or update a focused test for behavior changes.
4. Document new probes, flags, output fields, and safety implications.
5. Run the local checks below.

```bash
python -m ruff check .
python -m pytest tests -q
python -m build
```

For new techniques, prefer a deterministic `renikApp` scenario and a test
that proves both the blocked baseline and the intended lab-only behavior. Do
not submit credentials, live findings, or unbounded scanning defaults.

## Pull requests

Explain the user-visible problem, the safety impact, test evidence, and any
compatibility or output-schema changes. Small focused pull requests are easier
to review and release.
