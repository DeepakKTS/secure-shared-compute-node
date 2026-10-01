---
name: evidence-report
description: How results are recorded and turned into README numbers. Use when touching results/, scripts/report.py, scripts/parse_lynis.py, or any doc that states a number.
---

# Evidence and reporting

Read docs/EVIDENCE.md first. Summary of what matters when writing code or docs:

- Numbers in docs come only from `results/` via `make report`. If you are about to type a number into a markdown file, stop.
- `report.py` replaces only the text between `<!-- SSC:RESULTS:START -->` and `<!-- SSC:RESULTS:END -->`. It must be deterministic: sorted keys, fixed formatting, no timestamps of the report run itself inside the block except the recorded run date.
- The results table columns: Scenario, What it simulates, Prevented, Detected by, Time to first detection (s), Passed.
- Add an environment line under the table: VM sizes, host OS and architecture, Ubuntu version, scrape interval, rule `for:` values, VM clock offsets, component versions from docs/VERSIONS.md.
- Failed scenarios stay in the table as failed.
- Unit test `report.py` with fixtures covering: all pass, one failed, one with no detection, missing Lynis after-file (shows "pending").
