# Evidence Rules

This project exists to be believed. These rules protect that.

1. Every number shown to a reader comes from a file in `results/`, produced by a script, on a named date, at a named git SHA.
2. `make report` is the only writer of the README results block. Do not edit between the markers by hand.
3. If a scenario fails, the report shows it as failed. Do not remove failed rows to make the table look better; fix the control and rerun.
4. Report the environment next to the numbers: VM sizes, host OS and architecture, component versions, scrape interval, alert `for:` durations, and VM clock offsets at run time. Detection time means nothing without them.
5. Round nothing silently. Show seconds with one decimal place and say so.
6. Screenshots are illustrations, not evidence. The JSON is the evidence.

## Result file schemas

`results/lynis-<label>.json`
```json
{"label": "before", "host": "ssc-node", "timestamp": "UTC ISO8601", "lynis_version": "", "hardening_index": 0, "warnings": 0, "suggestions": 0, "git_sha": ""}
```

`git_sha` is the controller's commit when the result was made. It ends in `-dirty` when files outside `results/` (tracked, or untracked and not gitignored) differed from the commit, because then the commit alone does not describe the code. Commit before `make baseline` or `make audit`, so the result names real code.

`results/scenarios/SX.json`
```json
{"id": "S3", "name": "", "run_id": "", "started_at": "", "expected": {}, "observed": {}, "passed": true,
 "detections": [{"source": "falco|prometheus|auditd|nftables|fail2ban", "rule": "", "received_at": "", "seconds_to_detect": 0.0}],
 "prevented": true, "git_sha": "", "env": {}}
```
