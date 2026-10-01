---
name: prometheus-alerts
description: How to write Prometheus scrape configs and alert rules, and route alerts through Alertmanager to the receiver. Use for roles/prometheus, roles/alertmanager, roles/process_exporter, and detection/prometheus/.
---

# Prometheus and alerting

## process-exporter config
- Group by process name and user so alerts can say who ran what. Use the group name format `<comm>:<user>` (a template like `{{.Comm}}:{{.Username}}`). Check the template syntax in the installed version's README. In group_vars, mark the template `!unsafe` so Ansible does not try to render it.
- Linux cuts `comm` to 15 characters. `process-exporter` shows up as `process-exporte`. Allowlist entries must use the cut form.
- Metric of interest: `namedprocess_namegroup_cpu_seconds_total` (confirm the exact name on the running exporter at `:9256/metrics`).

## Alert rules (detection/prometheus/rules/ssc.yml)
- `SSCUnknownProcessHighCPU`: per-group CPU rate over a short window, above `detection_cpu_threshold` cores, for `detection_cpu_for`, where the group name does not match `detection_process_allowlist_regex`. The regex matches the `<comm>:` prefix of the group name (for example `^(python3|...):`), not the bare name. Labels: `severity`, `host`, `groupname`. Annotation explains the next step and links to the runbook section.
- `SSCHostCPUSaturated`: host-wide CPU busy above threshold for a sustained period.
- `SSCExporterDown`: `up == 0` for a target for more than a short period. This is the tamper signal.
- Render thresholds from group_vars via Jinja so DASH can tune them.
- Every rule file must pass `promtool check rules`. Add a `promtool test rules` unit test file with synthetic series for `SSCUnknownProcessHighCPU`: fires for an unknown name (`kworker/0:1:alice`), does not fire for an allowlisted one (`python3:alice`).

## Alertmanager
- Single route to webhook receiver `alert_receiver` on localhost. `group_wait` short in lab. `send_resolved: true`.
- Alertmanager merges alerts with the same labels and only re-sends a group after `group_interval` (or `repeat_interval` if nothing changed). In the lab use `group_by: ['...']` (each distinct label set is its own group) and a short `group_interval`, or back-to-back scenarios can lose or delay alerts.
- Listen on localhost only. A rooted node must not be able to reach the Alertmanager API and add a silence.
- Optional email or Slack receiver behind a variable, off by default, no credentials in git.

## alert_receiver
- Python standard library HTTP server, runs as its own system user under systemd with hardening options.
- Appends one JSON line per alert: `received_at` (UTC, ms), `source` (prometheus or falco, from labels), `alertname` or Falco `rule`, `status`, labels, annotations.
- Listens on localhost only. Alertmanager, falcosidekick, and the receiver are all on the monitor.
- falcosidekick posts each Falco event to the receiver directly as well as to Alertmanager, so a repeat event is not merged away.

## Verify
- Prometheus targets page shows all `up`.
- `amtool` or the Alertmanager API can send a test alert that appears in `alerts.jsonl`.
