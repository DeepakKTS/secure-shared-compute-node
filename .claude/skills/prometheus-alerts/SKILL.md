---
name: prometheus-alerts
description: How to write Prometheus scrape configs and alert rules, and route alerts through Alertmanager to the receiver. Use for roles/prometheus, roles/alertmanager, roles/process_exporter, and detection/prometheus/.
---

# Prometheus and alerting

## process-exporter config
- Group by process name and user so alerts can say who ran what, for example a name template combining `{{.Comm}}` and `{{.Username}}`. Check the template syntax in the installed version's README.
- Metric of interest: `namedprocess_namegroup_cpu_seconds_total` (confirm the exact name on the running exporter at `:9256/metrics`).

## Alert rules (detection/prometheus/rules/ssc.yml)
- `SSCUnknownProcessHighCPU`: per-group CPU rate over a short window, above `detection_cpu_threshold` cores, for `detection_cpu_for`, where the group name does not match `detection_process_allowlist_regex`. Labels: `severity`, `host`, `groupname`. Annotation explains the next step and links to the runbook section.
- `SSCHostCPUSaturated`: host-wide CPU busy above threshold for a sustained period.
- `SSCExporterDown`: `up == 0` for a target for more than a short period. This is the tamper signal.
- Render thresholds from group_vars via Jinja so DASH can tune them.
- Every rule file must pass `promtool check rules`. Add a `promtool test rules` unit test file with synthetic series for `SSCUnknownProcessHighCPU` (fires for an unknown name, does not fire for an allowlisted one).

## Alertmanager
- Single route to webhook receiver `alert_receiver` on localhost. `group_wait` short in lab. `send_resolved: true`.
- Optional email or Slack receiver behind a variable, off by default, no credentials in git.

## alert_receiver
- Python standard library HTTP server, runs as its own system user under systemd with hardening options.
- Appends one JSON line per alert: `received_at` (UTC, ms), `source` (prometheus or falco, from labels), `alertname` or Falco `rule`, `status`, labels, annotations.
- Listens on localhost only, unless falcosidekick needs another path; Alertmanager and receiver are on the same VM.

## Verify
- Prometheus targets page shows all `up`.
- `amtool` or the Alertmanager API can send a test alert that appears in `alerts.jsonl`.
