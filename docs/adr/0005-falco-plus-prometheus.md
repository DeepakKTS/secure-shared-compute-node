# ADR 0005: Two detection paths, Falco and Prometheus

Status: accepted

Context: Miners show up both as events (exec from odd path, pool connection) and as behavior over time (sustained CPU).

Decision: Falco for event rules (seconds), Prometheus with process-exporter for behavior rules (minutes). Both feed Alertmanager, which feeds one receiver with one clock.

Alternatives: auditd alone (good record, weak alerting), osquery (strong, heavier), commercial EDR (not appropriate for a student lab).

Consequences: Two tools to maintain, but each covers the other's blind spot. auditd stays as the forensic record.
