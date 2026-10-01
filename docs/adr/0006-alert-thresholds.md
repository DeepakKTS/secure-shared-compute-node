# ADR 0006: Alert thresholds and durations

Status: proposed (tune in Phase 5 and 6)

Context: Short `for:` durations detect faster but flag legitimate bursts. Research workloads legitimately use full CPU for hours.

Decision: Use an allowlist of expected heavy process names plus a threshold on non-allowlisted groups. Lab defaults are short for feedback; document the production values recommended for DASH next to them.

Consequences: Detection time in the README must be read together with these settings. Report both. Keep `detection_cpu_threshold` below the per-user CPU cap (`resource_limits_cpu_quota`). If the cap is lower than the threshold, a capped user's miner can never fire `SSCUnknownProcessHighCPU`.
