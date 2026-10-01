# ADR 0008: systemd user slice limits for isolation

Status: accepted

Context: One user or one compromised account should not be able to take the whole machine.

Decision: A drop-in in `/etc/systemd/system/user-.slice.d/` sets CPUQuota, MemoryMax, TasksMax for every user slice. Values in group_vars.

Alternatives: ulimits via limits.conf (no CPU share control), a scheduler like SLURM (right for DASH long term, too large for this project, listed in DASH_MAPPING).

Consequences: Processes started outside the user's login session (for example system services) are not covered. Containers need their own limits. Caps also limit legitimate heavy jobs, so values must be agreed with the DASH owner.
