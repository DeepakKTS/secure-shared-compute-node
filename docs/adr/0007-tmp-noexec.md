# ADR 0007: noexec on /tmp and /dev/shm

Status: accepted

Context: Dropping and running a payload in /tmp is the most common miner pattern after initial access.

Decision: Mount /tmp (via systemd tmp.mount) and /dev/shm with `noexec,nosuid,nodev`.

Consequences: Some builds (pip packages with C extensions, some installers) run code from /tmp and will fail. Document setting `TMPDIR=$HOME/tmp` for users. Test that apt upgrades still work after the change. Note that noexec does not stop `sh /tmp/x.sh` or `python /tmp/x.py`, because the interpreter is the executed binary; that is why Falco and auditd rules also watch these paths. State this in the README.
