# ADR 0004: nftables directly, ufw disabled

Status: accepted

Context: Needs ingress restriction by source, exporter ports limited to one host, and egress filtering of mining ports with logging and counters.

Decision: Template `/etc/nftables.conf` with named sets; disable ufw to avoid two tools managing the same tables.

Consequences: More explicit, easy to diff and test with `nft list ruleset`. fail2ban uses the `nftables-multiport` banaction. The template must always keep SSH allowed from admin CIDRs; testinfra checks it.
