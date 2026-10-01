# Secure Shared Compute Node: single entry point for everything.
#
# Written for GNU make 3.81 (the macOS default): no .ONESHELL, .RECIPEPREFIX,
# $(file ...), or grouped targets. All tools run from .venv/, never from PATH,
# so local runs and CI use the same pinned versions.

.DEFAULT_GOAL := help
.SUFFIXES:

VENV := .venv
BIN := $(VENV)/bin
PY := $(BIN)/python

ANSIBLE := $(BIN)/ansible
ANSIBLE_PLAYBOOK := $(BIN)/ansible-playbook
ANSIBLE_GALAXY := $(BIN)/ansible-galaxy
ANSIBLE_LINT := $(BIN)/ansible-lint
YAMLLINT := $(BIN)/yamllint
SHELLCHECK := $(BIN)/shellcheck
RUFF := $(BIN)/ruff
PYTEST := $(BIN)/pytest

COLLECTIONS_DIR := .ansible/collections

# Put .venv/bin first, so tools that call each other (ansible-lint runs
# ansible-playbook) also use the pinned copies.
export PATH := $(CURDIR)/$(BIN):$(PATH)

# full: node, monitor, attacker. small: monitor collapsed onto node, which is
# weaker because a rooted node can then silence its own monitoring.
LAB_PROFILE ?= full
export LAB_PROFILE

PLAYBOOKS := $(wildcard playbooks/*.yml)
SH_FILES := $(shell find scripts simulate -type f -name '*.sh' 2>/dev/null)

# Stub for targets whose phase is not built yet. It fails on purpose, so
# `make all` cannot report success before the work exists.
todo = echo "make $@: not implemented yet (Phase $(1), see TODO.md)" >&2; exit 2

.PHONY: help deps check-venv lab-up lab-down lab-status ping lint test audit-log demo
.PHONY: baseline harden idempotency monitoring detection verify audit simulate report all

help: ## List targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-z][a-z-]*:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---- Phase 0: tooling and lab ------------------------------------------------

deps: ## Install pinned Python and Ansible deps into .venv/ with uv
	@command -v uv >/dev/null 2>&1 || { echo "uv not found. Install it: https://docs.astral.sh/uv/getting-started/installation/" >&2; exit 1; }
	uv sync --locked
	$(ANSIBLE_GALAXY) collection install -r requirements.yml -p $(COLLECTIONS_DIR)
	@echo "Installed versions:"
	@$(PY) --version
	@$(ANSIBLE) --version | head -1
	@NO_COLOR=1 $(ANSIBLE_LINT) --version | head -1
	@$(YAMLLINT) --version
	@$(RUFF) --version
	@$(PYTEST) --version
	@$(SHELLCHECK) --version | sed -n 2p
	@$(ANSIBLE_GALAXY) collection list -p $(COLLECTIONS_DIR) 2>/dev/null | grep -E '^(ansible|community)\.'

check-venv:
	@test -x $(ANSIBLE) || { echo "No .venv/ found. Run 'make deps' first." >&2; exit 1; }

lab-up: check-venv ## Create the lab VMs, write inventory/lab.yml, run the lab check
	scripts/lab.sh up
	$(PY) scripts/gen_inventory.py
	$(ANSIBLE_PLAYBOOK) playbooks/lab_check.yml
	scripts/lab.sh check

lab-down: ## Delete the lab VMs only (type yes on the terminal; no flag skips the prompt)
	scripts/lab.sh down

lab-status: ## Show lab VMs and inventory state
	scripts/lab.sh status

ping: check-venv ## Ansible ping to every lab host
	$(ANSIBLE) all -m ansible.builtin.ping

lint: check-venv ## yamllint, ansible-lint, syntax-check, shellcheck, ruff
	$(YAMLLINT) --strict .
	$(ANSIBLE_LINT)
	@for pb in $(PLAYBOOKS); do \
	    echo "$(ANSIBLE_PLAYBOOK) --syntax-check $$pb"; \
	    $(ANSIBLE_PLAYBOOK) --syntax-check -i localhost, $$pb || exit 1; \
	done
	@if [ -n "$(SH_FILES)" ]; then \
	    echo "$(SHELLCHECK) $(SH_FILES)"; \
	    $(SHELLCHECK) $(SH_FILES); \
	else \
	    echo "shellcheck: no shell scripts yet"; \
	fi
	$(RUFF) check .
	$(RUFF) format --check .

test: check-venv ## Unit tests that need no VMs
	$(PYTEST) -m "not lab"

# The hooks in .claude/hooks/ write .lab/audit/bash.log. DATE=YYYY-MM-DD picks
# another UTC day; ALL=1 also lists the commands that ran.
audit-log: check-venv ## Show today's Bash commands the guard hook blocked
	$(PY) scripts/show_bash_log.py $(if $(DATE),--date $(DATE),) $(if $(ALL),--all,)

# Read-only: -B writes no __pycache__, and tests/test_demo.py checks that a
# run leaves the repo and the VMs as they were.
demo: check-venv ## Read-only summary of the live lab (changes nothing)
	$(PY) -B scripts/demo.py

# ---- Phase 1: baseline audit -------------------------------------------------

# Remove the old local report first, so a failed run can never leave a stale
# report for the parser.
baseline: check-venv ## Lynis on the fresh node -> results/lynis-before.json
	rm -f .lab/lynis/before/ssc-node-lynis-report.dat
	$(ANSIBLE_PLAYBOOK) playbooks/audit.yml -e audit_label=before
	$(PY) scripts/parse_lynis.py .lab/lynis/before/ssc-node-lynis-report.dat --label before

# ---- Phase 2: hardening ------------------------------------------------------

# TAGS=<role> runs one role, for example `make harden TAGS=base`.
harden: check-venv ## Hardening and isolation roles
	$(ANSIBLE_PLAYBOOK) playbooks/harden.yml $(if $(TAGS),--tags $(TAGS),)

# HOSTS=<group> limits it, for example `make reboot HOSTS=node`. Then rerun
# the testinfra tests: this is how boot-time overrides are caught.
reboot: check-venv ## Reboot lab VMs and wait for boot to finish (checks boot-time state)
	$(ANSIBLE_PLAYBOOK) playbooks/reboot.yml $(if $(HOSTS),-e reboot_hosts=$(HOSTS),)

# ---- Later phases (stubs until built) ----------------------------------------

idempotency: ## Run harden twice; fail if the second run changes anything
	@$(call todo,2)

verify: ## testinfra against node and monitor -> results/
	@$(call todo,2)

monitoring: ## Monitor stack and exporters
	@$(call todo,4)

detection: ## Falco, alert rules, egress rules
	@$(call todo,5)

simulate: ## Run scenarios -> results/scenarios/*.json
	@$(call todo,6)

audit: ## Lynis after hardening -> results/lynis-after.json
	@$(call todo,7)

report: ## Render evidence tables into README.md
	@$(call todo,7)

all: ## lab-up through report, in order
	$(MAKE) lab-up
	$(MAKE) baseline
	$(MAKE) harden
	$(MAKE) idempotency
	$(MAKE) monitoring
	$(MAKE) detection
	$(MAKE) verify
	$(MAKE) audit
	$(MAKE) simulate
	$(MAKE) report
