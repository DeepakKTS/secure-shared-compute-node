# Kickoff: starting the build with Claude Code

## 1. Install on your laptop
- Multipass: https://multipass.run (check the install page for your OS)
- Python 3.11+ and pipx or uv
- make, git, and the GitHub CLI (`gh`) if you want to create the repo from the terminal
- Claude Code CLI

Check free RAM. Three VMs need about 5 GB. If you have less, use `LAB_PROFILE=small`.

## 2. Create the repo
```
unzip secure-shared-compute-node.zip
cd secure-shared-compute-node
git init && git add . && git commit -m "chore: project plan and Claude Code setup"
gh repo create secure-shared-compute-node --public --source . --push
```

## 3. Start Claude Code in the repo
```
claude
```

## 4. First prompt (paste as is)
```
Read CLAUDE.md, docs/PLAN.md, docs/FEATURES.md, docs/ARCHITECTURE.md, docs/THREAT_MODEL.md, docs/EVIDENCE.md, TODO.md, and every skill in .claude/skills. Do not write code yet.

Then:
1. Summarize the project, the non-negotiable rules, and the Milestone A scope in your own words.
2. Check my machine: OS, CPU architecture, free RAM, and whether multipass, python3, make, and git are installed. Report what is missing.
3. List any contradictions, gaps, or wrong assumptions you find in the docs, with a proposed fix for each.
4. Propose the exact file list for Phase 0.
Wait for my go-ahead before implementing.
```

## 5. After you approve
Use `/next` for each task. Use `/verify-phase` at the end of each phase. Use `/review` before pushing.

## 6. Good habits during the build
- One task per `/next`. Read the diff before accepting.
- After any SSH or firewall change, open a second terminal and SSH in yourself before ending the session.
- If context gets long, start a fresh Claude Code session. CLAUDE.md and TODO.md carry the state.
- When Milestone A is done (see docs/PLAN.md), push, then send the repo link with your email to Professor Chan.
