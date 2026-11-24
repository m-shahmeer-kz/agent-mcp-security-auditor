# Agent & MCP security report

Scanned: `/tmp/blind/c42` · 2026-11-24T01:33:37+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 2 | 2 | 0 | 0 | 1 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **209** · agent/MCP code files: **40** · agent instruction files: **246**
- Frameworks seen: FastMCP, anthropic, mcp, modelcontextprotocol, openai

## Findings

### F001 · HIGH · AUTO-APPROVE
`.claude/settings.json:12` · ASI09 Human-Agent Trust Exploitation

Claude Code may run any claude-flow subcommand with any arguments without asking, and npx fetches whatever version of the package npm currently serves; a prompt-injected agent gets unattended command execution through it. The deny list is a short blocklist of exact strings and stops nothing else.
> `.claude/settings.json:12` — `"Bash(npx claude-flow *)",`
> `.claude/settings.json:34` — `"Bash(rm -rf /)",`

**Fix:** Remove the wildcard; allow only the specific read-only subcommands you need, pin the package (claude-flow@<exact version>) and install it locally instead of via npx.

### F002 · HIGH · AUTO-APPROVE
`.claude/settings.json:28` · ASI09 Human-Agent Trust Exploitation

`node *` auto-approves `node -e "require('child_process').execSync(...)"`, i.e. arbitrary code on the developer machine with no prompt; denying `eval *` and `curl * | bash` does not cover it.
> `.claude/settings.json:28` — `"Bash(node *)",`
> `.claude/settings.json:37` — `"Bash(eval *)"`

**Fix:** Drop `Bash(node *)`; allow only specific scripts (e.g. `Bash(node scripts/build.js)`) or use npm run targets.

### M001 · MEDIUM · Hooks run unpinned `npx claude-flow@alpha` automatically on every Bash call, edit and session end
`None:None` · ASI04 Agentic Supply Chain

Every tool use downloads and runs the current `alpha` tag of a third-party npm package in the developer's shell (with their credentials), passing it each command and file path; a compromised or changed release runs automatically with no approval. Telemetry and remote execution are also switched on.
> `.claude/settings.json:47` — `npx claude-flow@alpha hooks pre-command --command '{}' --validate-safety true --prepare-resources true`
> `.claude/settings.json:106` — `"command": "npx claude-flow@alpha hooks session-end --generate-summary true --persist-state true --export-metrics true"`
> `.claude/settings.json:7` — `"CLAUDE_FLOW_REMOTE_EXECUTION": "true",`

**Fix:** Pin an exact version and install it as a devDependency (run from node_modules/.bin), review its telemetry, and set CLAUDE_FLOW_REMOTE_EXECUTION/TELEMETRY to false unless needed.

### M002 · MEDIUM · git push and git config * are auto-approved
`None:None` · ASI09 Human-Agent Trust Exploitation

An injected agent can commit and push to the remote without asking (a way to send data out), and `git config` can set core.hooksPath, core.sshCommand or aliases that execute arbitrary commands on the next git call.
> `.claude/settings.json:21` — `"Bash(git push)",`
> `.claude/settings.json:22` — `"Bash(git config *)",`

**Fix:** Remove git push and git config from the allow list (keep them on ask), or restrict git config to read-only forms such as `git config --get *`.

## Dismissed as false alarms

- F003 HIDDEN-INSTRUCTIONS `.claude/agents/swarm/hierarchical-coordinator.md:150` — The 'invisible characters' are the variation selector and combining keycap of the emoji 1️⃣ (and similar numbered emoji) used as list markers; no hidden text is encoded.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
