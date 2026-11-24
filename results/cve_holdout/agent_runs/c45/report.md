# Agent & MCP security report

Scanned: `/tmp/blind/c45` · 2026-11-23T20:44:16+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 2 | 2 | 1 | 0 | 0 | 1 |

## What was checked

- MCP servers in config files: **1** · tools found in code: **7** · agent/MCP code files: **4** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol, openai

## Findings

### M001 · HIGH · sandbox_exec / run_js / sandbox_stop act on ANY Docker container on the host, not only sandboxes this server created
`None:None` · 

sanitizeContainerId only checks the name's characters and is never compared with activeSandboxContainers, so an injected prompt can run shell commands or code inside any other container on the host (e.g. a database or app container holding secrets) or force-delete it with sandbox_stop.
> `src/tools/exec.ts:12` — `container_id: z.string(),`
> `src/tools/exec.ts:44` — `execFileSync('docker', ['exec', validId, '/bin/sh', '-c', sanitizedCmd], {`
> `src/tools/stop.ts:35` — `execFileSync('docker', ['rm', '-f', validId]);`

**Fix:** Reject any container_id not present in activeSandboxContainers (or not carrying the mcp-sandbox=true and matching mcp-server-run-id labels, checked with docker inspect) in exec, run_js and stop.

### M002 · HIGH · Code sandboxes run with --network host
`None:None` · ASI02 Tool Misuse / ASI05 Unexpected Code Execution

Model-written (and so injectable) code runs in a container that shares the host's network namespace, so it can reach services bound to the host's localhost, internal networks and cloud metadata (169.254.169.254) and send data anywhere, with no approval step; the container is not an isolation boundary for the network.
> `src/tools/initialize.ts:48` — `const portOption = port ? `-p ${port}:${port}` : `--network host`; // prefer --network host if no explicit port mapping`
> `src/tools/runJsEphemeral.ts:85` — `'--network',`
> `src/tools/runJsEphemeral.ts:32` — `image: z`

**Fix:** Use the default bridge network (or --network none unless the user enables network), publish ports with -p only when listenOnPort is set, add --cap-drop ALL --security-opt no-new-privileges --pids-limit, and require client approval for run_js / sandbox_exec.

### M004 · MEDIUM · file:// resource template reads any file on the host
`None:None` · ASI02 Tool Misuse and Exploitation

The resource is meant for files in FILES_DIR, but any URI like file:///home/user/.ssh/id_rsa is read and returned base64; if the client lets the model read resources, an injected prompt can pull any file the server user can read.
> `src/server.ts:130` — `const filepath = new URL(uri).pathname;`
> `src/server.ts:131` — `const data = await fs.readFile(filepath);`

**Fix:** Resolve the path with fs.realpath and require it to be inside path.resolve(FILES_DIR) (path.relative not starting with '..'), otherwise refuse.

### M006 · MEDIUM · Documented setup mounts the Docker socket into the MCP server
`None:None` · ASI03 Identity and Privilege Abuse

Docker socket access is root-equivalent on the host; together with M001 (any container) and unvalidated image/options (M003) a tool call has host-level reach.
> `README.md:76` — `"/var/run/docker.sock:/var/run/docker.sock",`
> `Dockerfile:31` — `VOLUME ["/var/run/docker.sock"]`

**Fix:** Document the risk, prefer a rootless Docker or a socket proxy that only allows create/exec/rm on containers labelled mcp-sandbox=true.

### M003 · LOW · Docker image argument is not validated (sanitizeImageName is never used)
`None:None` · ASI02 Tool Misuse and Exploitation

image goes into docker run as a positional value with no check, so a value starting with '-' is parsed as a docker run option (e.g. --privileged / -v=/:/host), and any image from any registry can be pulled; exploitation is limited because the next token 'tail' then becomes the image name, but the guard the code already has is not applied.
> `src/tools/initialize.ts:25` — `image: z.string().optional(),`
> `src/tools/initialize.ts:72` — `image,`
> `src/utils.ts:164` — `export function sanitizeImageName(image: string): string | null {`

**Fix:** Call sanitizeImageName and reject values starting with '-', or restrict image to an allowlist (the suggestedImages keys).

## Needs information from you

- M005 PATH-TRAVERSAL `None:None` — Code inside the sandbox can create files/symlinks in the mounted FILES_DIR; the host process then reads any new .png/.jpg entry with readFile, which follows symlinks to host paths. Exploitation needs the link target's mtime to be newer than the run start, so it is limited to recently modified host files.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
