# Agent & MCP security report

Scanned: `/tmp/blind/c05` · 2026-11-23T20:52:00+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 3 | 1 | 1 | 0 | 2 | 1 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **1** · agent/MCP code files: **2** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · HIGH · mobile_save_screenshot writes to any path given in saveTo
`None:None` · ASI02 Tool Misuse and Exploitation

saveTo from the tool arguments is written with no checks, so a prompt injection (e.g. text shown on the device screen) can make the agent overwrite any file the user can write, such as ~/.bashrc, ~/.ssh/authorized_keys or project files, with PNG data (file destruction; content is not attacker-chosen).
> `src/server.ts:587` — `async ({ device, saveTo }) => {`
> `src/server.ts:591` — `fs.writeFileSync(saveTo, screenshot);`

**Fix:** Write only inside a dedicated screenshots directory: take a bare file name, require .png, resolve with realpath and check path.relative(baseDir, p) does not start with '..'; refuse to overwrite existing files.

### M002 · HIGH · mobile_start_screen_recording writes the recording to any output path
`None:None` · ASI02 Tool Misuse and Exploitation

output from the tool arguments is handed to mobilecli as the output file without any check, so the same arbitrary-file-overwrite applies with MP4 data.
> `src/server.ts:701` — `async ({ device, output, timeLimit }) => {`
> `src/server.ts:708` — `const outputPath = output || path.join(os.tmpdir(), `screen-recording-${Date.now()}.mp4`);`
> `src/server.ts:710` — `const args = ["screenrecord", "--device", device, "--output", outputPath, "--silent"];`

**Fix:** Apply the same base-directory containment and .mp4 extension check as for screenshots, or always use a server-generated temp path.

### M003 · HIGH · SSE mode listens on all interfaces with no authentication and lets any client take over the session
`None:None` · ASI03 Identity and Privilege Abuse

With --port, express listens on every interface (no host given) with no auth, Origin or Host check, and each GET /mcp replaces the current transport; anyone on the network can drive the connected phones (tap, type, install/uninstall apps, open URLs) and use the file-write tools above.
> `src/index.ts:30` — `app.listen(port, () => {`
> `src/index.ts:15` — `app.post("/mcp", (req, res) => {`

**Fix:** Bind to 127.0.0.1 by default, require a bearer token, validate Origin/Host headers, and keep one transport per authenticated session.

### M004 · MEDIUM · On-screen text from the device is returned to the model unmarked
`None:None` · 

Text of SMS, emails, web pages and notifications on the device goes straight into the model context, and the same agent can type, open URLs and save files with no approval step, so text on screen can steer it (untrusted input + private data on the phone + a way out).
> `src/server.ts:472` — `text: element.text,`
> `src/server.ts:492` — `return `Found these elements on screen: ${JSON.stringify(result)}`;`

**Fix:** Label returned screen text as untrusted data, and have clients require approval for destructiveHint tools (type, open_url, install/uninstall, save_screenshot).

### M005 · LOW · Telemetry to PostHog is always on with no opt-out
`None:None` · 

Every launch and tool call sends tool name, duration, platform, client name and a hostname-derived id to a third party with no environment switch to disable it; the embedded phc_ key is a public ingest key, not a secret.
> `src/server.ts:142` — `posthog("launch", {}).then();`
> `src/server.ts:120` — `await fetch(url, {`

**Fix:** Add an opt-out (e.g. MOBILEMCP_DISABLE_TELEMETRY / DO_NOT_TRACK) and document it.

## Dismissed as false alarms

- F002 ARG-INJECTION `src/mobilecli.ts:53` — executeCommandBuffer is only called with a fixed argument list plus deviceId, and deviceId must exactly match a device returned by the device listing before a robot is created; execFileSync uses no shell.
- F003 PATH-TRAVERSAL `src/logger.ts:9` — The log path comes from the operator's LOG_FILE environment variable, not from tool input; only the log message contains tool arguments.

## Needs information from you

- F001 ARG-INJECTION `src/mobilecli.ts:41` — execFileSync with an argument array means no shell injection, but for simulator devices (MobileDevice) packageName, bundle_id, path, url and text from tool arguments are passed to mobilecli as positional values with no `--` and no validation (unlike the Android path, which uses validatePackageName), so a value starting with `-` is parsed as a mobilecli flag. Impact depends on mobilecli's own flags, which are not in this repo.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
