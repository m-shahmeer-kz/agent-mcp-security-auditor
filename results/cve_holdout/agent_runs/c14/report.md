# Agent & MCP security report

Scanned: `/tmp/blind/c14` · 2026-11-23T20:44:27+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 1 | 1 | 1 | 0 | 2 | 2 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **1** · agent/MCP code files: **2** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · HIGH · --port SSE server has no authentication, no Origin/Host check and listens on all interfaces
`None:None` · ASI03 Identity and Privilege Abuse

In --port mode anyone on the network (or a web page via DNS rebinding) can open /mcp and call every tool without credentials: take screenshots and read screen elements of connected phones, type text, open URLs, install/uninstall apps, and write files on the host; a new GET also silently replaces the legitimate client's session.
> `src/index.ts:21` — `app.get("/mcp", (req, res) => {`
> `src/index.ts:15` — `app.post("/mcp", (req, res) => {`
> `src/index.ts:30` — `app.listen(port, () => {`

**Fix:** Listen on 127.0.0.1 by default (app.listen(port, '127.0.0.1')), validate Host and Origin headers, require a bearer token, and keep one transport per session instead of a single global one.

### M002 · MEDIUM · On-screen text from the device goes straight to the model, which also has device-control tools
`None:None` · 

Text shown on the device (web pages, messages, emails) is returned unmarked, and the same agent can read private app content and send it out by typing into apps or opening URLs; the server has no approval step of its own, so this toxic combination relies entirely on the MCP client's confirmation prompts.
> `src/server.ts:496` — `return `Found these elements on screen: ${JSON.stringify(result)}`;`
> `src/server.ts:527` — `await robot.openUrl(url);`
> `src/server.ts:572` — `await robot.sendKeys(text);`

**Fix:** Mark screen-derived text as untrusted data in the result, and document that clients must require human approval for the destructive tools (open_url, type_keys, install/uninstall, launch_app); consider an allowlist of URL schemes/hosts for mobile_open_url.

### M003 · LOW · All tool arguments, including typed text, are written to the log
`None:None` · 

When the agent types a password or OTP with mobile_type_keys, the plain value is written to stderr and to LOG_FILE (and echoed back in the 'Typed text' result).
> `src/server.ts:79` — `trace(`Invoking ${name} with args: ${JSON.stringify(args)}`);`
> `src/logger.ts:9` — `appendFileSync(logfile, logMessage + "\n");`

**Fix:** Redact the text argument of mobile_type_keys (and similar) before logging, e.g. log only its length.

## Dismissed as false alarms

- F002 ARG-INJECTION `src/mobilecli.ts:53` — executeCommandBuffer's only caller passes constant arguments plus a deviceId that getRobotFromDevice has already matched against the real device list; no shell is involved.
- F003 PATH-TRAVERSAL `src/logger.ts:9` — The log file path comes from the operator's LOG_FILE environment variable, not from tool arguments; only the log message contains tool input.

## Needs information from you

- F001 ARG-INJECTION `src/mobilecli.ts:41` — No shell is used (execFileSync with an argument list), so there is no command injection. But on the mobilecli path (iOS simulators) packageName, bundle_id, url, text and install path are passed as positional argv without validatePackageName (which the Android/iOS robots do use) and without '--', so a value starting with '-' is parsed as a mobilecli flag. Whether any mobilecli flag is dangerous cannot be seen from this repo.
- M004 PATH-TRAVERSAL `None:None` — validateOutputPath correctly resolves the parent directory and checks containment, but process.cwd() is an allowed root; if the client starts the server with cwd set to '/' or the home folder, saveTo can overwrite any .png/.jpg/.jpeg/.mp4 file there. Content is screenshot bytes, so impact is limited to overwriting media files. Check which cwd your MCP client uses.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
