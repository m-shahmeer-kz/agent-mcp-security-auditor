# Agent & MCP security report

Scanned: `/tmp/blind/c34` · 2026-11-23T20:40:51+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 2 | 0 | 9 | 0 | 2 | 2 |

## What was checked

- MCP servers in config files: **6** · tools found in code: **0** · agent/MCP code files: **3** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · HIGH · /bridge launches any command (or connects to any URL) chosen by the caller
`None:None` · ASI02 Tool Misuse / ASI05

Any holder of the single ACCESS_TOKEN can POST serverPath='/bin/sh', args=['-c','...'] and get command execution on the gateway host, or give an http(s)/ws URL to make the server connect to internal services (SSRF); nothing restricts it to the configured mcp-servers.json entries. With --tunnel the endpoint is published on the internet.
> `src/server/http-server.ts:191` — `const { serverPath, method, params, args, env } = req.body;`
> `src/server/http-server.ts:224` — `clientId = await this.mcpClient.createClient(serverPath, args, env);`
> `src/client/mcp-client-manager.ts:69` — `command: serverPath,`

**Fix:** Remove free-form serverPath/args/env from /bridge and accept only a server id from the operator's config (as /mcp/:serverId does); if URLs are needed, allowlist hosts and block private ranges.

### M002 · HIGH · X-MCP-ENV-* headers let callers set arbitrary environment variables for spawned servers
`None:None` · ASI02 Tool Misuse / ASI05

A caller can send X-MCP-ENV-NODE-OPTIONS: --require /tmp/x.js, LD_PRELOAD or PATH for an npx/uvx server and run code on the host, or override variables such as N8N_API_URL so a configured server sends its N8N_API_KEY to an attacker host. Even /mcp/:serverId is therefore not limited to operator-defined behaviour.
> `src/server/http-server.ts:377` — `const envKey = rawEnvName.replace(/-/g, '_').toUpperCase();`
> `src/server/http-server.ts:454` — `...headerEnvOverrides,`
> `src/stream/stream-session.ts:26` — `...(serverConfig.env ?? {}),`

**Fix:** Accept only an operator-defined allowlist of overridable variable names per server, and never NODE_OPTIONS, LD_*, PATH, *_URL for servers that hold keys.

### M003 · LOW · Single static bearer token compared with !==; tunnel publishes the gateway
`None:None` · 

One shared token gates full host command execution (M001/M002) for every client, the comparison is not constant-time, and --tunnel exposes the port publicly via ngrok; there are no per-client identities, scopes or rate limiting.
> `src/server/http-server.ts:128` — `if (!token || token !== this.accessToken) {`
> `src/server/http-server.ts:289` — `const url = await this.tunnelManager.createTunnel(this.config.server.port);`

**Fix:** Use crypto.timingSafeEqual, per-client tokens with scopes, rate limiting on 401s, and avoid public tunnels for this endpoint.

### M004 · LOW · Full tool-call arguments and bridge bodies are logged
`None:None` · 

maskSensitiveData only masks body.env; tool arguments and args (which can contain API keys, passwords or page content) are written to logs at info level.
> `src/client/mcp-client-manager.ts:128` — `this.logger.info(`Calling tool: ${JSON.stringify(params)}`);`
> `src/server/http-server.ts:192` — `this.logger.info('Bridge request received:', this.maskSensitiveData(req.body));`

**Fix:** Log only method/tool names and sizes, or redact argument values.

### M005 · LOW · Unbounded process spawning per request
`None:None` · 

Every request with new args/env or without a session id starts a new child process; there is no cap on concurrent clients/sessions, so an authenticated caller (or a looping agent) can exhaust the host.
> `src/server/http-server.ts:202` — `const cacheKey = `${serverPath}-${JSON.stringify(args)}-${JSON.stringify(env)}`;`
> `src/server/http-server.ts:466` — `session = await this.streamSessionManager.createSession(serverId, effectiveServerConfig);`

**Fix:** Cap concurrent clients/sessions per token and overall, and rate-limit session creation.

### F004 · LOW · UNPINNED-PACKAGE
`mcp-servers.example.json:5` · ASI04 Agentic Supply Chain

Each new session downloads whatever release is current (uvx/npx @latest); a hijacked release runs inside the gateway host. Low because these entries carry no credentials in env, but the browser servers control a shared browser.
> `mcp-servers.example.json:5` — `"args": ["mcp-server-fetch"],`

**Fix:** Pin exact versions (e.g. mcp-server-fetch==X.Y.Z, chrome-devtools-mcp@X.Y.Z, @playwright/mcp@X.Y.Z) and update deliberately.

### F005 · LOW · UNPINNED-PACKAGE
`mcp-servers.example.json:11` · ASI04 Agentic Supply Chain

Each new session downloads whatever release is current (uvx/npx @latest); a hijacked release runs inside the gateway host. Low because these entries carry no credentials in env, but the browser servers control a shared browser.
> `mcp-servers.example.json:11` — `"chrome-devtools-mcp@latest",`

**Fix:** Pin exact versions (e.g. mcp-server-fetch==X.Y.Z, chrome-devtools-mcp@X.Y.Z, @playwright/mcp@X.Y.Z) and update deliberately.

### F006 · LOW · UNPINNED-PACKAGE
`mcp-servers.example.json:22` · ASI04 Agentic Supply Chain

Each new session downloads whatever release is current (uvx/npx @latest); a hijacked release runs inside the gateway host. Low because these entries carry no credentials in env, but the browser servers control a shared browser.
> `mcp-servers.example.json:22` — `"@playwright/mcp@latest",`

**Fix:** Pin exact versions (e.g. mcp-server-fetch==X.Y.Z, chrome-devtools-mcp@X.Y.Z, @playwright/mcp@X.Y.Z) and update deliberately.

### F007 · LOW · UNPINNED-PACKAGE
`mcp-servers.json:5` · ASI04 Agentic Supply Chain

Each new session downloads whatever release is current (uvx/npx @latest); a hijacked release runs inside the gateway host. Low because these entries carry no credentials in env, but the browser servers control a shared browser.
> `mcp-servers.json:5` — `"args": ["mcp-server-fetch"],`

**Fix:** Pin exact versions (e.g. mcp-server-fetch==X.Y.Z, chrome-devtools-mcp@X.Y.Z, @playwright/mcp@X.Y.Z) and update deliberately.

### F008 · LOW · UNPINNED-PACKAGE
`mcp-servers.json:11` · ASI04 Agentic Supply Chain

Each new session downloads whatever release is current (uvx/npx @latest); a hijacked release runs inside the gateway host. Low because these entries carry no credentials in env, but the browser servers control a shared browser.
> `mcp-servers.json:11` — `"chrome-devtools-mcp@latest",`

**Fix:** Pin exact versions (e.g. mcp-server-fetch==X.Y.Z, chrome-devtools-mcp@X.Y.Z, @playwright/mcp@X.Y.Z) and update deliberately.

### F009 · LOW · UNPINNED-PACKAGE
`mcp-servers.json:22` · ASI04 Agentic Supply Chain

Each new session downloads whatever release is current (uvx/npx @latest); a hijacked release runs inside the gateway host. Low because these entries carry no credentials in env, but the browser servers control a shared browser.
> `mcp-servers.json:22` — `"@playwright/mcp@latest",`

**Fix:** Pin exact versions (e.g. mcp-server-fetch==X.Y.Z, chrome-devtools-mcp@X.Y.Z, @playwright/mcp@X.Y.Z) and update deliberately.

## Dismissed as false alarms

- F002 TLS-VERIFY-OFF `deploy/e2b/sandbox_deploy.py:692` — Unauthenticated GET /health probe of the deployer's own sandbox; no credentials are sent and only the status code is used, so a MITM can at most fake readiness.
- F003 TLS-VERIFY-OFF `deploy/e2b/sandbox_deploy.py:877` — Unauthenticated GET /health probe of the deployer's own sandbox; no credentials are sent and only the status code is used, so a MITM can at most fake readiness.

## Needs information from you

- F001 TOXIC-FLOW `mcp-servers.json:1` — The bridge exposes fetch (untrusted web text) plus two servers driving the same shared, non-isolated Chrome profile (logged-in sessions, can navigate/POST anywhere) with no approval step in the bridge. It is a real lethal trifecta only if that browser profile holds private sessions/data; in a throwaway E2B sandbox it may not.
- M006 NETWORK-EXPOSURE `None:None` — CDP gives full control of the browser (read pages/cookies, open file:// URLs, navigate) to anyone who can reach port 9222, with no token; whether 9222 is reachable from outside depends on E2B port exposure. startup.sh correctly uses 127.0.0.1.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
