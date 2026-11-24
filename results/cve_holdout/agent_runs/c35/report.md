# Agent & MCP security report

Scanned: `/tmp/blind/c35` · 2026-11-23T20:49:03+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🟠 Fix soon

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 0 | 2 | 2 | 0 | 5 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **33** · agent/MCP code files: **59** · agent instruction files: **9**
- Frameworks seen: anthropic, langchain, mcp, modelcontextprotocol, openai

## Findings

### M001 · MEDIUM · POST /mcp logs every request's headers and full body at INFO, before authentication
`None:None` · 

At the default LOG_LEVEL=info every request writes the Authorization bearer token, the x-n8n-key tenant API key, the mcp-session-id and the full JSON-RPC body (including credential data sent to n8n_manage_credentials create/update) to stdout/container logs, so anyone with log access gets the server token and tenants' n8n API keys.
> `src/http-server-single-session.ts:1326` — `logger.info('POST /mcp request received - DETAILED DEBUG', {`
> `src/http-server-single-session.ts:1327` — `headers: req.headers,`
> `src/http-server-single-session.ts:1332` — `bodyContent: req.body ? JSON.stringify(req.body, null, 2) : 'undefined',`

**Fix:** Drop the header/body dump or log only a redacted allowlist (method, path, content-length); never log Authorization, x-n8n-key or tools/call arguments. Do the same for the POST /mcp/test handler (line 1027).

### M002 · MEDIUM · Per-request x-n8n-url is checked once but redirects and later DNS answers are not
`None:None` · ASI02 Tool Misuse and Exploitation

An authenticated caller sets x-n8n-url; the check resolves DNS once, but the axios client re-resolves on every call (DNS rebinding) and follows redirects by default, so a host that passes the check and then 302-redirects (or re-resolves) to 169.254.169.254 or an internal service is reached with the n8n API client, and responses come back to the caller. The IPv6 check also only matches the literal prefixes fc00:/fd00: (other fc00::/7 addresses pass).
> `src/http-server-single-session.ts:1390` — `n8nApiUrl: hasUrl || undefined,`
> `src/http-server-single-session.ts:537` — `const ssrfResult = await SSRFProtection.validateWebhookUrl(instanceContext.n8nApiUrl);`
> `src/utils/ssrf-protection.ts:103` — `const { address } = await lookup(hostname);`

**Fix:** Pin the validated IP for the connection (custom lookup/http agent), set maxRedirects: 0 on the n8n API and webhook axios clients (or re-validate each hop), and test IPv6 ranges with a real CIDR check; only accept x-n8n-url when ENABLE_MULTI_TENANT=true.

### M003 · LOW · GET and DELETE /mcp skip the Bearer check and rely on the session ID alone
`None:None` · 

Anyone who learns a session ID (they are logged, see M001) can attach to that session's server-to-client stream or terminate it without the AUTH_TOKEN. Session IDs are random UUIDs, so this needs a leak first.
> `src/http-server-single-session.ts:1067` — `app.get('/mcp', async (req, res) => {`
> `src/http-server-single-session.ts:1074` — `await existingTransport.handleRequest(req, res, undefined);`
> `src/http-server-single-session.ts:1266` — `app.delete('/mcp', async (req: express.Request, res: express.Response): Promise<void> => {`

**Fix:** Call this.authenticateRequest(req, res) at the top of GET /mcp (session branch) and DELETE /mcp.

### M004 · LOW · Credential tool that can delete/overwrite secrets is annotated non-destructive
`None:None` · 

n8n_manage_credentials supports delete and update but declares destructiveHint: false, so clients that auto-approve non-destructive tools will let a prompt-injected agent delete or replace n8n credentials without asking.
> `src/mcp/tools-n8n-manager.ts:658` — `name: 'n8n_manage_credentials',`
> `src/mcp/tools-n8n-manager.ts:674` — `destructiveHint: false,`

**Fix:** Set destructiveHint: true (or split delete/update into a separate destructive tool) and require confirmation for credential changes.

## Dismissed as false alarms

- F001 TOOL-POISONING `src/mcp/tools-n8n-manager.ts:658` — Ordinary usage guidance: the word 'credentials' is the tool's subject (managing n8n credentials), and 'use getSchema first' serves the user's own request. No hidden steering, no data sent elsewhere.
- F002 NETWORK-EXPOSURE `src/http-server-single-session.ts:955` — This 0.0.0.0 default is only used to build the base URL shown by the unauthenticated info endpoint; it does not bind a socket.
- F003 NETWORK-EXPOSURE `src/http-server-single-session.ts:1474` — Binding all interfaces is intended for container deployment; the MCP endpoints require a Bearer AUTH_TOKEN compared in constant time, the server refuses to start without a token and refuses the default token in production. Remaining gaps on GET/DELETE /mcp are covered in M003.
- F004 NETWORK-EXPOSURE `src/http-server.ts:201` — Same as F002: only used to display the base URL in the info response.
- F005 NETWORK-EXPOSURE `src/http-server.ts:565` — POST /mcp in the legacy server requires a Bearer token checked with a timing-safe compare; the bind address alone is not an exposure. Note this legacy server only warns (does not refuse) when the default AUTH_TOKEN is used.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
