# Agent & MCP security report

Scanned: `/tmp/blind/c43` · 2026-11-23T20:38:18+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 1 | 2 | 1 | 0 | 3 | 2 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **33** · agent/MCP code files: **59** · agent instruction files: **9**
- Frameworks seen: anthropic, langchain, mcp, modelcontextprotocol, openai

## Findings

### M001 · HIGH · POST /mcp logs all request headers (bearer token, x-n8n-key) and the full JSON body before authentication
`None:None` · 

At the default info level, every POST /mcp writes the Authorization bearer token, each tenant's x-n8n-key n8n API key, and the whole JSON-RPC body (including n8n_manage_credentials create/update `data` secrets) to stdout/container logs; it runs outside the ConsoleManager wrapper so it is not suppressed. Anyone with log access gets the server token and every tenant's n8n key and credential values, contradicting the tool's 'never logged' promise.
> `src/http-server-single-session.ts:1274` — `logger.info('POST /mcp request received - DETAILED DEBUG', {`
> `src/http-server-single-session.ts:1275` — `headers: req.headers,`
> `src/http-server-single-session.ts:1280` — `bodyContent: req.body ? JSON.stringify(req.body, null, 2) : 'undefined',`

**Fix:** Remove headers and bodyContent from this log line (log method, sessionId and a redacted header list only), or move it to debug with Authorization, x-n8n-key and params.arguments.data redacted.

### M002 · MEDIUM · Model can create, activate and trigger arbitrary n8n workflows with no approval step
`None:None` · ASI02 Tool Misuse / ASI05 Unexpected Code Execution

By design, n8n_create_workflow / n8n_update_partial_workflow (activateWorkflow) / n8n_test_workflow let any tool call build a workflow with Code, HTTP Request or Execute Command nodes, activate it and fire it, so a prompt injection can run code or send data out from the n8n instance using its stored credentials. The only controls are the operator-set DISABLED_TOOLS list, the n8n API key scope and the client honouring destructiveHint annotations.
> `src/mcp/tools-n8n-manager.ts:150` — `activate/deactivateWorkflow, transferWorkflow.`
> `src/mcp/server.ts:1505` — `return n8nHandlers.handleTestWorkflow(args, this.instanceContext);`

**Fix:** Document running with DISABLED_TOOLS for write/activate/test tools unless needed, require client-side approval for these tools, and use an n8n API key scoped to a sandbox project; consider refusing to activate workflows containing Code/Execute Command nodes without an explicit confirm flag.

### M003 · MEDIUM · Destructive delete actions run immediately with no confirmation or dry-run
`None:None` · 

n8n_delete_workflow and n8n_manage_credentials action=delete permanently delete on the first call; a prompt-injected call can wipe workflows or credentials. Only the destructiveHint annotation (client-dependent) stands in the way.
> `src/mcp/handlers-n8n-manager.ts:934` — `const deleted = await client.deleteWorkflow(id);`
> `src/mcp/handlers-n8n-manager.ts:3105` — `await client.deleteCredential(id);`

**Fix:** Require a confirm: true argument echoed back from a preview call, or keep these tools in DISABLED_TOOLS by default.

### M004 · LOW · Execution data and workflow/template content returned raw to the model
`None:None` · 

n8n_executions get returns execution data, which contains whatever external webhooks, emails or HTTP responses the workflow processed, straight into the model context unmarked; combined with M002 this is the path for injected instructions.
> `src/mcp/server.ts:1514` — `return n8nHandlers.handleGetExecution(args, this.instanceContext);`

**Fix:** Mark returned execution/template content as untrusted data and default to summary/metadata modes.

## Dismissed as false alarms

- F001 TOOL-POISONING `src/mcp/tools-n8n-manager.ts:658` — Ordinary usage guidance for the tool's own purpose (list actions, call getSchema before create); it does not tell the model to read secrets, call other tools, send data out or hide anything. The word 'credentials' is just the tool's subject.
- F002 NETWORK-EXPOSURE `src/http-server-single-session.ts:991` — Inside the GET / info handler the host value is only used to build the displayed base URL; it does not bind a socket. The real listen call is F003.
- F004 NETWORK-EXPOSURE `src/http-server.ts:201` — Display-only value inside the GET / info handler; no socket is bound here (the listen call is F005).

## Needs information from you

- F003 NETWORK-EXPOSURE `src/http-server-single-session.ts:1422` — The HTTP server binds all interfaces by default, but every MCP endpoint (/mcp GET/POST/DELETE, /sse, /messages) calls authenticateRequest with a timing-safe bearer-token check and startup refuses an empty token. Whether all-interface exposure is acceptable depends on the deployment (container behind a proxy vs. a laptop).
- F005 NETWORK-EXPOSURE `src/http-server.ts:565` — Legacy HTTP server binds all interfaces by default; POST /mcp requires a timing-safe bearer token, so exposure risk depends on where it is deployed.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
