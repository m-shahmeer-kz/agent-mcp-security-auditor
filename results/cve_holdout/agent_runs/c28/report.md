# Agent & MCP security report

Scanned: `/tmp/blind/c28` · 2026-11-23T20:51:25+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🟠 Fix soon

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 0 | 1 | 2 | 0 | 1 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **12** · agent/MCP code files: **6** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M002 · MEDIUM · delete_memory / delete_translation delete account data with no confirmation
`None:None` · 

A prompt injection in any text the agent is translating can make it call list_memories then delete_memory on every id, permanently destroying the user's translation memories; there is no confirmation, dry-run or destructive hint.
> `src/mcp/tools/delete_memory.ts:12` — `export async function deleteMemory(args: any, lara: Translator) {`
> `src/mcp/tools/delete_memory.ts:15` — `return await lara.memories.delete(id);`

**Fix:** Mark these tools destructiveHint: true so clients ask for approval, require an explicit confirm argument matching the memory name, or move deletes out of the MCP tool set.

### M001 · LOW · HTTP transport binds 0.0.0.0 by default with wildcard CORS
`None:None` · ASI03 Identity and Privilege Abuse

Contrary to the comment, the HTTP server listens on all interfaces by default and cors() without an origin option answers any Origin; impact is limited because every /mcp request must carry the caller's own Lara keys (no server-held credential), so it mainly exposes a free relay and the debug logs.
> `src/env.ts:5` — `HOST: z.string().default("0.0.0.0"),`
> `src/rest/server.ts:41` — `// Bind specifically on 127.0.0.1 to avoid binding to all interfaces`
> `src/rest/middleware/cors.ts:3` — `const corsMiddleware = cors({`

**Fix:** Default HOST to 127.0.0.1 (set 0.0.0.0 only in the Docker env), set an explicit CORS origin allowlist and validate Origin/Host on /mcp.

### M003 · LOW · Debug logging writes full MCP request bodies and the access key id
`None:None` · 

sanitizeBody only redacts top-level keys, so at debug level every tool call's arguments (texts being translated, TMX content) and responses are logged, together with each caller's Lara access key id; the secret itself is redacted.
> `src/rest/middleware/logging.ts:43` — `logger.debug(`Body: ${JSON.stringify(sanitizeBody(req.body), null, 2)}`);`
> `src/mcp/server.ts:17` — `logger.debug("Creating MCP server with credentials: " + accessKeyId);`

**Fix:** Do not log JSON-RPC params/results or key ids; log method name and tool name only.

## Dismissed as false alarms

- F001 PATH-TRAVERSAL `src/mcp/tools/import_tmx.ts:38` — The path is built entirely by the server (fixed temp directory + timestamp + random suffix); only the file content (tmx_content, capped at 5MB) comes from the tool arguments, and the file is deleted in finally. No attacker control over where it is written.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
