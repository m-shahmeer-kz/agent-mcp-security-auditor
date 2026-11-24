# Agent & MCP security report

Scanned: `/tmp/blind/c33` · 2026-11-23T20:45:32+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 1 | 1 | 2 | 0 | 1 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **12** · agent/MCP code files: **7** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · HIGH · HTTP mode: unauthenticated callers (and any website, via CORS *) get the operator's HACKMD_API_TOKEN
`None:None` · 

When TRANSPORT=http (the Docker image default) and HACKMD_API_TOKEN is set, a POST to /mcp with no token header silently uses the operator's token; the server has no auth, listens on all interfaces and allows any CORS origin, so anyone on the network or any web page the user opens can list, read, edit or delete the operator's notes.
> `index.ts:152` — `rawConfig.hackmdApiToken || process.env.HACKMD_API_TOKEN;`
> `index.ts:27` — `origin: process.env.CORS_ORIGIN?.split(",") || "*",`
> `index.ts:230` — `app.listen(PORT, () => {`

**Fix:** In HTTP mode never fall back to the env token (require the per-request Hackmd-Api-Token header) or require a separate server bearer secret; bind to 127.0.0.1 by default and default CORS_ORIGIN to none.

### M002 · MEDIUM · Reads untrusted team notes, reaches private notes, and can publish notes publicly with no approval
`None:None` · ASI01 / ASI02 (untrusted input + private data + way out)

Note content written by other team members is returned to the model unmarked; an injected instruction can make the agent copy private notes into a new note (or update one) with readPermission 'guest', i.e. publicly readable, and nothing in the server asks for confirmation.
> `tools/teamNotes.ts:24` — `const notes = await client.getTeamNotes(teamPath);`
> `tools/userNotes.ts:54` — `const note = await client.getNote(noteId);`
> `tools/userNotes.ts:88` — `const note = await client.createNote(payload);`

**Fix:** Drop 'guest' from readPermission/writePermission in the tool schemas (or require an explicit server flag to allow it), and have the client require approval for create/update/delete tools.

### M003 · LOW · Delete tools run without confirmation
`None:None` · 

delete_note / delete_team_note delete immediately; they are annotated destructiveHint: true, so protection depends on the client asking the user.
> `tools/userNotes.ts:157` — `const result = await client.deleteNote(noteId);`
> `tools/teamNotes.ts:130` — `const result = await client.deleteTeamNote(teamPath, noteId);`

**Fix:** Keep the annotations, document that clients must require approval, or add a dry-run/confirm parameter.

### M004 · LOW · API token accepted in the URL query string (Smithery config)
`None:None` · 

The base64 config in ?config= carries hackmdApiToken, so the token ends up in reverse-proxy and access logs and browser history.
> `index.ts:99` — `const configParam = req.query.config;`
> `index.ts:102` — `const smitheryConfig = JSON.parse(`

**Fix:** Prefer the Hackmd-Api-Token header; if the query form must stay, make sure proxies strip or do not log the query string.

## Dismissed as false alarms

- M005 SSRF `None:None` — Every request's API URL (from header, query config or env) is checked by exact match against ALLOWED_HACKMD_API_URLS, defaulting to only https://api.hackmd.io/v1, before the client is created.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
