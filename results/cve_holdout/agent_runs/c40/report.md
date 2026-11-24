# Agent & MCP security report

Scanned: `/tmp/blind/c40` · 2026-11-23T20:40:18+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 1 | 1 | 2 | 0 | 0 | 0 | 1 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **12** · agent/MCP code files: **7** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · Hackmd-Api-Url header lets any HTTP caller point the server (and its env token) at any URL
`None:None` · ASI02 Tool Misuse and Exploitation

In TRANSPORT=http mode an unauthenticated request can send only the Hackmd-Api-Url header (or ?config=base64 JSON) with an attacker URL; the server then falls back to the operator's HACKMD_API_TOKEN and sends it as a bearer token to that URL on every tool call (token theft), and can also be aimed at internal hosts or 169.254.169.254 (SSRF). ConfigSchema only checks it is a string.
> `index.ts:63` — `config.hackmdApiUrl = hackmdApiUrlHeader;`
> `index.ts:108` — `rawConfig.hackmdApiToken || process.env.HACKMD_API_TOKEN;`
> `index.ts:125` — `rawConfig.hackmdApiUrl ||`

**Fix:** Do not accept the API URL from requests (env/config only), or allowlist https://api.hackmd.io; never combine a request-supplied URL with the server's env token; block private/link-local addresses.

### M002 · HIGH · HTTP /mcp endpoint has no authentication and falls back to the operator's token
`None:None` · 

Any client that reaches the port (listen binds all interfaces) gets read/write/delete access to the HackMD account whose token is in the env, without presenting any credential — a confused deputy with one static upstream credential.
> `index.ts:101` — `app.post("/mcp", async (req: Request, res: Response) => {`
> `index.ts:108` — `rawConfig.hackmdApiToken || process.env.HACKMD_API_TOKEN;`
> `index.ts:189` — `app.listen(PORT, () => {`

**Fix:** In HTTP mode require each caller to send its own token (no env fallback), or add real authentication on /mcp; bind to 127.0.0.1 unless deployed behind an authenticating proxy.

### M003 · MEDIUM · CORS defaults to '*' and allows the token/URL headers
`None:None` · ASI03 Identity and Privilege Abuse

With no CORS_ORIGIN set, any web page the user visits can send cross-origin POSTs to a local/remote HTTP instance and drive all tools with the env token (and set Hackmd-Api-Url for M001); no Origin/Host check guards against DNS rebinding.
> `index.ts:27` — `origin: process.env.CORS_ORIGIN?.split(",") || "*",`
> `index.ts:36` — `HACKMD_API_TOKEN_HEADER,`

**Fix:** Default to no CORS (or an explicit allowlist) and validate Origin/Host headers on /mcp.

### M004 · MEDIUM · Untrusted note content + private notes + a way to publish them, no approval
`None:None` · ASI01 / ASI02 (untrusted input + private data + way out)

get_note / list_team_notes return note bodies (often written by teammates or guests) raw into the model; injected text there can make the agent read private notes and then create_note/update_note with readPermission 'guest' to publish them, or delete notes.
> `tools/userNotes.ts:59` — `text: JSON.stringify(note, null, 2),`
> `tools/userNotes.ts:112` — `payload: UpdateNoteOptionsSchema.describe("Update note options"),`
> `utils/schemas.ts:63` — `readPermission: z`

**Fix:** Mark note content as untrusted data in results, require user confirmation for permission changes, deletes and creates, and consider dropping readPermission/writePermission from the tool schema.

## Needs information from you

- M005 NO-APPROVAL `None:None` — Destructive tools have destructiveHint annotations but no server-side confirmation or dry-run; whether a human approves depends on the MCP client's settings.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
