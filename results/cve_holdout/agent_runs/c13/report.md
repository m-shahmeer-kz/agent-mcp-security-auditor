# Agent & MCP security report

Scanned: `/tmp/blind/c13` · 2026-11-23T20:46:14+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 2 | 1 | 0 | 0 | 3 | 1 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **63** · agent/MCP code files: **6** · agent instruction files: **3**
- Frameworks seen: FastMCP, mcp

## Findings

### M001 · HIGH · confluence_upload_attachment(s) reads any file on the server host and uploads it to Confluence
`None:None` · ASI02 Tool Misuse and Exploitation

file_path (and each entry of file_paths) is a tool argument opened with no base-directory check, unlike the download paths which use validate_safe_path; an injected instruction can upload ~/.ssh/id_rsa, .env or /proc/self/environ (holding the Atlassian tokens) to a page the attacker can read.
> `src/mcp_atlassian/servers/confluence.py:1009` — `file_path: Annotated[`
> `src/mcp_atlassian/confluence/attachments.py:63` — `file_path = os.path.abspath(file_path)`
> `src/mcp_atlassian/confluence/attachments.py:445` — `files = {"file": (filename, open(file_path, "rb"))}`

**Fix:** Run every path through validate_safe_path(path, UPLOAD_BASE_DIR) with a dedicated operator-configured upload directory (realpath + is_relative_to), and reject absolute paths outside it.

### M002 · HIGH · jira_update_issue attachments argument reads any file on the server host and attaches it to an issue
`None:None` · ASI02 Tool Misuse and Exploitation

Paths from the attachments argument go to upload_attachment, which only makes them absolute and checks existence before opening; a prompt-injected update_issue call can attach any readable server file (keys, env, token cache) to an attacker-visible issue.
> `src/mcp_atlassian/servers/jira.py:1199` — `attachments: Annotated[`
> `src/mcp_atlassian/servers/jira.py:1263` — `all_updates["attachments"] = attachment_paths`
> `src/mcp_atlassian/jira/attachments.py:331` — `with open(file_path, "rb") as file:`

**Fix:** Validate each path with validate_safe_path against a configured upload directory before opening; refuse anything outside it.

### M004 · MEDIUM · Jira/Confluence content returned to the model unmarked, with exfil-capable write tools in the same server
`None:None` · 

Issue and page text written by any project member reaches the model as plain tool output; combined with M001/M002 the same server can read local files and post them back to Atlassian, a full untrusted-input -> private-data -> exfil path with no approval beyond the client's.
> `src/mcp_atlassian/servers/jira.py:163` — `async def get_issue(`
> `src/mcp_atlassian/servers/jira.py:1159` — `async def update_issue(`

**Fix:** Fix M001/M002 first; document READ_ONLY_MODE / ENABLED_TOOLS for untrusted content, and keep write tools behind client approval.

## Dismissed as false alarms

- F001 SSRF `src/mcp_atlassian/servers/confluence.py:1311` — Not SSRF: the host comes from the operator's Confluence URL (config.url); attachment_id only lands in the path of a GET on that same Confluence server, which the caller can already query with the same credentials.
- F002 SSRF `src/mcp_atlassian/servers/confluence.py:1362` — download_url is not a tool argument: it is the _links.download value returned by the configured Confluence server's own attachment metadata (normally a relative path joined to config.url). A tool caller cannot pick the host.
- F003 SSRF `src/mcp_atlassian/servers/confluence.py:1522` — The URL comes from the attachment list returned by the configured Confluence server (get_content_attachments), not from the content_id argument; the caller cannot choose the host.

## Needs information from you

- M003 AUTH `None:None` — With --transport sse/streamable-http, a request with no Authorization header is not rejected and tools run with the server's own configured token (confused deputy), on all interfaces by default; anyone who can reach the port gets the operator's Jira/Confluence access plus the file-reading upload tools above.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
