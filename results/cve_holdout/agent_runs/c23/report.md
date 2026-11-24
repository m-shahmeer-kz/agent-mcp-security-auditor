# Agent & MCP security report

Scanned: `/tmp/blind/c23` · 2026-11-23T20:46:34+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 3 | 0 | 1 | 0 | 3 | 1 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **63** · agent/MCP code files: **6** · agent instruction files: **3**
- Frameworks seen: FastMCP, mcp

## Findings

### M001 · HIGH · Confluence upload_attachment(s) reads and uploads any local file chosen by the model
`None:None` · ASI02 Tool Misuse and Exploitation

file_path (and file_paths in upload_attachments) goes straight from the tool arguments to an open/upload with no base-directory check, unlike the download path which uses validate_safe_path. An injected instruction in a page or issue can make the agent upload ~/.ssh/id_rsa, ~/.aws/credentials or the server's .env to a Confluence page the attacker can read.
> `src/mcp_atlassian/servers/confluence.py:1009` — `file_path: Annotated[`
> `src/mcp_atlassian/servers/confluence.py:1060` — `result = confluence_fetcher.upload_attachment(`
> `src/mcp_atlassian/confluence/attachments.py:64` — `file_path = os.path.abspath(file_path)`

**Fix:** Call validate_safe_path(file_path, base_dir=<configured upload dir>) on every path before opening it, refuse symlinks, and make the upload directory an explicit operator setting.

### M002 · HIGH · Jira update_issue attachments argument uploads any local file
`None:None` · ASI02 Tool Misuse and Exploitation

Paths from the update_issue tool argument are opened and attached to the issue with no containment check, so a prompt injection can exfiltrate any file readable by the server process into a Jira issue.
> `src/mcp_atlassian/servers/jira.py:1199` — `attachments: Annotated[`
> `src/mcp_atlassian/servers/jira.py:1263` — `all_updates["attachments"] = attachment_paths`
> `src/mcp_atlassian/jira/attachments.py:331` — `with open(file_path, "rb") as file:`

**Fix:** Validate each path with validate_safe_path against an operator-configured upload directory before upload_attachment opens it.

### M003 · HIGH · X-Atlassian-Jira-Url / X-Atlassian-Confluence-Url request headers set the upstream URL with no allowlist
`None:None` · ASI02 Tool Misuse and Exploitation

Any HTTP client of the server can send these headers with any token and the server immediately makes requests to that URL (validation call, then every tool call), e.g. http://169.254.169.254/ or internal admin services; error text is returned to the caller.
> `src/mcp_atlassian/servers/main.py:451` — `jira_url_header = headers.get(b"x-atlassian-jira-url")`
> `src/mcp_atlassian/servers/dependencies.py:271` — `url=jira_url_header,`
> `src/mcp_atlassian/servers/main.py:455` — `confluence_url_header = headers.get(b"x-atlassian-confluence-url")`

**Fix:** Only accept header URLs that match an operator allowlist of Atlassian hosts (e.g. *.atlassian.net or configured DC URLs), require https, and block private/loopback/link-local addresses after DNS resolution.

### M005 · LOW · Page and issue content is returned to the model unmarked
`None:None` · 

Confluence pages, comments and Jira issues are written by many people and go straight into the model context; this is the path by which injected text reaches the file-upload tools above.
> `src/mcp_atlassian/servers/confluence.py:126` — `async def get_page(`

**Fix:** Wrap returned content as untrusted data, and keep write/upload tools behind human approval or READ_ONLY_MODE when processing third-party content.

## Dismissed as false alarms

- F001 SSRF `src/mcp_atlassian/servers/confluence.py:1311` — Scheme and host come from the operator-configured Confluence URL; attachment_id only lands in the path on that same host, so it cannot redirect the request to another host or to cloud metadata. (Path tampering stays inside the Confluence API the caller is already authorized for.)
- F002 SSRF `src/mcp_atlassian/servers/confluence.py:1362` — download_url is not a tool argument: it is taken from the configured Confluence server's own attachment metadata response, and relative links are prefixed with the configured base URL. The model cannot choose it.
- F003 SSRF `src/mcp_atlassian/servers/confluence.py:1522` — Same as F002: the URL comes from Confluence's attachment listing for content_id, not from the tool arguments; relative links are prefixed with the configured base URL.

## Needs information from you

- M004 NETWORK-EXPOSURE `None:None` — In SSE/streamable-HTTP mode the server listens on all interfaces and a request with no Authorization header is served with the globally configured token, so anyone who can reach the port acts as the operator in Jira/Confluence and can use the local-file upload tools (M001/M002). Whether this matters depends on whether the port is reachable.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
