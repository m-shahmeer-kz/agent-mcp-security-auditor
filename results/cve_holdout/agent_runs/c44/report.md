# Agent & MCP security report

Scanned: `/tmp/blind/c44` · 2026-11-23T20:42:59+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 2 | 1 | 0 | 0 | 3 | 1 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **63** · agent/MCP code files: **6** · agent instruction files: **3**
- Frameworks seen: FastMCP, mcp

## Findings

### M001 · HIGH · Unauthenticated HTTP clients choose the Atlassian base URL via X-Atlassian-Jira-Url / X-Atlassian-Confluence-Url headers
`None:None` · ASI02 Tool Misuse and Exploitation

Any client of the HTTP transport (no other auth needed, any token value) can send X-Atlassian-Jira-Url: http://169.254.169.254/ or an internal host; the server builds a fetcher for that URL and immediately makes requests to it, giving SSRF to cloud metadata and internal services, with errors echoed back.
> `src/mcp_atlassian/servers/main.py:451` — `jira_url_header = headers.get(b"x-atlassian-jira-url")`
> `src/mcp_atlassian/servers/dependencies.py:270` — `header_config = JiraConfig(`
> `src/mcp_atlassian/servers/dependencies.py:271` — `url=jira_url_header,`

**Fix:** Only accept header-supplied URLs that match an operator allowlist (e.g. ALLOWED_ATLASSIAN_HOSTS, *.atlassian.net), require https, resolve the host and block private/loopback/link-local ranges, and disable redirects for this validation call.

### M002 · HIGH · Upload tools read any server-side file and send it to Jira/Confluence (local file exfiltration)
`None:None` · ASI02 Tool Misuse and Exploitation

file_path / attachments are tool arguments only turned into absolute paths and checked for existence; a prompt injection in an issue or page can make the agent upload ~/.ssh/id_rsa, the server's .env (Atlassian tokens) or /proc/self/environ as an attachment to a page or issue the attacker can read. In HTTP mode this also lets any remote client read the server host's files.
> `src/mcp_atlassian/servers/confluence.py:1009` — `file_path: Annotated[`
> `src/mcp_atlassian/confluence/attachments.py:438` — `files = {"file": (filename, open(file_path, "rb"))}`
> `src/mcp_atlassian/servers/jira.py:1199` — `attachments: Annotated[`

**Fix:** Restrict uploads to a configured upload directory: Path(file_path).resolve() then require is_relative_to(UPLOAD_ROOT.resolve()); refuse symlinks; or disable path-based uploads in HTTP mode and accept base64 content instead.

### M003 · MEDIUM · HTTP transports bind to 0.0.0.0 by default
`None:None` · ASI03 Identity and Privilege Abuse

With sse/streamable-http the server listens on all interfaces by default, so anyone on the network can reach the tools (and M001/M002) and, when global credentials are configured, act with the operator's Atlassian account.
> `src/mcp_atlassian/__init__.py:130` — `default="0.0.0.0",  # noqa: S104`
> `src/mcp_atlassian/servers/main.py:451` — `jira_url_header = headers.get(b"x-atlassian-jira-url")`

**Fix:** Default --host to 127.0.0.1 and require an explicit flag plus an authentication layer to listen publicly.

## Dismissed as false alarms

- F001 SSRF `src/mcp_atlassian/servers/confluence.py:1311` — The host is the operator-configured Confluence base URL; attachment_id only changes the path on that same host, so a tool argument cannot point the request at internal services or cloud metadata.
- F002 SSRF `src/mcp_atlassian/servers/confluence.py:1362` — download_url is taken from the configured Confluence server's own API response (_links.download), not from a tool argument; relative links are joined to the configured base URL.
- F003 SSRF `src/mcp_atlassian/servers/confluence.py:1522` — The URL comes from attachment metadata returned by the configured Confluence server, not from the tool argument (content_id only selects which page's attachments to list).

## Needs information from you

- M004 INDIRECT-INJECTION `None:None` — Jira/Confluence content written by other users is returned straight into the model context while the same server exposes write and upload tools (M002) with no confirmation; whether this matters depends on who can write to the connected spaces/projects.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
