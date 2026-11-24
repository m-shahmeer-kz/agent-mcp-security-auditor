# Agent & MCP security report

Scanned: `/tmp/blind/c38` · 2026-11-23T20:41:32+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 1 | 2 | 0 | 1 | 0 | 0 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **25** · agent/MCP code files: **1** · agent instruction files: **0**
- Frameworks seen: FastMCP, mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · create_workbook / write tools create or overwrite files at any path
`None:None` · ASI02 Tool Misuse and Exploitation

create_workbook takes any absolute or '../' path (same unchecked get_excel_path), creates missing directories and saves a workbook there without checking whether a file exists, so a caller can overwrite any file the server user can write (e.g. ~/.bashrc, config files) and create directories anywhere.
> `src/excel_mcp/server.py:297` — `def create_workbook(filepath: str) -> str:`
> `src/excel_mcp/server.py:300` — `full_path = get_excel_path(filepath)`
> `src/excel_mcp/workbook.py:24` — `path.parent.mkdir(parents=True, exist_ok=True)`

**Fix:** Use the contained-path check from F001 for every tool, refuse to overwrite existing files in create_workbook (open with mode 'xb' or check exists()), and only allow .xlsx extensions.

### M002 · HIGH · HTTP/SSE server binds 0.0.0.0 with no authentication
`None:None` · ASI03 Identity and Privilege Abuse

In sse/streamable-http mode the server listens on all interfaces by default and FastMCP is created with no auth, so anyone who can reach port 8017 can call every tool, and with F001/M001 read or overwrite files anywhere on the host.
> `src/excel_mcp/server.py:69` — `host=os.environ.get("FASTMCP_HOST", "0.0.0.0"),`
> `src/excel_mcp/server.py:807` — `mcp.run(transport="sse")`
> `src/excel_mcp/server.py:826` — `mcp.run(transport="streamable-http")`

**Fix:** Default FASTMCP_HOST to 127.0.0.1, require a bearer token (FastMCP auth settings or a reverse proxy with auth) before exposing it, and enable Host/Origin checks.

### F001 · HIGH · PATH-TRAVERSAL
`src/excel_mcp/server.py:684` · ASI02 Tool Misuse and Exploitation

get_excel_path returns absolute paths unchanged and joins relative ones without resolving or checking containment, so in SSE/HTTP mode filepath='/home/user/finance.xlsx' or '../../secret.xlsx' escapes EXCEL_FILES_PATH. The same helper feeds every tool (read_data_from_excel, get_workbook_metadata, etc.), so any workbook on the host can be read.
> `src/excel_mcp/server.py:663` — `filepath: str,`
> `src/excel_mcp/server.py:86` — `if os.path.isabs(filename):`
> `src/excel_mcp/server.py:94` — `return os.path.join(EXCEL_FILES_PATH, filename)`

**Fix:** In get_excel_path: reject absolute paths when EXCEL_FILES_PATH is set, resolve with Path(EXCEL_FILES_PATH, filename).resolve() and require .is_relative_to(Path(EXCEL_FILES_PATH).resolve()); also enforce an .xlsx/.xlsm extension.

### M003 · LOW · Spreadsheet cell contents returned unmarked to the model
`None:None` · 

Cell values from workbooks (often received from third parties) go straight into the model context; injected instructions in a cell can steer the destructive tools of this server (delete/overwrite). The server itself has no network egress, so impact is limited.
> `src/excel_mcp/server.py:251` — `return json.dumps(result, indent=2, default=str)`

**Fix:** Mark returned cell data as untrusted content and keep human approval on the destructive tools.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
