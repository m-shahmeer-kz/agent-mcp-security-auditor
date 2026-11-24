# Agent & MCP security report

Scanned: `/tmp/blind/c25` · 2026-11-23T20:33:24+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 1 | 6 | 1 | 0 | 0 | 8 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **50** · agent/MCP code files: **6** · agent instruction files: **0**
- Frameworks seen: mcp

## Findings

### M001 · CRITICAL · get_sql_profile executes arbitrary SQL with no security validation
`None:None` · ASI02 Tool Misuse and Exploitation

The get_sql_profile tool runs the model-supplied sql directly on a pooled connection without auth_context, so DorisConnection.execute skips validate_sql_security; `DROP DATABASE prod` or `GRANT ...` runs as the configured DB user (root by default), bypassing the blocklist that exec_query applies.
> `doris_mcp_server/tools/tools_manager.py:1565` — `sql = arguments.get("sql")`
> `doris_mcp_server/utils/analysis_tools.py:535` — `sql_result = await connection.execute(sql)`

**Fix:** Run security_manager.validate_sql_security(sql, auth_context) before executing (or reuse execute_sql_for_mcp), accept only a single SELECT statement, and connect with a read-only Doris user.

### M002 · HIGH · Metadata tools paste table_name/db_name into SQL string literals, bypassing the SQL validator
`None:None` · ASI02 Tool Misuse and Exploitation

get_table_comment (and get_table_schema / get_table_column_comments / get_db_table_list, same pattern at lines 454, 604, 1354, TABLE_SCHEMA = '{db_name}') build information_schema queries with f-strings and execute them via connection_manager.execute_query without auth_context, so no validation; table_name `x' UNION SELECT secret FROM other_db.t -- ` returns any data the root DB user can read, including tables the validator blocks.
> `doris_mcp_server/tools/tools_manager.py:1504` — `table_name = arguments.get("table_name")`
> `doris_mcp_server/utils/schema_extractor.py:1557` — `comment = await self.get_table_comment_async(table_name=table_name, db_name=db_name, catalog_name=catalog_name)`
> `doris_mcp_server/utils/schema_extractor.py:1329` — `AND TABLE_NAME = '{table_name}'`

**Fix:** Use placeholders: execute_query(session, 'SELECT ... WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s', (db_name, table_name)); validate identifiers with ^[A-Za-z0-9_]+$ where they must be inlined (USE, SHOW INDEX, DESCRIBE).

### M003 · HIGH · exec_query relies on a keyword blocklist while connecting as root
`None:None` · ASI02 Tool Misuse and Exploitation

The only guard on the run-any-SQL tool is a sqlparse keyword/regex blocklist that inspects only the first parsed statement and misses Doris statements not on the list (e.g. SET GLOBAL, ADMIN ..., SELECT ... INTO OUTFILE), while the default DB user is root; a blocklist is not a working guard for this tool.
> `doris_mcp_server/tools/tools_manager.py:1465` — `sql = arguments.get("sql")`
> `doris_mcp_server/utils/security.py:907` — `parsed = sqlparse.parse(sql)[0]`
> `doris_mcp_server/utils/config.py:44` — `user: str = "root"`

**Fix:** Connect the MCP server with a dedicated read-only Doris user (SELECT privilege on the allowed databases only), reject inputs with more than one statement, and allow-list statement types (SELECT/SHOW/DESC/EXPLAIN).

### M004 · HIGH · HTTP transport binds 0.0.0.0 with all authentication disabled by default
`None:None` · ASI03 Identity and Privilege Abuse

The Docker/start script runs Streamable HTTP on 0.0.0.0:3000 and, with token/JWT/OAuth all off by default, authenticate_request returns an anonymous context, so anyone who can reach the port can call exec_query / get_sql_profile against the root DB connection.
> `start_server.sh:68` — `export MCP_HOST="${MCP_HOST:-0.0.0.0}"`
> `doris_mcp_server/utils/config.py:81` — `enable_token_auth: bool = False  # Enable token-based authentication (default: disabled)`
> `doris_mcp_server/utils/security.py:234` — `return AuthContext(`

**Fix:** Default to 127.0.0.1, refuse to start the HTTP transport on a non-loopback address unless an auth method is enabled, and enable token auth in docker-compose.

### F008 · HIGH · SECRET-IN-CODE
`tokens.json:8` · ASI03 Identity and Privilege Abuse

Not a leaked third-party key but a publicly known default admin token that the server loads from tokens.json by default; when token auth is enabled anyone who has read the repo can authenticate as admin (bound to DB user root).
> `tokens.json:8` — `"token": "doris_admin_token_123456",`
> `doris_mcp_server/auth/token_manager.py:95` — `self.token_file_path = getattr(config.security, 'token_file_path', 'tokens.json')`

**Fix:** Ship tokens.json.example only, generate random tokens on first start (secrets.token_urlsafe(32)), refuse to start if a default token is present, and replace these values in any deployment.

### F009 · HIGH · SECRET-IN-CODE
`tokens.json:24` · ASI03 Identity and Privilege Abuse

Same as F008: publicly known default analyst token loaded by default; its database_config also connects as root.
> `tokens.json:24` — `"token": "doris_analyst_token_123456",`

**Fix:** Same as F008.

### F010 · HIGH · SECRET-IN-CODE
`tokens.json:40` · ASI03 Identity and Privilege Abuse

Same as F008: publicly known default 'readonly' token, which is in fact bound to DB user root, so it gives full tool access.
> `tokens.json:40` — `"token": "doris_readonly_token_123456",`

**Fix:** Same as F008, and bind readonly tokens to a read-only Doris user.

### M005 · MEDIUM · All MCP request headers, including Authorization, logged at INFO
`None:None` · 

Bearer tokens sent in the Authorization header are written to the log file on every MCP request, so anyone with log access can replay them.
> `doris_mcp_server/main.py:627` — `self.logger.info(f"MCP Request - Headers: {headers}")`

**Fix:** Drop this log line or redact authorization/cookie/x-api-key headers before logging.

## Dismissed as false alarms

- F001 SECRET-IN-CODE `doris_mcp_server/auth/oauth_types.py:166` — Public Google OAuth authorization endpoint URL, not a secret.
- F002 SECRET-IN-CODE `doris_mcp_server/auth/oauth_types.py:167` — Public Google OAuth token endpoint URL, not a secret.
- F003 SECRET-IN-CODE `doris_mcp_server/auth/oauth_types.py:177` — Public Microsoft identity platform endpoint URL, not a secret.
- F004 SECRET-IN-CODE `doris_mcp_server/auth/oauth_types.py:178` — Public Microsoft identity platform endpoint URL, not a secret.
- F005 SECRET-IN-CODE `test/test_config.json:41` — Test fixture placeholder in test/ config, not a real credential and not loaded by the server.
- F006 SECRET-IN-CODE `test/test_config.json:42` — Test fixture placeholder in test/ config, not a real credential and not loaded by the server.
- F007 SECRET-IN-CODE `test/test_config.json:43` — Test fixture for an intentionally invalid token.
- F011 AUTH-BYPASS `doris_mcp_server/auth/jwt_manager.py:380` — decode_token_unsafe is only called by get_token_info, which nothing in the code base calls; the authentication path uses the verified jwt.decode at line 259 / 346. Unreachable today, but a trap for future use.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
