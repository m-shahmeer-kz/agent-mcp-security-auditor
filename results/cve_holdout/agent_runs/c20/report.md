# Agent & MCP security report

Scanned: `/tmp/blind/c20` · 2026-11-23T20:47:36+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 2 | 4 | 0 | 0 | 8 | 1 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **50** · agent/MCP code files: **6** · agent instruction files: **0**
- Frameworks seen: mcp

## Findings

### M001 · HIGH · get_sql_profile runs the caller's SQL with the security validator skipped (and on the global high-privilege pool)
`None:None` · ASI02 Tool Misuse and Exploitation

get_auth_context() reads a ContextVar that nothing ever sets (set_auth_context has no callers; main.py sets the different security.mcp_auth_context_var), so auth_context is None and DorisConnection.execute skips validate_sql_security; calling get_sql_profile with sql='DROP TABLE x' (or any INSERT/DELETE/GRANT) and catalog_name='internal' executes it unchecked. The connection also comes from the global pool (get_connection("query")), so token-bound lower-privilege DB users are bypassed.
> `doris_mcp_server/tools/tools_manager.py:1565` — `sql = arguments.get("sql")`
> `doris_mcp_server/utils/analysis_tools.py:557` — `auth_context = get_auth_context()`
> `doris_mcp_server/utils/sql_security_utils.py:33` — `auth_context_var: ContextVar = ContextVar('mcp_auth_context', default=None)`

**Fix:** Read mcp_auth_context_var (or delete the duplicate ContextVar), make DorisConnection.execute always validate (build a default AuthContext when none is set instead of skipping), allow only SELECT/WITH in get_sql_profile, and use the per-token pool via execute_query.

### M002 · HIGH · exec_query runs model-written SQL guarded only by a keyword blocklist, as Doris root by default
`None:None` · ASI02 Tool Misuse / ASI05 Unexpected Code Execution

Arbitrary SQL from the tool argument is executed after a blocklist (DROP/CREATE/ALTER/.../KILL) and regex checks, which the review guide treats as not a working guard; statements outside the list (e.g. SET GLOBAL, ADMIN SET ... CONFIG, SELECT ... INTO OUTFILE / EXPORT to remote storage) are not blocked, and the default DB user is root.
> `doris_mcp_server/tools/tools_manager.py:1465` — `sql = arguments.get("sql")`
> `doris_mcp_server/utils/config.py:126` — `blocked_keywords: list[str] = field(`
> `doris_mcp_server/utils/config.py:44` — `user: str = "root"`

**Fix:** Connect exec_query with a dedicated Doris user that has only SELECT on the intended databases; switch to an allowlist (single SELECT/WITH/SHOW/DESCRIBE statement, parsed) rather than a blocklist; require client approval for this tool.

### M003 · MEDIUM · All MCP request headers, including Authorization tokens, are logged at INFO
`None:None` · 

Every HTTP MCP request writes its raw headers (Authorization bearer token, cookies) to the log, so anyone with log access can replay any client's token.
> `doris_mcp_server/main.py:629` — `headers = dict(scope.get("headers", []))`
> `doris_mcp_server/main.py:631` — `self.logger.info(f"MCP Request - Headers: {headers}")`

**Fix:** Remove the header dump or redact authorization/cookie/x-api-key before logging; log at DEBUG at most.

### F008 · MEDIUM · SECRET-IN-CODE
`tokens.json:8` · ASI03 Identity and Privilege Abuse

The repo ships a tokens.json with a predictable, publicly known admin token (masked dori…56) that the TokenManager loads by default from the working directory; anyone who enables ENABLE_TOKEN_AUTH without replacing the file accepts a token every reader of the repo knows. It is bound to the Doris root user with an empty password.
> `tokens.json:7` — `"token_id": "admin-token",`
> `doris_mcp_server/auth/token_manager.py:160` — `with open(self.token_file_path, 'r') as f:`

**Fix:** Do not ship tokens.json; ship tokens.json.example, refuse to start if a known default token is present, and generate random tokens at setup. Rotate any deployed copy.

### F009 · MEDIUM · SECRET-IN-CODE
`tokens.json:24` · ASI03 Identity and Privilege Abuse

Second well-known default token (masked dori…56) in the shipped tokens.json, also mapped to Doris root.
> `tokens.json:23` — `"token_id": "analyst-token",`
> `tokens.json:31` — `"user": "root",`

**Fix:** Same as F008: remove from repo, generate per deployment, rotate.

### F010 · MEDIUM · SECRET-IN-CODE
`tokens.json:40` · ASI03 Identity and Privilege Abuse

Third well-known default token (masked dori…56); despite its 'readonly' name it is bound to the Doris root user, so a holder is not read-only at the database level.
> `tokens.json:39` — `"token_id": "readonly-token",`
> `tokens.json:47` — `"user": "root",`

**Fix:** Remove from repo; bind read-only tokens to a Doris user with only SELECT grants; rotate.

## Dismissed as false alarms

- F001 SECRET-IN-CODE `doris_mcp_server/auth/oauth_types.py:166` — Public Google OAuth endpoint URL, not a secret.
- F002 SECRET-IN-CODE `doris_mcp_server/auth/oauth_types.py:167` — Public Google OAuth token endpoint URL, not a secret.
- F003 SECRET-IN-CODE `doris_mcp_server/auth/oauth_types.py:177` — Public Microsoft identity platform endpoint URL, not a secret.
- F004 SECRET-IN-CODE `doris_mcp_server/auth/oauth_types.py:178` — Public Microsoft token endpoint URL, not a secret.
- F005 SECRET-IN-CODE `test/test_config.json:41` — Placeholder test fixture value in test config (valid_token/admin_token/invalid_token for unit tests), not a real credential.
- F006 SECRET-IN-CODE `test/test_config.json:42` — Placeholder test fixture token, not a real credential.
- F007 SECRET-IN-CODE `test/test_config.json:43` — Deliberately invalid test token, not a credential.
- F011 AUTH-BYPASS `doris_mcp_server/auth/jwt_manager.py:380` — decode_token_unsafe is only used by get_token_info, which nothing in the code calls; real JWT validation goes through validate_token with jwt_verify_signature defaulting to True. Not an auth bypass today, but a footgun.

## Needs information from you

- M004 AUTH `None:None` — With all auth switches off (the default), every HTTP caller gets an anonymous context and can use exec_query/get_sql_profile against the configured (root by default) Doris connection. Impact depends on whether HTTP mode is used and which host it binds to (docs show --host 0.0.0.0).

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
