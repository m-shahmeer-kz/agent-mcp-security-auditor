# Agent & MCP security report

Scanned: `/tmp/blind/c12` · 2026-11-23T20:36:13+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 3 | 4 | 2 | 0 | 0 | 1 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **0** · agent/MCP code files: **0** · agent instruction files: **0**
- Frameworks seen: none detected

## Findings

### M001 · HIGH · Postgres execute_select_query pastes raw clauses into SQL; read-only is only a keyword blocklist
`None:None` · ASI02 Tool Misuse and Exploitation

Every clause argument is interpolated into the SQL text and the only 'SELECT only' guard checks the first word of select_clause, so an injected caller can read any table/schema the connection user can (e.g. pg_shadow, other tenants' rows), run data-modifying CTEs in with_clause and call side-effect functions (pg_terminate_backend, pg_read_file, dblink) with the connection's privileges.
> `toolkits/postgres/arcade_postgres/tools/postgres.py:80` — `where_clause: Annotated[`
> `toolkits/postgres/arcade_postgres/database_engine.py:159` — `parts.append(f"WITH {with_clause}")`
> `toolkits/postgres/arcade_postgres/database_engine.py:160` — `parts.append(f"SELECT {select_clause} FROM {from_clause}")  # noqa: S608`

**Fix:** Connect with a dedicated read-only role limited to the intended schemas and run each query in a READ ONLY transaction (SET TRANSACTION READ ONLY) with a statement_timeout; validate identifiers against the discovered table list instead of a keyword blocklist.

### M002 · HIGH · ClickHouse query tools interpolate raw clauses and identifiers with no readonly setting
`None:None` · ASI02 Tool Misuse and Exploitation

from_clause/table_name go straight into the query and the client is created without readonly settings, so a caller can read every database the user can and use ClickHouse table functions such as url('http://169.254.169.254/...') or file()/remote() to make the DB server fetch internal URLs or files (subject to server settings).
> `toolkits/clickhouse/arcade_clickhouse/tools/clickhouse.py:72` — `from_clause: Annotated[`
> `toolkits/clickhouse/arcade_clickhouse/database_engine.py:189` — `parts.append(f"SELECT {select_clause} FROM {from_clause}")  # noqa: S608`
> `toolkits/clickhouse/arcade_clickhouse/tools/clickhouse.py:288` — `result = client.query(formatted_query)`

**Fix:** Create the client with settings={'readonly': 1} and a DB user without URL/file/remote table-function grants; check database/table names against the discovered list and quote them with backticks.

### M004 · HIGH · /mcp HTTP endpoint has no authentication and no Origin/Host check
`None:None` · 

Unlike /worker/* (JWT), /mcp accepts any caller and request header validation only checks the session id, so anything that can reach the port (other users on a 0.0.0.0 bind, or a web page via DNS rebinding against 127.0.0.1) can call every tool with the server's configured secrets and OAuth tokens.
> `libs/arcade-mcp-server/arcade_mcp_server/worker.py:205` — `app.mount("/mcp", _MCPASGIProxy(app), name="mcp-proxy")`
> `libs/arcade-mcp-server/arcade_mcp_server/transports/http_streamable.py:647` — `return await self._validate_session(request, send)`

**Fix:** Require authentication on /mcp (bearer token or the same worker JWT), validate Origin and Host against an allowlist (localhost only by default), and refuse to bind to non-loopback addresses without auth configured.

### M003 · MEDIUM · MongoDB aggregate tool uses a blocklist that misses server-side JavaScript
`None:None` · ASI02 Tool Misuse and Exploitation

Only $out/$merge/$where and update operators are blocked; $function/$accumulator (server-side JS) and $lookup/$unionWith into any collection pass, and database_name is caller-chosen, so the tool can read any database the connection user can and run JS on the server.
> `toolkits/mongodb/arcade_mongodb/tools/mongodb.py:238` — `pipeline: Annotated[`
> `toolkits/mongodb/arcade_mongodb/tools/utils.py:138` — `"$merge",  # These stages write to collections`
> `toolkits/mongodb/arcade_mongodb/tools/mongodb.py:288` — `cursor = collection.aggregate(pipeline_with_limit)`

**Fix:** Use a MongoDB user with the read role on the intended database only, disable server-side scripting (security.javascriptEnabled: false), and allowlist pipeline stages/operators instead of blocklisting.

### M005 · MEDIUM · Worker secret written to logs on every bad JWT
`None:None` · 

Any unauthenticated request with a badly signed JWT makes the server log the HS256 worker secret in clear text; whoever can read logs can then mint valid worker tokens and call tools.
> `libs/arcade-serve/arcade_serve/core/auth.py:33` — `"Invalid signature. Is the Arcade Engine configured with the Worker secret '%s'?",`
> `libs/arcade-serve/arcade_serve/core/auth.py:34` — `worker_secret,`

**Fix:** Remove the secret from the log message (log only that the signature was invalid); rotate any worker secret that has appeared in logs.

### M006 · MEDIUM · docker-compose publishes Redis on all interfaces with an empty password
`None:None` · ASI03 Identity and Privilege Abuse

Following the example config exposes an unauthenticated Redis (used by the engine) on every host interface, letting anyone on the network read or alter its data.
> `docker/docker-compose.yml:34` — `- "6379:6379"`
> `docker/env.example:44` — `REDIS_PASSWORD=""`

**Fix:** Do not publish 6379 (keep Redis on the internal network) or bind it to 127.0.0.1, and set a strong REDIS_PASSWORD.

### M008 · MEDIUM · Bright Data scrape returns arbitrary web pages raw to the model
`None:None` · 

Scraped page markdown goes into the model context unmarked; when this toolkit is served together with the GitHub/Slack/DB toolkits, text on a page can steer the model to read private data and send it out.
> `toolkits/brightdata/arcade_brightdata/tools/bright_data_tools.py:57` — `url: Annotated[str, "URL to scrape"],`
> `toolkits/brightdata/arcade_brightdata/tools/bright_data_tools.py:71` — `return client.make_request(payload)`

**Fix:** Mark scraped content as untrusted data in the result and avoid serving web-scraping tools in the same server as write/send tools without client approval.

### M007 · LOW · Example env ships guessable worker/root secrets
`None:None` · ASI03 Identity and Privilege Abuse

These are placeholders, not leaked keys, but a deployment that copies env.example to .env gets a worker secret of 'dev', which lets anyone forge worker JWTs.
> `docker/env.example:50` — `ARCADE_WORKER_SECRET=dev`
> `docker/env.example:51` — `ROOT_KEY_1=supersecret`

**Fix:** Leave the values empty in env.example and make the server refuse to start with a known default secret.

### M009 · LOW · Generated API wrappers put path arguments into URLs without encoding
`None:None` · ASI02 Tool Misuse and Exploitation

Values like `../../user/keys` or ones containing `?`/`#` change which endpoint on the same API host is called with the user's token; the host itself is fixed by operator secrets, so the impact is limited to the token's scopes.
> `toolkits/github_api/arcade_github_api/tools/__init__.py:16798` — `file_path: Annotated[str, "The file path in the repository to be deleted. This path is case-sensitive."],`
> `toolkits/github_api/arcade_github_api/tools/__init__.py:16816` — `url="{git_server_url}/repos/{owner}/{repo}/contents/{path}".format(git_server_url=context.get_secret("GIT_SERVER_URL"), owner=repository_owner, repo=repository_name, path=file_path),`

**Fix:** URL-encode each path parameter in the generator (urllib.parse.quote(value, safe='')) and reject values containing '/' unless the parameter is meant to be a path.

## Needs information from you

- M010 NO-APPROVAL `None:None` — Tools such as delete_github_repository (and similar delete/send/pay tools across the generated toolkits) act immediately; whether a human approves them depends on the MCP client, which is not in this repo.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
