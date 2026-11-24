# Agent & MCP security report

Scanned: `/tmp/blind/c16` · 2026-11-23T21:08:24+00:00 · auditor vmanual (scan timed out after 15 min) · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 2 | 1 | 1 | 1 | 0 | 2 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **0** · agent/MCP code files: **0** · agent instruction files: **0**
- Frameworks seen: none detected

## Findings

### M001 · HIGH · Postgres execute_select_query pastes every clause into raw SQL; SELECT-only guard is a first-word blocklist
`None:None` · ASI02 Tool Misuse and Exploitation

select/from/where/join/with/order clauses are tool arguments interpolated straight into SQL; only the first word of select_clause is checked. An injected call can read any table or catalog the connection user can (e.g. from_clause='pg_shadow' or a subquery), call server functions (pg_read_file, dblink, pg_terminate_backend) and use data-modifying CTEs in with_clause; the connection is never committed, which limits but does not remove side effects.
> `toolkits/postgres/arcade_postgres/tools/postgres.py:59` — `async def execute_select_query(`
> `toolkits/postgres/arcade_postgres/database_engine.py:116` — `first_select_word = select_clause.strip().split(" ")[0].upper()`
> `toolkits/postgres/arcade_postgres/database_engine.py:159` — `parts.append(f"WITH {with_clause}")`

**Fix:** Run the tool with a dedicated read-only DB role (default_transaction_read_only=on, no superuser, only the intended tables); validate table/column names against the inspected schema and build the query with SQLAlchemy Core instead of string clauses; put filter values in bound parameters.

### M002 · HIGH · ClickHouse execute_select_query/get_table_schema interpolate arguments into SQL without a read-only setting
`None:None` · ASI02 Tool Misuse and Exploitation

Clauses and schema/table names from the tool call are pasted into the query; the client is created without readonly settings. A SELECT can use ClickHouse table functions (url(), file(), s3(), remote()) in from_clause, giving SSRF to internal services and local file reads, plus reads of any database the user can see.
> `toolkits/clickhouse/arcade_clickhouse/tools/clickhouse.py:66` — `async def execute_select_query(`
> `toolkits/clickhouse/arcade_clickhouse/database_engine.py:189` — `parts.append(f"SELECT {select_clause} FROM {from_clause}")`
> `toolkits/clickhouse/arcade_clickhouse/tools/clickhouse.py:288` — `result = client.query(formatted_query)`

**Fix:** Connect with a ClickHouse user that has readonly=1 (or pass settings={'readonly': 1}) and no table-function grants; validate identifiers against system.tables; pass values as server-side parameters.

### M003 · MEDIUM · MongoDB read-only blocklist misses $function/$accumulator (server-side JavaScript)
`None:None` · ASI05 Unexpected Code Execution

The pipeline comes from the tool call and is checked against a blocklist that only stops $where/$out/$merge and update operators; a stage such as {"$project": {"x": {"$function": {...}}}} with arbitrary JavaScript, or $accumulator, passes and runs inside mongod when server-side JS is enabled (CPU exhaustion / DoS). database_name is also free, so any database the connection can see is readable.
> `toolkits/mongodb/arcade_mongodb/tools/mongodb.py:238` — `pipeline: Annotated[`
> `toolkits/mongodb/arcade_mongodb/tools/utils.py:56` — `"$where",  # Can execute JavaScript`
> `toolkits/mongodb/arcade_mongodb/tools/mongodb.py:288` — `cursor = collection.aggregate(pipeline_with_limit)`

**Fix:** Use an allowlist of pipeline stages and operators, block $function/$accumulator/$unionWith/$lookup to other DBs, connect with a read-only MongoDB role limited to the intended database, and run mongod with javascriptEnabled=false.

### M005 · LOW · Worker secret written to logs on every bad-signature request
`None:None` · 

Any client sending a token with a wrong signature makes the server log the real worker secret in clear text; whoever reads the logs can then forge tokens.
> `libs/arcade-serve/arcade_serve/core/auth.py:33` — `"Invalid signature. Is the Arcade Engine configured with the Worker secret '%s'?",`
> `libs/arcade-serve/arcade_serve/core/auth.py:34` — `worker_secret,`

**Fix:** Log only that the signature was invalid (optionally a short hash of the secret), never the secret itself.

### M007 · INFO · Bright Data scrape returns raw web content to the model
`None:None` · 

Any page's markdown goes straight into the model context unmarked; text in it can steer later tool calls (e.g. the SQL or GitHub/Stripe wrapper tools if loaded in the same agent). Requests go through Bright Data's API, so this is not SSRF against the local network.
> `toolkits/brightdata/arcade_brightdata/tools/bright_data_tools.py:57` — `url: Annotated[str, "URL to scrape"],`
> `toolkits/brightdata/arcade_brightdata/tools/bright_data_tools.py:71` — `return client.make_request(payload)`

**Fix:** Wrap returned content as untrusted data (clear delimiters / a field like {'untrusted_content': ...}) and keep write-capable tools behind confirmation in agents that also load scraping tools.

## Needs information from you

- M004 AUTH `None:None` — If ARCADE_WORKER_SECRET is not set, the worker's HS256 JWT secret is the well-known string 'dev', so anyone who can reach the worker port can sign a token and list/invoke tools (the base worker refuses to start without a secret, but this path overrides that). The Docker image binds 0.0.0.0. Whether this is exploitable depends on how the port is exposed.
- M006 NETWORK-EXPOSURE `None:None` — Any client (or a web page via DNS rebinding against 127.0.0.1) can call /mcp without credentials. Impact is limited because tools that need secrets or OAuth are refused on non-stdio transports (server.py:801-803), so only secret-free tools are exposed; check whether your deployment adds tools without declared secrets that touch private data.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
