# Agent & MCP security report

Scanned: `/tmp/blind/c02` · 2026-11-23T21:08:37+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 3 | 2 | 1 | 1 | 10 | 1 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **94** · agent/MCP code files: **39** · agent instruction files: **11**
- Frameworks seen: FastMCP, anthropic, mcp, modelcontextprotocol, openai

## Findings

### M001 · HIGH · OAuth mode accepts unsigned, self-made bearer tokens and connects to the ha_url inside them (auth bypass + SSRF)
`None:None` · 

verify_token only base64-decodes JSON; there is no signature, expiry or check that the server issued it. Anyone can send Authorization: Bearer base64({"ha_url":"http://169.254.169.254","ha_token":"x"}) and every tool call makes the server send requests to that URL (internal services, the host's localhost) and return the responses. Tokens also carry the user's HA long-lived token in readable form and never expire.
> `src/ha_mcp/auth/provider.py:171` — `decoded = urlsafe_b64decode(token.encode()).decode()`
> `src/ha_mcp/auth/provider.py:750` — `ha_url, ha_token = credentials`
> `src/ha_mcp/__main__.py:62` — `ha_url = claims["ha_url"]`

**Fix:** Issue opaque random tokens (or signed+encrypted JWTs with exp and audience) and keep HA credentials server-side keyed by token; reject tokens the server did not issue; validate ha_url at consent time against an allowlist / block private and link-local ranges.

### M002 · HIGH · HTTP/SSE modes bind 0.0.0.0 on a default '/mcp' path with no authentication
`None:None` · ASI03 Identity and Privilege Abuse

main_web/main_sse run with the operator's HOMEASSISTANT_TOKEN from the environment, listen on every interface, and the default path is the well-known /mcp with no auth. Anyone on the network can call all tools (unlock doors, call any service, install HACS code).
> `src/ha_mcp/__main__.py:267` — `"host": "0.0.0.0",`
> `src/ha_mcp/__main__.py:554` — `path = os.getenv("MCP_SECRET_PATH", "/mcp")`

**Fix:** Default to 127.0.0.1, refuse to start on a public interface without a bearer token or a generated high-entropy secret path, and validate Origin/Host.

### M004 · HIGH · HACS add-repository + download lets any tool caller install arbitrary code into Home Assistant
`None:None` · 

A prompt-injected model can add an attacker's GitHub repo as a custom integration, download it and restart HA (ha_restart exists); custom integrations are Python that runs inside Home Assistant with full access. The only control is the advisory destructiveHint annotation; these tools load by default.
> `src/ha_mcp/tools/tools_hacs.py:563` — `async def ha_hacs_add_repository(`
> `src/ha_mcp/tools/tools_hacs.py:564` — `repository: str,`
> `src/ha_mcp/tools/tools_hacs.py:691` — `async def ha_hacs_download(`

**Fix:** Disable HACS write tools by default behind an explicit opt-in flag, require out-of-band human confirmation (MCP elicitation) for add/download/restart, and optionally restrict to an allowlist of repositories.

### M003 · MEDIUM · Model-written Python executed with exec() behind an AST filter
`None:None` · ASI05 Unexpected Code Execution

python_transform is executed in the server process; the guard is an AST allowlist plus empty __builtins__, which the review guide rates as insufficient. I found no escape in the allowed node set (dunders and getattr are blocked), but While loops and list multiplication are allowed, so `while True: pass` or `x=[0]*10**10` hangs or exhausts the server (sync exec inside the async handler).
> `src/ha_mcp/tools/tools_config_dashboards.py:456` — `python_transform: Annotated[`
> `src/ha_mcp/utils/python_sandbox.py:244` — `exec(expr, safe_globals, safe_locals)`
> `src/ha_mcp/utils/python_sandbox.py:236` — `"__builtins__": {},`

**Fix:** Replace exec with a declarative patch format (JSON Patch / jq, already supported), or run the transform in a separate process with CPU/memory/time limits.

### F006 · MEDIUM · NETWORK-EXPOSURE
`homeassistant-addon/start.py:153` · ASI03 Identity and Privilege Abuse

The add-on (host_network) serves MCP over plain HTTP on all interfaces with the Supervisor token behind it; the only protection is an unguessable URL path. The auto path has 128-bit entropy, but it is printed to the add-on log, sent in clear text on the LAN, and a user-chosen custom path is accepted with no strength check.
> `homeassistant-addon/start.py:155` — `host="0.0.0.0",`
> `homeassistant-addon/start.py:157` — `path=secret_path,`
> `homeassistant-addon/start.py:136` — `log_info(f"   Secret Path: {secret_path}")`

**Fix:** Require a bearer token (or HA auth) on the endpoint instead of a URL secret, enforce a minimum length/entropy for custom secret_path, avoid logging the full path, and recommend TLS / binding to the HA ingress network only.

### F001 · LOW · SECRET-IN-CODE
`src/ha_mcp/config.py:19` · ASI03 Identity and Privilege Abuse

A working long-lived Home Assistant token is committed on purpose for the public demo server (which also publishes mcp/mcp login and resets weekly). It grants nothing beyond the public demo, but anyone can drive that demo instance with it.
> `src/ha_mcp/config.py:19` — `DEMO_TOKEN`
> `src/ha_mcp/config.py:18` — `# Demo server: https://ha-mcp-demo-server.qc-h.net (login: mcp/mcp, resets weekly)`

**Fix:** Keep it only if the demo instance is meant to be public and isolated; otherwise remove it, rotate the token and fetch demo credentials at runtime.

### M006 · INFO · Third-party release notes and docs returned to the model unmarked
`None:None` · 

Release notes of any installed HACS/custom repo (author-controlled text) go straight into the model context of an agent that can also call services and install code (M004), giving a path for injected instructions.
> `src/ha_mcp/tools/tools_updates.py:599` — `return {"notes": str(body), "source": "github_api"}`
> `src/ha_mcp/tools/tools_updates.py:638` — `return {"notes": content, "source": "github_raw"}`

**Fix:** Mark returned notes as untrusted data and keep high-impact tools behind confirmation.

## Dismissed as false alarms

- F002 TOOL-POISONING `src/ha_mcp/tools/tools_labels.py:108` — Ordinary usage guidance for the user's own request (how to assign a label after creating it); it does not redirect actions, read secrets or hide anything.
- F003 TOOL-POISONING `src/ha_mcp/tools/tools_search.py:148` — Ordinary usage guidance (call a read-only overview tool first); serves the user's request, no hidden or manipulative instruction.
- F004 TOOL-POISONING `src/ha_mcp/tools/tools_system.py:54` — Safety guidance: validate config before restarting. It names another tool only to make the user's restart safer.
- F005 SECRET-IN-CODE `tests/.env.test:10` — Test fixture token for the throw-away Home Assistant container used in CI (the file says so and points to the bundled test auth store); it does not unlock a real instance.
- F007 SSRF `src/ha_mcp/tools/tools_camera.py:94` — Only a relative path is built and sent through the client configured with the Home Assistant base URL; the host cannot be changed, so this is not SSRF. At most a crafted entity_id reaches another GET endpoint of the same HA API that other tools already expose.
- F008 SSRF `src/ha_mcp/tools/tools_config_dashboards.py:1376` — card_type is checked against a bundled allowlist and appended to a fixed raw.githubusercontent.com base; the host cannot be chosen.
- F009 SSRF `src/ha_mcp/tools/tools_updates.py:587` — The release URL must match a github.com pattern and only owner/repo/tag (no slashes) are placed into a fixed api.github.com URL; no internal host is reachable.
- F010 SSRF `src/ha_mcp/tools/tools_updates.py:627` — Fixed host raw.githubusercontent.com with segments taken from a regex that excludes '/'; not SSRF.
- F011 SSRF `src/ha_mcp/tools/tools_updates.py:672` — Fixed host and repo (api.github.com/home-assistant/core); only the tag varies, so no internal service can be reached.
- F012 SSRF `src/ha_mcp/tools/tools_utility.py:473` — Fixed public host raw.githubusercontent.com; domain only changes the path on GitHub's CDN, so this cannot reach internal services.

## Needs information from you

- M005 NO-APPROVAL `None:None` — Path containment is checked (normpath + resolve, though with a prefix startswith), but www/ is served at /local/ on the Home Assistant origin, so an injected write of www/x.html with script can steal the HA session of whoever opens it. Feature is off by default (HAMCP_ENABLE_FILESYSTEM_TOOLS); impact depends on whether you enable it.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
