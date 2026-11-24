# Agent & MCP security report

Scanned: `/tmp/blind/c04` · 2026-11-23T20:52:36+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 1 | 4 | 2 | 0 | 11 | 1 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **94** · agent/MCP code files: **39** · agent instruction files: **11**
- Frameworks seen: FastMCP, anthropic, mcp, modelcontextprotocol, openai

## Findings

### M001 · HIGH · Agent can add any GitHub repo to HACS and install it - arbitrary Python runs inside Home Assistant
`None:None` · ASI02 Tool Misuse / ASI05 Unexpected Code Execution

A prompt-injected agent can call ha_hacs_add_repository('attacker/repo', category='integration'), then ha_hacs_download and ha_restart; the attacker's custom integration is Python that Home Assistant imports with full access to the host, all tokens and devices. The only check is that repository contains '/', and there is no human approval in the server.
> `src/ha_mcp/tools/tools_hacs.py:564` — `repository: str,`
> `src/ha_mcp/tools/tools_hacs.py:640` — `"hacs/repositories/add",`
> `src/ha_mcp/tools/tools_hacs.py:781` — `response = await ws_client.send_command("hacs/repository/download", **download_kwargs)`

**Fix:** Disable custom-repository add/download by default behind an explicit feature flag, restrict to HACS default-store repositories or an operator allowlist, and require out-of-band human confirmation before installing integrations/python_scripts.

### M002 · MEDIUM · python_transform runs model-written Python with exec() behind an AST filter and no time limit
`None:None` · ASI05 Unexpected Code Execution

The tool argument is executed in-process; the only protection is an AST allowlist plus empty __builtins__, which the review guide treats as insufficient. The method allowlist is already bypassable by aliasing (`f = config.copy; f()` is a Name call, not an attribute call), and `while True: pass` or `'a' * 10**10`-style input blocks the event loop or exhausts memory, taking the whole MCP server down. No escape to code execution was demonstrated in this review.
> `src/ha_mcp/tools/tools_config_dashboards.py:734` — `transformed_config = safe_execute(python_transform, current_config)`
> `src/ha_mcp/utils/python_sandbox.py:244` — `exec(expr, safe_globals, safe_locals)`
> `src/ha_mcp/utils/python_sandbox.py:234` — `"__builtins__": {},`

**Fix:** Replace exec with a declarative patch format (JSON Patch / jq already offered), or run the transform in a separate process with a CPU/memory/time limit; at minimum add a timeout and forbid While.

### M003 · MEDIUM · ha_write_file writes model-chosen content into www/, which Home Assistant serves unauthenticated on its own origin
`None:None` · ASI02 Tool Misuse and Exploitation

Files in www/ are served at /local/ without authentication from the same origin as the HA frontend, so an injected call can drop an HTML/JS page that steals the admin's stored HA tokens when opened, or copy private data into a publicly readable URL as an exfiltration channel. Gated by HAMCP_ENABLE_FILESYSTEM_TOOLS (off by default).
> `src/ha_mcp/tools/tools_filesystem.py:339` — `async def ha_write_file(`
> `custom_components/ha_mcp_tools/const.py:7` — `ALLOWED_WRITE_DIRS = ["www", "themes", "custom_templates"]`
> `custom_components/ha_mcp_tools/__init__.py:403` — `await hass.async_add_executor_job(target_file.write_text, content)`

**Fix:** Disallow writing .html/.js/.svg (or any executable content type) to www/, or write to a non-served directory; require human confirmation for writes.

### M004 · MEDIUM · OAuth access tokens are unsigned base64 JSON containing the user's HA long-lived token, with no expiry
`None:None` · 

verify_token accepts any bearer that base64-decodes to {"ha_token": ...} and forwards that value to Home Assistant, so the MCP-layer OAuth adds no authentication of its own (HA is the only check), and every MCP client/log that holds the access token holds the raw HA admin token forever; revoking the OAuth grant does nothing.
> `src/ha_mcp/auth/provider.py:145` — `No encryption or signing - credentials are readable but transmitted over HTTPS.`
> `src/ha_mcp/auth/provider.py:669` — `ha_token = self._decode_credentials(token)`
> `src/ha_mcp/auth/provider.py:679` — `expires_at=None,  # Stateless tokens don't expire`

**Fix:** Issue opaque random access tokens (or signed+encrypted JWTs with exp and audience) and keep the HA token server-side, encrypted at rest; enforce expiry and revocation.

### F006 · MEDIUM · NETWORK-EXPOSURE
`homeassistant-addon/start.py:153` · ASI03 Identity and Privilege Abuse

The add-on serves the full admin toolset (Supervisor token) over plain HTTP on every host interface; the only protection is a secret URL path, which is sent in clear text on the LAN, is printed to the add-on log, and can be replaced by a weak user-chosen secret_path.
> `homeassistant-addon/start.py:155` — `host="0.0.0.0",`
> `homeassistant-addon/start.py:157` — `path=secret_path,`
> `homeassistant-addon/config.yaml:20` — `host_network: true`

**Fix:** Bind to the internal add-on network or 127.0.0.1 unless remote access is enabled, require a bearer token header (not a URL path) and enforce a minimum entropy for custom secret_path; use HTTPS/ingress for remote access.

### M006 · LOW · Secret URL path (the only auth for the add-ons) is written to the add-on logs
`None:None` · 

Anyone who can read add-on logs (other HA admins, diagnostics/bug-report dumps, support pastes) gets the credential that unlocks the full admin MCP server; the proxy even discovers the secret by scraping these logs.
> `homeassistant-addon/start.py:136` — `log_info(f"   Secret Path: {secret_path}")`
> `homeassistant-addon-webhook-proxy/start.py:628` — `log_info(f"  MCP target (local): {target_url}")`

**Fix:** Show the URL once in the add-on UI/ingress page instead of logs, mask it in log output, and use a header token rather than a path secret.

### M007 · LOW · Containment check uses string startswith without a separator
`None:None` · ASI02 Tool Misuse and Exploitation

A symlink inside www/, themes/ or custom_templates/ that resolves to a sibling such as /config-backup still passes the check, and writes use the unresolved path afterwards (TOCTOU). Exploitation needs an existing symlink, so this is hardening.
> `custom_components/ha_mcp_tools/__init__.py:361` — `rel_path = call.data["path"]`
> `custom_components/ha_mcp_tools/__init__.py:100` — `return str(resolved).startswith(str(config_resolved))`
> `custom_components/ha_mcp_tools/__init__.py:376` — `target_file = config_dir / rel_path`

**Fix:** Use resolved.is_relative_to(config_resolved / allowed_dir) and open with O_NOFOLLOW (or re-resolve immediately before the write).

## Dismissed as false alarms

- F001 SECRET-IN-CODE `src/ha_mcp/config.py:19` — Deliberately published token for the project's public demo instance (whose login is also public and which resets weekly); it grants nothing private. Still make sure it is never the fallback for a real deployment.
- F002 TOOL-POISONING `src/ha_mcp/tools/tools_labels.py:108` — Ordinary usage guidance explaining how to apply the label the user just created; it does not ask for secrets, hidden steps or overriding arguments.
- F003 TOOL-POISONING `src/ha_mcp/tools/tools_search.py:148` — Ordinary usage guidance (read-only overview call to scope the user's own search); not a hidden or manipulative instruction.
- F004 TOOL-POISONING `src/ha_mcp/tools/tools_system.py:54` — Safety guidance that serves the user (validate config before restarting); it reduces risk rather than redirecting actions.
- F005 SECRET-IN-CODE `tests/.env.test:10` — Token for the throw-away Home Assistant test container built from tests/initial_test_state; it is not valid for any real instance.
- F007 SSRF `src/ha_mcp/tools/tools_camera.py:94` — The request goes to a relative path on the operator-configured Home Assistant base URL with the same token the other tools already use; the model cannot choose the host, so this is not SSRF.
- F008 SSRF `src/ha_mcp/tools/tools_config_dashboards.py:1376` — card_type must be in a bundled allowlist and the host is a fixed raw.githubusercontent.com base URL.
- F009 SSRF `src/ha_mcp/tools/tools_updates.py:587` — Host is fixed to api.github.com and the components come from an anchored github.com regex over the update entity's release_url, not from a free tool argument; no internal address can be reached.
- F010 SSRF `src/ha_mcp/tools/tools_updates.py:627` — Fixed public host (raw.githubusercontent.com) with path parts from the same anchored github.com regex; not SSRF.
- F011 SSRF `src/ha_mcp/tools/tools_updates.py:672` — Host and repository are fixed; only the version tag (taken from Home Assistant's update entity) varies.
- F012 SSRF `src/ha_mcp/tools/tools_utility.py:473` — The host is fixed to raw.githubusercontent.com; the domain argument only changes the path on that public host, so internal services cannot be reached.

## Needs information from you

- M005 TOXIC-FLOW `None:None` — Tools return third-party text (GitHub/blog release notes, HACS repo info, calendar and to-do items from external accounts) unmarked to the model, the same server exposes cameras, history and config, and ha_call_service can invoke any HA service including notify/rest_command, so injected text can make the agent send private data out. Whether that is reachable depends on which integrations the user has; the server itself has no approval gate.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
