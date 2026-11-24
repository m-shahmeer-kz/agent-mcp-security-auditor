# Agent & MCP security report

Scanned: `/tmp/blind/c01` · 2026-11-23T20:43:24+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 1 | 4 | 1 | 0 | 3 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **20** · agent/MCP code files: **27** · agent instruction files: **9**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · HIGH · server_url on every CKAN tool reaches any host/scheme, and the response body is echoed back in the error
`None:None` · ASI02 Tool Misuse and Exploitation

server_url is only checked with z.string().url(), so http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>? (the trailing '?' turns the appended /api/3/action path into a query string) makes the Node server fetch cloud metadata or any internal URL, following redirects, and the non-CKAN body is returned verbatim to the model in the 'success=false' error text.
> `src/tools/package.ts:1117` — `params.server_url,`
> `src/utils/http.ts:202` — `const url = `${baseUrl}${apiPath}/${action}`;`
> `src/utils/http.ts:208` — `const response = await axios.get(url, {`

**Fix:** Require https, resolve the hostname and reject private/loopback/link-local/IPv6-local addresses (or restrict to portals.json / datashades hosts), set maxRedirects: 0 or re-validate each hop, and do not include the raw response body in error messages.

### M002 · MEDIUM · Node HTTP transport has no authentication, no Origin/Host check and listens on all interfaces
`None:None` · ASI03 Identity and Privilege Abuse

With TRANSPORT=http anyone on the network (or a DNS-rebinding web page) can call every tool without credentials, turning the M001/F003 SSRF into an open proxy into the host's internal network.
> `src/transport/http.ts:23` — `app.post('/mcp', async (req, res) => {`
> `src/transport/http.ts:28` — `app.listen(port, () => {`

**Fix:** Bind to 127.0.0.1 by default (app.listen(port, '127.0.0.1')), validate Host/Origin headers, and require a bearer token when exposed beyond localhost.

### F003 · MEDIUM · SSRF
`src/tools/sparql.ts:68` · ASI02 Tool Misuse and Exploitation

endpoint_url is any HTTPS URL (only the scheme is checked), so a steered sparql_query call makes the server send GET/POST requests with attacker-chosen body to internal HTTPS hosts (localhost, intranet); the status code is echoed back and SPARQL-shaped JSON is returned in full.
> `src/tools/sparql.ts:190` — `const data = await querySparqlEndpoint(params.endpoint_url, limitedQuery);`
> `src/tools/sparql.ts:68` — `response = await fetch(getUrl.toString(), {`

**Fix:** Allowlist SPARQL endpoint hosts (e.g. those in portals.json) or resolve the host and reject private/loopback/link-local addresses, and disable redirects (redirect: 'manual') or re-check each hop.

### F004 · MEDIUM · SSRF
`src/tools/sparql.ts:74` · ASI02 Tool Misuse and Exploitation

Same sink as F003 (POST branch): an attacker-chosen HTTPS URL receives a POST with the attacker-chosen query as body.
> `src/tools/sparql.ts:190` — `const data = await querySparqlEndpoint(params.endpoint_url, limitedQuery);`
> `src/tools/sparql.ts:74` — `response = await fetch(endpointUrl, {`

**Fix:** Same as F003: host allowlist or private-address block after DNS resolution, no blind redirect following.

### F005 · MEDIUM · SSRF
`src/tools/sparql.ts:84` · ASI02 Tool Misuse and Exploitation

Same sink as F003 (GET fallback after 403/405).
> `src/tools/sparql.ts:190` — `const data = await querySparqlEndpoint(params.endpoint_url, limitedQuery);`
> `src/tools/sparql.ts:84` — `response = await fetch(getUrl.toString(), {`

**Fix:** Same as F003.

### M003 · LOW · Third-party portal content is returned to the model unmarked
`None:None` · 

Dataset titles/descriptions from any CKAN portal (which anyone can publish to, and server_url can be any host) are inserted into the model context as plain markdown, so injected instructions there can steer later tool calls (e.g. into the M001 SSRF). Tools are read-only, which limits the impact.
> `src/tools/package.ts:1133` — `const markdown = formatPackageShowMarkdown(result, params.server_url);`
> `src/tools/package.ts:1135` — `content: [{ type: "text", text: truncateText(addDemoFooter(markdown)) }]`

**Fix:** Mark returned remote text as untrusted data (delimiters / structured fields only) and fix M001 so steered calls cannot reach internal hosts.

## Dismissed as false alarms

- F001 TOOL-POISONING `src/tools/portal-discovery.ts:90` — Ordinary usage guidance that serves the user's own request (translate the country name to English, suggested tool order); it does not override arguments, reach secrets, send data or hide anything from the user.
- F002 HIDDEN-INSTRUCTIONS `.claude/commands/astro_website.md:140` — The HTML comment is a plain section label inside an Astro/HTML code sample; it contains no instruction to the model.
- F006 CORS-WILDCARD `src/worker.ts:272` — The Cloudflare worker is an intentionally public, unauthenticated, cookie-less demo over public open data; a cross-origin page gains nothing it could not get by calling the endpoint directly. (The real exposure issue is the Node HTTP transport, see M002.)

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
