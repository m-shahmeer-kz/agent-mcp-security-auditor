# Agent & MCP security report

Scanned: `/tmp/blind/c37` · 2026-11-23T20:47:57+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 1 | 3 | 1 | 0 | 3 | 2 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **20** · agent/MCP code files: **27** · agent instruction files: **9**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · HIGH · server_url on every CKAN tool reaches internal hosts and the response body is echoed back
`None:None` · ASI02 Tool Misuse and Exploitation

server_url is attacker-controlled on every CKAN tool. The guard is a literal-hostname blocklist with no DNS resolution, and axios follows redirects without re-checking, so http://<name resolving to 169.254.169.254>/... or an external URL redirecting to an internal service is fetched; any non-CKAN response body is returned verbatim in the error text, giving full-read SSRF (e.g. cloud metadata credentials) when the server runs in Node/HTTP mode.
> `src/tools/package.ts:603` — `server_url: z.string()`
> `src/utils/http.ts:245` — `validateServerUrl(serverUrl);`
> `src/utils/http.ts:267` — `const response = await axios.get(url, {`

**Fix:** In makeCkanRequest: resolve the host and reject private/loopback/link-local/unique-local results (use a custom lookup/agent so the checked IP is the one connected to), set maxRedirects: 0 or re-validate each redirect, and do not echo raw response bodies in errors.

### F004 · MEDIUM · SSRF
`src/tools/sparql.ts:70` · ASI02 Tool Misuse and Exploitation

endpoint_url is a tool argument; validateServerUrl only checks literal IPs/'localhost' in the hostname, never resolves DNS and fetch follows redirects, so a hostname that resolves to 10.x/169.254.169.254 or an https URL that 302-redirects to an internal address passes. Readback is limited (body must parse as SPARQL JSON; status text is echoed), hence medium.
> `src/tools/sparql.ts:175` — `endpoint_url: z.string().url().describe("HTTPS URL of the SPARQL endpoint"),`
> `src/tools/sparql.ts:70` — `response = await fetch(getUrl.toString(), {`
> `src/utils/http.ts:199` — `const ipv4 = hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);`

**Fix:** Resolve the hostname and reject private/loopback/link-local results (pin the resolved IP for the request), set redirect: 'manual' and re-validate each hop, or restrict endpoint_url to an allowlist of known SPARQL hosts.

### F005 · MEDIUM · SSRF
`src/tools/sparql.ts:76` · ASI02 Tool Misuse and Exploitation

Same sink as F004 (POST variant): attacker-chosen endpoint_url, guard bypassable via DNS names pointing at internal IPs or redirects; the POST body (query) is also attacker-chosen.
> `src/tools/sparql.ts:192` — `const data = await querySparqlEndpoint(params.endpoint_url, limitedQuery);`
> `src/tools/sparql.ts:76` — `response = await fetch(endpointUrl, {`

**Fix:** Same as F004: DNS-resolve-and-block plus manual redirect handling, or a host allowlist.

### F006 · MEDIUM · SSRF
`src/tools/sparql.ts:86` · ASI02 Tool Misuse and Exploitation

GET fallback of the same request as F004/F005; same bypassable guard.
> `src/tools/sparql.ts:192` — `const data = await querySparqlEndpoint(params.endpoint_url, limitedQuery);`
> `src/tools/sparql.ts:86` — `response = await fetch(getUrl.toString(), {`

**Fix:** Same as F004.

### M003 · LOW · Third-party portal content returned to the model unmarked
`None:None` · 

Dataset titles/descriptions and raw responses from any portal the model is pointed at flow straight into the model context; a malicious portal can inject instructions (e.g. to call sparql_query/server_url with internal targets). Impact is bounded because all tools are read-only.
> `src/utils/http.ts:333` — ``CKAN API returned success=false: ${JSON.stringify(decodedData)}``

**Fix:** Mark tool output as untrusted data and strip or truncate free-text fields from unknown portals.

## Dismissed as false alarms

- F001 HIDDEN-INSTRUCTIONS `skills/ckan-mcp/SKILL.md:291` — 'SSN' here is the W3C Semantic Sensor Network ontology, not a social security number; the curl/URL lines are documented example queries to a public ontology search API. Ordinary usage guidance, no hidden steering.
- F002 TOOL-POISONING `src/tools/portal-discovery.ts:90` — The description only explains how to use this tool and suggests a normal workflow (find portal, then status_show, then package_search) that serves the user's own request; nothing hidden, no data sent elsewhere, no argument override.
- F003 HIDDEN-INSTRUCTIONS `.claude/commands/astro_website.md:140` — The HTML comment is part of a sample Astro page layout inside a code block (a section label before og: meta tags), not an instruction to the model.

## Needs information from you

- F007 CORS-WILDCARD `src/worker.ts:285` — The Cloudflare worker is a public, unauthenticated, read-only demo that uses no cookies or user credentials, so a wildcard CORS mostly lets other sites use the shared quota and its SSRF (see M001). Acceptable only if this instance is meant to be public.
- M002 NETWORK-EXPOSURE `None:None` — app.listen(port) without a host binds 0.0.0.0 and /mcp has no auth or Origin check, so anyone who can reach the port (or a web page via DNS rebinding) can drive the tools, including the SSRF in M001, from inside the server's network. Severity depends on where it is deployed.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
