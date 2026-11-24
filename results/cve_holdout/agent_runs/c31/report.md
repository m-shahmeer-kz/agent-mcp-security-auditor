# Agent & MCP security report

Scanned: `/tmp/blind/c31` · 2026-11-23T20:42:14+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 1 | 1 | 1 | 0 | 0 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **4** · agent/MCP code files: **1** · agent instruction files: **0**
- Frameworks seen: modelcontextprotocol

## Findings

### M001 · HIGH · Private-address block checks only the literal hostname; DNS names, redirects and bracketed IPv6 bypass it
`None:None` · ASI02 Tool Misuse and Exploitation

The check runs on the URL's hostname string only: a domain that resolves to 127.0.0.1/169.254.169.254 (e.g. a wildcard DNS name or 'localhost.'), a public URL that 302-redirects to an internal address (fetch follows redirects by default), or a bracketed IPv6 host such as http://[::1]/ all pass, so a prompt-injected fetch reaches localhost services or cloud metadata and the response is returned to the model.
> `src/index.ts:142` — `const validatedArgs = RequestPayloadSchema.parse(args);`
> `src/Fetcher.ts:22` — `if (hostname === 'localhost' || is_ip_private(hostname)) {`
> `src/Fetcher.ts:27` — `const response = await fetch(url, {`

**Fix:** Resolve the hostname (dns.lookup all addresses), reject loopback/private/link-local/unique-local/IPv4-mapped ranges on the resolved IPs and connect to the checked IP (custom undici dispatcher/lookup), set redirect: 'manual' and re-validate each Location hop, and strip brackets before checking IPv6.

### M002 · MEDIUM · Fetched web content returned unmarked into the model context
`None:None` · 

Arbitrary web pages are returned verbatim as tool output with nothing marking them as untrusted data; this is the main path by which injected instructions reach an agent, and the same tools (any URL, caller-set headers) give that agent a way to send data out in the query string.
> `src/Fetcher.ts:60` — `return { content: [{ type: "text", text: html }], isError: false };`
> `src/Fetcher.ts:143` — `return { content: [{ type: "text", text: markdown }], isError: false };`

**Fix:** Wrap results in a clearly delimited untrusted-content block and tell the host to require approval for follow-up actions; consider a domain allowlist option.

### M003 · LOW · Whole response body is downloaded before max_length is applied
`None:None` · 

max_length only truncates after the full body is read into memory (and parsed by JSDOM for fetch_txt), and there is no request timeout, so a huge or never-ending response can exhaust memory or hang the server.
> `src/Fetcher.ts:51` — `let html = await response.text();`
> `src/Fetcher.ts:13` — `return text.substring(startIndex, end);`

**Fix:** Stream the body and stop after a byte cap (e.g. 5 MB), and pass an AbortSignal.timeout() to fetch.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
