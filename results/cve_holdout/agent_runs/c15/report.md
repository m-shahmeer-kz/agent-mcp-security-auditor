# Agent & MCP security report

Scanned: `/tmp/blind/c15` · 2026-11-23T20:51:23+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 1 | 0 | 2 | 0 | 0 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **4** · agent/MCP code files: **1** · agent instruction files: **0**
- Frameworks seen: modelcontextprotocol

## Findings

### M001 · HIGH · Private-IP guard checks the whole URL string, so internal hosts and cloud metadata are reachable
`None:None` · ASI02 Tool Misuse and Exploitation

The url tool argument is passed whole (e.g. `http://169.254.169.254/latest/meta-data/`) to is_ip_private, which tests whether a string is a private IP, not the URL's host, so it does not match and the request goes out; hostnames like `localhost` or a DNS name pointing at 127.0.0.1 and redirects to internal addresses are never checked either. A prompt-injected call can read internal services and cloud metadata and return them to the model.
> `src/index.ts:142` — `const validatedArgs = RequestPayloadSchema.parse(args);`
> `src/Fetcher.ts:20` — `if (is_ip_private(url)) {`
> `src/Fetcher.ts:25` — `const response = await fetch(url, {`

**Fix:** Parse with new URL(url), allow only http/https, resolve the hostname (dns.lookup all addresses) and reject private/loopback/link-local/IPv6-local ranges, fetch with redirect: 'manual' and re-check each Location hop (or pin the resolved IP via a custom undici dispatcher).

### M002 · LOW · Fetched web content returned unmarked into the model context
`None:None` · 

Every tool returns arbitrary third-party page content verbatim to the model, which is how injected instructions on a web page reach the agent (and combined with M001 can steer it to internal URLs).
> `src/Fetcher.ts:58` — `return { content: [{ type: "text", text: html }], isError: false };`

**Fix:** Wrap returned content in clear untrusted-data delimiters and document that clients should not auto-approve follow-up actions based on fetched content.

### M003 · LOW · Whole response body is read into memory before max_length is applied
`None:None` · 

max_length only truncates after the full body is downloaded; a URL to a huge or endless response can exhaust memory or hang the server (no timeout either).
> `src/Fetcher.ts:49` — `let html = await response.text();`

**Fix:** Stream the body and stop after max_length+start_index bytes, and pass an AbortSignal.timeout() to fetch.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
