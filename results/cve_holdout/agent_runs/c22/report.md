# Agent & MCP security report

Scanned: `/tmp/blind/c22` · 2026-11-23T20:49:27+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 4 | 3 | 1 | 0 | 1 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **209** · agent/MCP code files: **40** · agent instruction files: **246**
- Frameworks seen: FastMCP, anthropic, mcp, modelcontextprotocol, openai

## Findings

### M001 · HIGH · saveVectorToFile writes to any path the model chooses (arbitrary file overwrite)
`None:None` · ASI02 Tool Misuse and Exploitation

file_path from the tool arguments is only path.resolve()d, parent directories are created and the file is overwritten, so `file_path: "~/.ssh/authorized_keys"`, `.bashrc` or any project/source file can be truncated and replaced with numbers (data destruction anywhere the server user can write). Same code ships in dist/mcp/server.js.
> `src/mcp/server.ts:1132` — `const filePath = params.file_path;`
> `src/mcp/server.ts:1275` — `fs.writeFileSync(absolutePath, content, 'utf8');`

**Fix:** Restrict writes to a dedicated output directory: resolve with fs.realpathSync on the parent, check path.relative(baseDir, p) does not start with '..' and is not absolute, refuse to overwrite existing files, and only accept .json/.csv/.txt names.

### M003 · HIGH · consciousness-explorer export_state / import_state read and write arbitrary paths
`None:None` · ASI02 Tool Misuse and Exploitation

filepath comes straight from tool arguments with no checks: export_state overwrites any writable file with JSON that includes attacker-supplied knowledge (from knowledge_add), and import_state reads any file and loads its knowledge/goals into the agent's state (memory poisoning; parse errors can leak file content).
> `src/consciousness-explorer/mcp/server.js:529` — `const state = await this.explorer.exportState(args.filepath);`
> `src/consciousness-explorer/index.js:288` — `fs.writeFileSync(filepath, JSON.stringify(state, null, 2));`
> `src/consciousness-explorer/mcp/server.js:546` — `await this.explorer.importState(args.filepath);`

**Fix:** Fix the state directory, accept only a bare file name matching ^[\w.-]+\.json$, join it to that directory and check containment after realpath; validate the imported state schema.

### F001 · HIGH · AUTO-APPROVE
`.claude/settings.json:12` · ASI09 Human-Agent Trust Exploitation

Any agent working in this repo may run `npx claude-flow <anything>` without asking: an unpinned package fetched from npm runs with the developer's rights, and its sub-commands include remote execution (CLAUDE_FLOW_REMOTE_EXECUTION is set to true in the same file).
> `.claude/settings.json:12` — `"Bash(npx claude-flow *)",`

**Fix:** Remove the wildcard allow; allow only the specific pinned sub-commands needed (e.g. `Bash(npx claude-flow@<exact-version> hooks pre-edit:*)`) or require approval.

### F002 · HIGH · AUTO-APPROVE
`.claude/settings.json:28` · ASI09 Human-Agent Trust Exploitation

`node -e '<any JS>'` is arbitrary code execution without approval, so a prompt injection in anything the agent reads can run code on the developer machine; `git config *` (e.g. core.fsmonitor / core.sshCommand) plus the allowed `git status`/`git push` is a second path to code execution and exfiltration. The deny list (`rm -rf /`, `eval *`) does not stop either.
> `.claude/settings.json:28` — `"Bash(node *)",`
> `.claude/settings.json:22` — `"Bash(git config *)",`

**Fix:** Remove `Bash(node *)` and `Bash(git config *)` from allow; allow only specific scripts (e.g. `Bash(node scripts/copy-wasm.js)`) and keep git config / push behind approval.

### M002 · MEDIUM · solveTrueSublinear vector_file reads any file on disk
`None:None` · ASI02 Tool Misuse and Exploitation

vector_file is resolved without any base-directory check, so the model can probe whether any file exists (the error echoes the absolute path) and read numeric content of any .json/.csv/.txt file (solving with an identity matrix returns b); JSON.parse errors can echo a snippet of the file.
> `src/mcp/server.ts:938` — `vector = await this.loadVectorFromFile(params.vector_file);`
> `src/mcp/server.ts:1184` — `const fileContent = fs.readFileSync(absolutePath, 'utf8');`

**Fix:** Only load vector files from the same dedicated data directory (realpath + containment check) and return a generic error without the path or parse snippet.

### M004 · MEDIUM · goalie search tool writes result files into any directory (outputPath)
`None:None` · ASI02 Tool Misuse and Exploitation

outputPath from the tool arguments is used as the directory with mkdir -p and no containment check, so the model can drop .json/.md files containing web-search text (untrusted) into any directory; file names are generated, which limits impact to planting new files.
> `npx/goalie/src/mcp/tools.ts:374` — `outputPath: params.outputPath,`
> `npx/goalie/src/utils/output-manager.ts:29` — `let baseDir = options?.outputPath || this.defaultResultsDir;`
> `npx/goalie/src/utils/output-manager.ts:146` — `await fs.writeFile(jsonPath, JSON.stringify(results, null, 2), 'utf-8');`

**Fix:** Ignore outputPath from tool calls or resolve it under the .research/ base directory and reject paths whose path.relative() starts with '..'.

### M005 · MEDIUM · Claude Code hooks run unpinned npx claude-flow@alpha on every tool call
`None:None` · ASI04 Agentic Supply Chain

Every Bash/Write/Edit by an agent in this repo downloads and runs whatever is currently tagged `alpha` on npm, with the developer's rights and the full command text as input; a compromised or changed release runs automatically.
> `.claude/settings.json:47` — `npx claude-flow@alpha hooks pre-command --command '{}'`

**Fix:** Pin an exact version (claude-flow@<x.y.z>) or install it as a locked devDependency and call the local binary; disable hooks you do not need.

### M006 · LOW · Perplexity API key prefix logged
`None:None` · 

Debug logs print the first characters of the Authorization header / key (`Bearer pplx-xxx`), leaking part of the secret into logs on every request.
> `npx/goalie/src/actions/perplexity-actions.ts:108` — `authHeaderPrefix: authHeader ? `${authHeader.substring(0, 15)}...` : 'none',`

**Fix:** Log only whether a key is set, never any part of it; remove the [DEBUG] logging.

## Dismissed as false alarms

- F003 HIDDEN-INSTRUCTIONS `.claude/agents/swarm/hierarchical-coordinator.md:150` — The 'invisible characters' are the variation selector U+FE0F inside keycap emoji (1️⃣ etc.) used as step numbers; no hidden text or instructions are encoded.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
