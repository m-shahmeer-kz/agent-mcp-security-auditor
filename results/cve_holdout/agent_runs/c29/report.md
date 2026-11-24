# Agent & MCP security report

Scanned: `/tmp/blind/c29` · 2026-11-23T20:37:43+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🟠 Fix soon

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 0 | 1 | 1 | 0 | 1 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **9** · agent/MCP code files: **1** · agent instruction files: **1**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · MEDIUM · screenshot / record_video write to any path the model chooses
`None:None` · ASI02 Tool Misuse and Exploitation

output_path is only length-limited; absolute paths and '..' are accepted as-is, so a prompt-injected call can overwrite any file the user can write (e.g. ~/.zshrc, project sources, ~/.ssh/authorized_keys) with image/video bytes, and record_video's force flag overwrites existing files. Content is not attacker-chosen, so this is file destruction, not code execution. The '--' separator correctly prevents flag injection.
> `src/index.ts:478` — `async ({ udid, output_path, type, display, mask }) => {`
> `src/index.ts:430` — `if (path.isAbsolute(filePath)) {`
> `src/index.ts:481` — `const absolutePath = ensureAbsolutePath(output_path);`

**Fix:** Resolve the path (fs.realpath on the parent) and require it to stay inside an allowed output directory such as ~/Downloads (path.relative must not start with '..'), and refuse to overwrite existing files unless the user approves.

### M002 · LOW · On-screen accessibility text of the simulated app is returned raw to the model
`None:None` · 

ui_describe_all / ui_describe_point return all text visible in the app under test (which may show web content, chat messages or other third-party text) without marking it as untrusted; injected text there can steer the model's next ui_type / ui_tap / screenshot calls (see M001).
> `src/index.ts:164` — `const { stdout } = await run("idb", [`
> `src/index.ts:175` — `content: [{ type: "text", text: stdout }],`

**Fix:** Mark the returned accessibility tree as untrusted data in the tool result, and keep human approval for file-writing tools.

## Dismissed as false alarms

- M003 ARG-INJECTION `None:None` — Checked every tool that starts a process: commands run without a shell, udid is checked against a strict UUID regex, duration against a number regex, enum fields use z.enum, numbers are z.number, and free-text values come after '--'. No command or argument injection found.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
