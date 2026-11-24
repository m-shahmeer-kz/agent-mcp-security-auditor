# Agent & MCP security report

Scanned: `/tmp/blind/c26` · 2026-11-23T20:41:56+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 1 | 13 | 2 | 1 | 0 | 13 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **28** · agent/MCP code files: **19** · agent instruction files: **1**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### F018 · CRITICAL · ARG-INJECTION
`src/tools/kubectl-generic.ts:129` · ASI02 Tool Misuse and Exploitation

kubectl_generic runs any kubectl subcommand with any flags from the tool call: e.g. 'cp <pod>:/x <host path>' writes arbitrary files on the server host, '--kubeconfig=<file>' loads an exec credential plugin (host command execution), and 'get secrets -o yaml' returns unmasked secrets. One injected prompt gets full control of the cluster and the host.
> `src/index.ts:212` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-generic.ts:76` — `const cmdArgs: string[] = [input.command];`
> `src/tools/kubectl-generic.ts:118` — `cmdArgs.push(...input.args);`

**Fix:** Remove kubectl_generic or restrict it to an allowlist of subcommands and flags (no cp, proxy, plugin, --kubeconfig, --server, --token, --as), and require human approval.

### M001 · HIGH · Read-only / non-destructive / allowlist modes only hide tools; tools/call still runs every tool
`None:None` · 

ALLOW_ONLY_READONLY_TOOLS, ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS and ALLOWED_TOOLS filter only tools/list; the tools/call handler dispatches any tool name, so a client or injected prompt that calls kubectl_delete, exec_in_pod or kubectl_generic by name runs it anyway.
> `src/index.ts:193` — `tools = readonlyTools;`
> `src/index.ts:368` — `if (name === "kubectl_generic") {`

**Fix:** In the CallTool handler, compute the same allowed set and throw McpError(InvalidRequest) when name is not in it.

### M002 · HIGH · port_forward builds a command string and splits it on spaces
`None:None` · ASI02 Tool Misuse and Exploitation

namespace/resourceType/resourceName containing spaces become extra kubectl arguments, e.g. namespace 'default --address 0.0.0.0' exposes the forwarded internal service on all interfaces, or '--kubeconfig /path' switches credentials.
> `src/tools/port_forward.ts:87` — `command += ` -n ${input.namespace}`;`
> `src/tools/port_forward.ts:10` — `const [cmd, ...args] = command.split(" ");`

**Fix:** Build an argument array: spawn('kubectl', ['port-forward', '-n', ns, `${type}/${name}`, `${local}:${target}`]) after validating names against a DNS-1123 regex and ports as integers.

### M003 · HIGH · Helm install/upgrade pass release name and chart as positional args; valuesFile reads any host file
`None:None` · ASI02 Tool Misuse and Exploitation

name/chart starting with '-' are parsed by helm as flags (helm has options such as --post-renderer that run a local program), chart/repo can point at any attacker repository, and valuesFile makes the server 'cat' any host file into chart values that are then rendered into the cluster.
> `src/tools/helm-operations.ts:320` — `params.name,`
> `src/tools/helm-operations.ts:321` — `params.chart,`
> `src/tools/helm-operations.ts:210` — `valuesContent = executeCommand("cat", [params.valuesFile]);`

**Fix:** Validate name against ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$, reject chart/repo values starting with '-', allowlist repositories, and drop valuesFile or confine it to a fixed directory with realpath + containment check.

### M004 · HIGH · Secret masking in kubectl_get is bypassed with another resource spelling
`None:None` · 

Masking is applied only when resourceType is exactly 'secrets' or 'secret'; resourceType 'pods,secrets' (or 'secrets.v1.') makes kubectl return the secret data unmasked to the model, even in read-only mode.
> `src/tools/kubectl-get.ts:167` — `(resourceType === "secrets" || resourceType === "secret");`
> `src/tools/kubectl-get.ts:90` — `const args = ["get", resourceType];`

**Fix:** Mask any output whose items have kind == 'Secret' (parse the JSON/YAML) instead of checking the requested type string, and also strip the last-applied-configuration annotation.

### M005 · HIGH · HTTP/SSE transports have no authentication by default; Helm chart binds 0.0.0.0 without setting a token
`None:None` · ASI03 Identity and Privilege Abuse

Without MCP_AUTH_TOKEN every request is allowed, the Helm chart listens on all interfaces and never sets a token, and DNS-rebinding protection is off by default, so anyone who can reach the port (or a web page via DNS rebinding on localhost) can call kubectl_generic/exec_in_pod with the server's cluster credentials.
> `src/utils/auth.ts:34` — `if (!authToken) {`
> `helm-chart/templates/deployment.yaml:114` — `value: "0.0.0.0"`
> `src/utils/streamable-http.ts:23` — `process.env.DNS_REBINDING_PROTECTION === "true";`

**Fix:** Refuse to start the HTTP/SSE transports unless MCP_AUTH_TOKEN is set, wire the token into the Helm chart from a Secret, and enable DNS-rebinding protection by default.

### F002 · HIGH · ARG-INJECTION
`src/tools/kubectl-delete.ts:159` · ASI02 Tool Misuse and Exploitation

input.resourceType / input.name comes straight from the tool arguments and is placed as a positional kubectl argument with no '--' separator and no check for a leading '-', so kubectl parses it as a flag (e.g. '--kubeconfig=<path>' to load another kubeconfig whose exec plugin runs on the host, '--server=https://attacker' to send the cluster credentials elsewhere, '--as=...' to impersonate).
> `src/index.ts:212` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-delete.ts:123` — `args.push(input.name);`

**Fix:** Validate resourceType/name against ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (DNS-1123) and reject values starting with '-'; put '--' before positional arguments where kubectl allows it.

### F003 · HIGH · ARG-INJECTION
`src/tools/kubectl-describe.ts:75` · ASI02 Tool Misuse and Exploitation

resourceType / name comes straight from the tool arguments and is placed as a positional kubectl argument with no '--' separator and no check for a leading '-', so kubectl parses it as a flag (e.g. '--kubeconfig=<path>' to load another kubeconfig whose exec plugin runs on the host, '--server=https://attacker' to send the cluster credentials elsewhere, '--as=...' to impersonate).
> `src/index.ts:212` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-describe.ts:60` — `const args = ["describe", resourceType, name];`

**Fix:** Validate resourceType/name against ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (DNS-1123) and reject values starting with '-'; put '--' before positional arguments where kubectl allows it.

### F004 · HIGH · ARG-INJECTION
`src/tools/kubectl-get.ts:158` · ASI02 Tool Misuse and Exploitation

resourceType / name comes straight from the tool arguments and is placed as a positional kubectl argument with no '--' separator and no check for a leading '-', so kubectl parses it as a flag (e.g. '--kubeconfig=<path>' to load another kubeconfig whose exec plugin runs on the host, '--server=https://attacker' to send the cluster credentials elsewhere, '--as=...' to impersonate).
> `src/index.ts:212` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-get.ts:94` — `args.push(name);`

**Fix:** Validate resourceType/name against ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (DNS-1123) and reject values starting with '-'; put '--' before positional arguments where kubectl allows it.

### F005 · HIGH · ARG-INJECTION
`src/tools/kubectl-logs.ts:116` · ASI02 Tool Misuse and Exploitation

name comes straight from the tool arguments and is placed as a positional kubectl argument with no '--' separator and no check for a leading '-', so kubectl parses it as a flag (e.g. '--kubeconfig=<path>' to load another kubeconfig whose exec plugin runs on the host, '--server=https://attacker' to send the cluster credentials elsewhere, '--as=...' to impersonate).
> `src/index.ts:212` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-logs.ts:99` — `let args = ["-n", namespace, "logs", name];`

**Fix:** Validate resourceType/name against ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (DNS-1123) and reject values starting with '-'; put '--' before positional arguments where kubectl allows it.

### F006 · HIGH · ARG-INJECTION
`src/tools/kubectl-patch.ts:131` · ASI02 Tool Misuse and Exploitation

input.resourceType / input.name comes straight from the tool arguments and is placed as a positional kubectl argument with no '--' separator and no check for a leading '-', so kubectl parses it as a flag (e.g. '--kubeconfig=<path>' to load another kubeconfig whose exec plugin runs on the host, '--server=https://attacker' to send the cluster credentials elsewhere, '--as=...' to impersonate).
> `src/index.ts:212` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-patch.ts:84` — `const args = ["patch", input.resourceType, input.name, "-n", namespace];`

**Fix:** Validate resourceType/name against ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (DNS-1123) and reject values starting with '-'; put '--' before positional arguments where kubectl allows it.

### F007 · HIGH · ARG-INJECTION
`src/tools/kubectl-rollout.ts:114` · ASI02 Tool Misuse and Exploitation

input.subCommand (not enum-checked at runtime) comes straight from the tool arguments and is placed as a positional kubectl argument with no '--' separator and no check for a leading '-', so kubectl parses it as a flag (e.g. '--kubeconfig=<path>' to load another kubeconfig whose exec plugin runs on the host, '--server=https://attacker' to send the cluster credentials elsewhere, '--as=...' to impersonate).
> `src/index.ts:212` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-rollout.ts:80` — `input.subCommand,`

**Fix:** Validate resourceType/name against ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (DNS-1123) and reject values starting with '-'; put '--' before positional arguments where kubectl allows it.

### F008 · HIGH · ARG-INJECTION
`src/tools/kubectl-rollout.ts:132` · ASI02 Tool Misuse and Exploitation

input.subCommand / input.resourceType comes straight from the tool arguments and is placed as a positional kubectl argument with no '--' separator and no check for a leading '-', so kubectl parses it as a flag (e.g. '--kubeconfig=<path>' to load another kubeconfig whose exec plugin runs on the host, '--server=https://attacker' to send the cluster credentials elsewhere, '--as=...' to impersonate).
> `src/index.ts:212` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-rollout.ts:81` — ``${input.resourceType}/${input.name}`,`

**Fix:** Validate resourceType/name against ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (DNS-1123) and reject values starting with '-'; put '--' before positional arguments where kubectl allows it.

### F009 · HIGH · ARG-INJECTION
`src/tools/kubectl-scale.ts:68` · ASI02 Tool Misuse and Exploitation

resourceType / input.name comes straight from the tool arguments and is placed as a positional kubectl argument with no '--' separator and no check for a leading '-', so kubectl parses it as a flag (e.g. '--kubeconfig=<path>' to load another kubeconfig whose exec plugin runs on the host, '--server=https://attacker' to send the cluster credentials elsewhere, '--as=...' to impersonate).
> `src/index.ts:212` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-scale.ts:56` — `input.name,`

**Fix:** Validate resourceType/name against ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (DNS-1123) and reject values starting with '-'; put '--' before positional arguments where kubectl allows it.

### M006 · MEDIUM · filename / patchFile accept any host path or URL
`None:None` · ASI02 Tool Misuse and Exploitation

kubectl -f accepts local paths and http(s) URLs, so the server can be made to read any local manifest/file it can access or fetch a URL from its network (internal services) and apply the result to the cluster.
> `src/index.ts:212` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-apply.ts:78` — `args.push("-f", input.filename);`
> `src/tools/kubectl-patch.ts:116` — `args.push("--patch-file", input.patchFile);`

**Fix:** Drop filename/patchFile (use manifest/patchData), or allow only paths under a configured directory after realpath + containment check and reject URLs.

### M007 · MEDIUM · Destructive and code-running tools run without confirmation
`None:None` · 

exec_in_pod, kubectl_delete, helm install/uninstall and kubectl_generic act on the cluster immediately (only node drain has a confirm flag); combined with M001 there is no human gate at all.
> `src/tools/exec_in_pod.ts:105` — `const args = ["exec", input.name, "-n", namespace];`
> `src/tools/kubectl-delete.ts:120` — `args.push(input.resourceType!);`

**Fix:** Add a confirm/dry-run step for exec, delete, helm and generic commands, and rely on client-side approval for destructiveHint tools.

### M008 · LOW · Pod logs, events and exec output returned raw to the model
`None:None` · 

Logs, events and command output contain text written by workloads or users of the cluster and go straight into the model context, which is how injected instructions can reach the agent and drive the tools above.
> `src/tools/exec_in_pod.ts:130` — `text: result,`

**Fix:** Wrap tool output in clearly marked untrusted-data blocks and keep the tools above behind approval.

## Dismissed as false alarms

- F001 ARG-INJECTION `src/tools/kubectl-apply.ts:101` — Every tool value in kubectl apply sits in a flag-value slot (-f, -n, --context), so it cannot become a new flag. The free filename path/URL is covered separately in M006.
- F010 PATH-TRAVERSAL `src/tools/kubectl-apply.ts:75` — The written path is built from os.tmpdir() and a timestamp only; the tool input is the file content, not the path, so there is no traversal.
- F016 PATH-TRAVERSAL `src/tools/kubectl-create.ts:240` — The written path is built from os.tmpdir() and a timestamp only; the tool input is the file content, not the path, so there is no traversal.
- F017 PATH-TRAVERSAL `src/tools/kubectl-delete.ts:114` — The written path is built from os.tmpdir() and a timestamp only; the tool input is the file content, not the path, so there is no traversal.
- F022 PATH-TRAVERSAL `src/tools/kubectl-patch.ts:113` — The written path is built from os.tmpdir() and a timestamp only; the tool input is the file content, not the path, so there is no traversal.
- F011 ARG-INJECTION `src/tools/kubectl-context.ts:77` — The argument list is fixed; no tool input reaches it.
- F012 ARG-INJECTION `src/tools/kubectl-context.ts:146` — The argument list is fixed; no tool input reaches it.
- F013 ARG-INJECTION `src/tools/kubectl-context.ts:167` — The argument list is fixed; no tool input reaches it.
- F014 ARG-INJECTION `src/tools/kubectl-context.ts:268` — The argument list is fixed; no tool input reaches it.
- F015 ARG-INJECTION `src/tools/kubectl-context.ts:303` — contextName must exactly match a context already listed by 'kubectl config get-contexts', so an injected flag value is rejected before use-context runs.
- F019 ARG-INJECTION `src/tools/kubectl-logs.ts:158` — The tool value is glued to the flag with '=', and namespace follows '-n' as its value, so neither can become a separate kubectl flag.
- F020 ARG-INJECTION `src/tools/kubectl-logs.ts:328` — The tool value is glued to the flag with '=', and namespace follows '-n' as its value, so neither can become a separate kubectl flag.
- F021 ARG-INJECTION `src/tools/kubectl-logs.ts:371` — Pod names here come from the cluster's own 'get pods' output, container follows '-c' as its value and the other log options are joined with '='; no tool string becomes a new flag.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
