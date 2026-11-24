# Agent & MCP security report

Scanned: `/tmp/blind/c09` · 2026-11-23T20:32:49+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 2 | 12 | 2 | 0 | 0 | 13 | 1 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **26** · agent/MCP code files: **16** · agent instruction files: **1**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M001 · CRITICAL · exec_in_pod runs any shell command in any pod, with an attacker-chosen shell, and is never treated as destructive
`None:None` · ASI02 Tool Misuse / ASI05 Unexpected Code Execution

Any tool call gives command execution inside any pod in any namespace the kubeconfig can reach (reading mounted service-account tokens and secrets, or changing workloads). There is no approval step, and exec_in_pod is not in destructiveTools, so even the non-destructive mode keeps it listed.
> `src/tools/exec_in_pod.ts:85` — `const shell = input.shell || "/bin/sh";`
> `src/tools/exec_in_pod.ts:86` — `commandArr = [shell, "-c", input.command];`
> `src/tools/exec_in_pod.ts:144` — `exec.exec(`

**Fix:** Add exec_in_pod to destructiveTools, require human approval per call, and optionally restrict namespaces/pods via an operator allowlist.

### F018 · CRITICAL · DANGEROUS-AGENT-TOOL
`src/tools/kubectl-generic.ts:118` · ASI02 Tool Misuse and Exploitation

By design this tool runs any kubectl subcommand with any flags and arguments chosen by the model, with no allowlist or approval. Besides deleting anything in the cluster, `kubectl cp` reads and writes arbitrary files on the host running the server (e.g. copy ~/.ssh or ~/.kube/config into a pod, or overwrite host files from a pod), and `--kubeconfig`/`--server` flags redirect credentials. It is also still callable when ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS hides it (see M002).
> `src/tools/kubectl-generic.ts:8` — `"Execute any kubectl command with the provided arguments and flags",`
> `src/tools/kubectl-generic.ts:70` — `const cmdArgs: string[] = [input.command];`
> `src/tools/kubectl-generic.ts:112` — `cmdArgs.push(...input.args);`

**Fix:** Disable kubectl_generic by default; if kept, allowlist subcommands (no cp, exec, proxy, port-forward, plugin, config) and flags (no --kubeconfig, --server, --token, --as, --context), and require human approval.

### M002 · HIGH · Non-destructive mode only hides tools from tools/list; tools/call still runs them
`None:None` · 

ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS filters the ListTools response but the CallTool handler never checks it, so a client sending tools/call for kubectl_delete, kubectl_generic or uninstall_helm_chart still deletes resources. The destructive list also omits exec_in_pod, kubectl_apply/create/patch/scale/rollout and helm install/upgrade.
> `src/index.ts:151` — `const tools = nonDestructiveTools`
> `src/index.ts:223` — `if (name === "kubectl_delete") {`
> `src/index.ts:309` — `if (name === "kubectl_generic") {`

**Fix:** In the CallTool handler, reject any tool whose name is in destructiveTools when nonDestructiveTools is true, and add every state-changing tool to that list.

### M003 · HIGH · port_forward builds a command string and splits it on spaces
`None:None` · ASI02 Tool Misuse and Exploitation

Any space in namespace, resourceType or resourceName adds new kubectl arguments; e.g. namespace 'default --address 0.0.0.0' makes the forwarded cluster port listen on every network interface, and '--context=...' / '--kubeconfig=...' work too. No shell, so flag injection only.
> `src/tools/port_forward.ts:84` — `command += ` -n ${input.namespace}`;`
> `src/tools/port_forward.ts:86` — `command += ` ${input.resourceType}/${input.resourceName} ${input.localPort}:${input.targetPort}`;`
> `src/tools/port_forward.ts:10` — `const [cmd, ...args] = command.split(" ");`

**Fix:** Build the args array directly: spawn('kubectl', ['port-forward', '-n', ns, `${type}/${name}`, `${local}:${target}`]) after validating names with the Kubernetes name regex and ports as integers 1-65535.

### M005 · HIGH · Helm release name / chart passed positionally without validation
`None:None` · ASI02 Tool Misuse and Exploitation

name, chart and the repo name derived from chart are positional helm arguments with no '--' and no validation, so values like '--kube-context=prod' or '--kubeconfig=/path' become helm flags; repo is any URL the model chooses, so an attacker-controlled chart is installed into the cluster with no approval.
> `src/tools/helm-operations.ts:129` — `params.name,`
> `src/tools/helm-operations.ts:122` — `executeHelmCommand("helm", ["repo", "add", repoName, params.repo]);`
> `src/tools/helm-operations.ts:99` — `return execFileSync(command, args, {`

**Fix:** Validate name/chart with strict regexes (no leading '-'), insert '--' before positionals, allowlist chart repositories, and require approval for install/upgrade.

### M007 · HIGH · Pod logs/exec output reach the model next to secrets and network-capable tools
`None:None` · ASI01 / ASI02 (untrusted input + private data + way out)

Logs, describe output and exec output contain text written by applications and their users (untrusted) and are returned raw to the model; the same server can read Secrets (kubectl_get secrets -o yaml) and send data out (exec_in_pod curl, helm repo add with any URL, port_forward), with no approval in between, so an injected log line can drive secret exfiltration.
> `src/tools/kubectl-logs.ts:391` — `logs: logOutput,`
> `src/tools/exec_in_pod.ts:188` — `text: stdout,`
> `src/tools/kubectl-get.ts:212` — `text: result,`

**Fix:** Mark tool output as untrusted data, require approval for exec_in_pod/kubectl_generic/helm, and deny secrets access in the RBAC role used by the server.

### F002 · HIGH · ARG-INJECTION
`src/tools/kubectl-delete.ts:148` · ASI02 Tool Misuse and Exploitation

kubectl_delete resourceType and name is pushed into the kubectl argument list as a positional value with no validation and no '--' separator; the input is never checked against the JSON schema at runtime. An injected value such as '--context=prod-cluster', '--server=http://attacker:80' or '--kubeconfig=/path' is parsed by kubectl as a global flag, so the tool acts on another cluster or sends cluster credentials elsewhere. execFileSync means no shell, so this is flag injection, not command injection.
> `src/index.ts:166` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-delete.ts:114` — `args.push(input.resourceType!);`
> `src/tools/kubectl-delete.ts:117` — `args.push(input.name);`

**Fix:** Validate resourceType/name/namespace against the Kubernetes name pattern ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (reject anything starting with '-'), and put '--' before positional values.

### F003 · HIGH · ARG-INJECTION
`src/tools/kubectl-describe.ts:65` · ASI02 Tool Misuse and Exploitation

kubectl_describe resourceType and name is pushed into the kubectl argument list as a positional value with no validation and no '--' separator; the input is never checked against the JSON schema at runtime. An injected value such as '--context=prod-cluster', '--server=http://attacker:80' or '--kubeconfig=/path' is parsed by kubectl as a global flag, so the tool acts on another cluster or sends cluster credentials elsewhere. execFileSync means no shell, so this is flag injection, not command injection.
> `src/tools/kubectl-describe.ts:47` — `const resourceType = input.resourceType.toLowerCase();`
> `src/tools/kubectl-describe.ts:54` — `const args = ["describe", resourceType, name];`
> `src/tools/kubectl-describe.ts:65` — `const result = execFileSync(command, args, {`

**Fix:** Validate resourceType/name/namespace against the Kubernetes name pattern ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (reject anything starting with '-'), and put '--' before positional values.

### F004 · HIGH · ARG-INJECTION
`src/tools/kubectl-get.ts:147` · ASI02 Tool Misuse and Exploitation

kubectl_get resourceType and name is pushed into the kubectl argument list as a positional value with no validation and no '--' separator; the input is never checked against the JSON schema at runtime. An injected value such as '--context=prod-cluster', '--server=http://attacker:80' or '--kubeconfig=/path' is parsed by kubectl as a global flag, so the tool acts on another cluster or sends cluster credentials elsewhere. execFileSync means no shell, so this is flag injection, not command injection.
> `src/tools/kubectl-get.ts:72` — `const resourceType = input.resourceType.toLowerCase();`
> `src/tools/kubectl-get.ts:87` — `args.push(name);`
> `src/tools/kubectl-get.ts:147` — `const result = execFileSync(command, args, {`

**Fix:** Validate resourceType/name/namespace against the Kubernetes name pattern ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (reject anything starting with '-'), and put '--' before positional values.

### F005 · HIGH · ARG-INJECTION
`src/tools/kubectl-logs.ts:104` · ASI02 Tool Misuse and Exploitation

kubectl_logs name is pushed into the kubectl argument list as a positional value with no validation and no '--' separator; the input is never checked against the JSON schema at runtime. An injected value such as '--context=prod-cluster', '--server=http://attacker:80' or '--kubeconfig=/path' is parsed by kubectl as a global flag, so the tool acts on another cluster or sends cluster credentials elsewhere. execFileSync means no shell, so this is flag injection, not command injection.
> `src/tools/kubectl-logs.ts:84` — `const resourceType = input.resourceType.toLowerCase();`
> `src/tools/kubectl-logs.ts:92` — `let args = ["-n", namespace, "logs", name];`
> `src/tools/kubectl-logs.ts:104` — `const result = execFileSync(command, args, {`

**Fix:** Validate resourceType/name/namespace against the Kubernetes name pattern ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (reject anything starting with '-'), and put '--' before positional values.

### F006 · HIGH · ARG-INJECTION
`src/tools/kubectl-patch.ts:116` · ASI02 Tool Misuse and Exploitation

kubectl_patch resourceType and name is pushed into the kubectl argument list as a positional value with no validation and no '--' separator; the input is never checked against the JSON schema at runtime. An injected value such as '--context=prod-cluster', '--server=http://attacker:80' or '--kubeconfig=/path' is parsed by kubectl as a global flag, so the tool acts on another cluster or sends cluster credentials elsewhere. execFileSync means no shell, so this is flag injection, not command injection.
> `src/index.ts:166` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-patch.ts:81` — `const args = ["patch", input.resourceType, input.name, "-n", namespace];`
> `src/tools/kubectl-patch.ts:116` — `const result = execFileSync(command, args, {`

**Fix:** Validate resourceType/name/namespace against the Kubernetes name pattern ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (reject anything starting with '-'), and put '--' before positional values.

### F007 · HIGH · ARG-INJECTION
`src/tools/kubectl-rollout.ts:105` · ASI02 Tool Misuse and Exploitation

kubectl_rollout subCommand (typed as an enum in TypeScript only, never checked at runtime) is pushed into the kubectl argument list as a positional value with no validation and no '--' separator; the input is never checked against the JSON schema at runtime. An injected value such as '--context=prod-cluster', '--server=http://attacker:80' or '--kubeconfig=/path' is parsed by kubectl as a global flag, so the tool acts on another cluster or sends cluster credentials elsewhere. execFileSync means no shell, so this is flag injection, not command injection.
> `src/index.ts:166` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-rollout.ts:76` — `input.subCommand,`
> `src/tools/kubectl-rollout.ts:105` — `const result = execFileSync(command, args, {`

**Fix:** Check subCommand against the fixed list (history/pause/restart/resume/status/undo) and resourceType against deployment/daemonset/statefulset at runtime; validate name with the Kubernetes name regex.

### F008 · HIGH · ARG-INJECTION
`src/tools/kubectl-rollout.ts:122` · ASI02 Tool Misuse and Exploitation

kubectl_rollout subCommand (typed as an enum in TypeScript only, never checked at runtime) is pushed into the kubectl argument list as a positional value with no validation and no '--' separator; the input is never checked against the JSON schema at runtime. An injected value such as '--context=prod-cluster', '--server=http://attacker:80' or '--kubeconfig=/path' is parsed by kubectl as a global flag, so the tool acts on another cluster or sends cluster credentials elsewhere. execFileSync means no shell, so this is flag injection, not command injection.
> `src/index.ts:166` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-rollout.ts:76` — `input.subCommand,`
> `src/tools/kubectl-rollout.ts:122` — `const result = execFileSync(command, args, {`

**Fix:** Check subCommand against the fixed list (history/pause/restart/resume/status/undo) and resourceType against deployment/daemonset/statefulset at runtime; validate name with the Kubernetes name regex.

### F009 · HIGH · ARG-INJECTION
`src/tools/kubectl-scale.ts:59` · ASI02 Tool Misuse and Exploitation

kubectl_scale resourceType and name is pushed into the kubectl argument list as a positional value with no validation and no '--' separator; the input is never checked against the JSON schema at runtime. An injected value such as '--context=prod-cluster', '--server=http://attacker:80' or '--kubeconfig=/path' is parsed by kubectl as a global flag, so the tool acts on another cluster or sends cluster credentials elsewhere. execFileSync means no shell, so this is flag injection, not command injection.
> `src/index.ts:166` — `const { name, arguments: input = {} } = request.params;`
> `src/tools/kubectl-scale.ts:52` — `input.name,`
> `src/tools/kubectl-scale.ts:59` — `const result = execFileSync(command, args, {`

**Fix:** Validate resourceType/name/namespace against the Kubernetes name pattern ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ (reject anything starting with '-'), and put '--' before positional values. Also check replicas is a non-negative integer.

### M004 · MEDIUM · Helm values file is written to a path built from the release name
`None:None` · ASI02 Tool Misuse and Exploitation

name such as '../../../home/user/project/prod' writes attacker YAML to any directory the server can write, as long as the file ends in '-values.yaml', and then deletes it in the finally block, so existing *-values.yaml files anywhere can be overwritten and removed.
> `src/tools/helm-operations.ts:138` — `const valuesFile = writeValuesFile(params.name, params.values);`
> `src/tools/helm-operations.ts:110` — `const filename = `${name}-values.yaml`;`
> `src/tools/helm-operations.ts:111` — `writeFileSync(filename, yaml.stringify(values));`

**Fix:** Write values to fs.mkdtempSync(path.join(os.tmpdir(),'helm-')) + '/values.yaml' and validate name with the Helm release-name regex ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$.

### M006 · MEDIUM · filename / patchFile let kubectl read any local path or URL
`None:None` · ASI02 Tool Misuse and Exploitation

kubectl -f accepts local paths and http(s) URLs, so the model can make the server fetch internal URLs or apply/delete whatever manifests exist anywhere on the host disk; fragments of the read data can come back in error messages.
> `src/index.ts:215` — `filename?: string;`
> `src/tools/kubectl-apply.ts:78` — `args.push("-f", input.filename);`
> `src/tools/kubectl-delete.ts:111` — `args.push("-f", input.filename);`

**Fix:** Drop filename/patchFile (manifest/patchData already cover the use case) or restrict them to files under an operator-configured directory (realpath + containment check) and reject URLs.

## Dismissed as false alarms

- F001 ARG-INJECTION `src/tools/kubectl-apply.ts:96` — No positional value reaches kubectl apply: filename and namespace are always the value of -f / -n, so they cannot become flags (execFileSync, no shell). The real issue with filename (any local path or URL) is reported separately as M006.
- F010 PATH-TRAVERSAL `src/tools/kubectl-apply.ts:75` — The written path is built only from os.tmpdir(), a constant prefix and Date.now(); the tool input controls the file content, not the path, so there is no traversal. (Hardening: use fs.mkdtempSync for an unpredictable name.)
- F016 PATH-TRAVERSAL `src/tools/kubectl-create.ts:244` — The written path is built only from os.tmpdir(), a constant prefix and Date.now(); the tool input controls the file content, not the path, so there is no traversal. (Hardening: use fs.mkdtempSync for an unpredictable name.)
- F017 PATH-TRAVERSAL `src/tools/kubectl-delete.ts:108` — The written path is built only from os.tmpdir(), a constant prefix and Date.now(); the tool input controls the file content, not the path, so there is no traversal. (Hardening: use fs.mkdtempSync for an unpredictable name.)
- F022 PATH-TRAVERSAL `src/tools/kubectl-patch.ts:103` — The written path is built only from os.tmpdir(), a constant prefix and Date.now(); the tool input controls the file content, not the path, so there is no traversal. (Hardening: use fs.mkdtempSync for an unpredictable name.)
- F011 ARG-INJECTION `src/tools/kubectl-context.ts:73` — listArgs contains only constants ('config','get-contexts' and optionally '-o','name'); the output argument only selects a branch and is never placed in the argument list.
- F012 ARG-INJECTION `src/tools/kubectl-context.ts:112` — listArgs contains only constants ('config','get-contexts' and optionally '-o','name'); the output argument only selects a branch and is never placed in the argument list.
- F013 ARG-INJECTION `src/tools/kubectl-context.ts:131` — Constant argument list; no tool input reaches it.
- F014 ARG-INJECTION `src/tools/kubectl-context.ts:231` — Constant argument list; no tool input reaches it.
- F015 ARG-INJECTION `src/tools/kubectl-context.ts:265` — contextName is only used after it is checked to be an exact entry of `kubectl config get-contexts -o name`, an allowlist from the operator's kubeconfig, so it cannot be a flag. Switching to any configured context is the tool's purpose.
- F019 ARG-INJECTION `src/tools/kubectl-logs.ts:145` — The user value is glued behind a fixed '--selector=job-name=' prefix in a single argv entry, so it cannot become a separate flag (execFileSync, no shell).
- F020 ARG-INJECTION `src/tools/kubectl-logs.ts:309` — labelSelector sits behind a fixed '--selector=' prefix in one argv entry; it cannot add flags.
- F021 ARG-INJECTION `src/tools/kubectl-logs.ts:351` — pod comes from the cluster's own `get pods` output (Kubernetes names cannot start with '-'), and container is always the value of -c; no tool input becomes a flag here.

## Needs information from you

- M008 NETWORK-EXPOSURE `None:None` — When enabled, anyone who reaches the port (or a web page via DNS rebinding, since Host/Origin are not checked) gets every tool, including exec_in_pod. It is opt-in and labelled unsafe; whether it is enabled and on which HOST depends on deployment.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
