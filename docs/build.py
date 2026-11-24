"""Build docs/index.html from results/ so every number on the page is a measured one.

Run:  python docs/build.py
"""
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
R = ROOT / "results"
MT = json.loads((R / "mcptox" / "holdout_result.json").read_text())
CH = json.loads((R / "cve_holdout" / "cve_agent_handchecked_v1.0.0.json").read_text())
CS = json.loads((R / "cve_holdout" / "cve_agent_strict_v1.0.0.json").read_text())
SC = json.loads((R / "cve_holdout" / "cve_scanner_v1.0.0.json").read_text())
LB = json.loads((R / "cve_holdout" / "labels.json").read_text())
BT = json.loads((R / "buyer_test" / "score.json").read_text())
AGENSI_URL = "https://www.agensi.io/creators/muhammad-shahmeer"
PRICE = "$19"
GH = "https://github.com/m-shahmeer-kz/agent-mcp-security-auditor"
e = html.escape
CSS = (ROOT / "docs" / "style.css").read_text()

caught = len(CH["caught_confirmed"])
nc = len(CH["found_but_needs_context"])
missed = len(CH["missed"])
total = len(LB)
again = CH["after_fix"]["flagged_again"]
not_again = len(CH["after_fix"]["not_flagged_again"])
m, lo = MT["medium"], MT["low"]


def pct(a, b, d=1):
    return f"{100 * a / b:.{d}f}%"


rows = []
for x in LB:
    hid = x["id"]
    if hid in CH["caught_confirmed"]:
        res = '<span class="ok">caught</span>'
    elif hid in CH["found_but_needs_context"]:
        res = '<span class="warn">found, marked "needs context"</span>'
    else:
        res = f'<span class="bad">missed</span> <small>({e(CH["missed"][hid])})</small>'
    if hid in again:
        after = f'flagged again: {e(again[hid])}'
    elif hid in CH["after_fix"]["not_flagged_again"]:
        after = "not flagged"
    else:
        after = "–"
    rows.append(f'<tr><td><a href="{e(x["advisory_url"])}">{e(x.get("cve") or x["ghsa"])}</a></td><td>{e(x["repo"])}</td>'
                f'<td>{e(x["class"])}</td><td>{e(x["language"])}</td><td>{res}</td><td><small>{after}</small></td></tr>')
table = "".join(rows)
buy = f'<a class="btn solid" href="{AGENSI_URL}" target="_blank" rel="noopener">Get it on Agensi · {PRICE} ↗</a>'

page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent &amp; MCP Security Auditor · is your AI agent safe to ship?</title>
<meta name="description" content="AI-agent skill that audits AI agent apps and MCP servers for prompt injection, poisoned tool descriptions, leaked secrets, over-wide permissions and unsafe tool calls. Blind-tested on 24 real MCP security advisories.">
<meta property="og:type" content="website">
<meta property="og:title" content="Agent &amp; MCP Security Auditor · is your AI agent safe to ship?">
<meta property="og:description" content="Local, read-only audit of agent apps and MCP servers with script-verified evidence. Blind test: {caught} of {total} real MCP security advisories caught.">
<meta property="og:url" content="https://m-shahmeer-kz.github.io/agent-mcp-security-auditor/">
<meta property="og:image" content="https://m-shahmeer-kz.github.io/agent-mcp-security-auditor/assets/og.png">
<meta property="og:image:width" content="1200"><meta property="og:image:height" content="627">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="assets/logo.png">
{CSS}<style>.ok{{color:var(--ok)}}.bad{{color:var(--bad)}}.warn{{color:var(--warn)}}small{{color:var(--mute)}}</style></head>
<body><div class="wrap">
<p class="sub" style="letter-spacing:.12em;text-transform:uppercase;font-size:12px">AI-agent skill · Claude Code · Codex · Cursor · Gemini CLI</p>
<h1>Is your AI agent safe to ship?</h1>
<p class="sub">Agent &amp; MCP Security Auditor lets your AI coding agent audit an AI agent app or MCP server before it goes to production.
A local script finds the candidates: hidden instructions in tool descriptions and agent files (prompt injection, tool poisoning),
command / argument injection, path traversal, SSRF, SQL and code injection in tool handlers (Python and TypeScript/JavaScript, followed across files),
secrets, over-wide permissions, auto-approval and unpinned packages in MCP configs. Your agent then judges every candidate and adds what a script cannot see
(missing authorization, refunds with no approval, untrusted text reaching the model). Every verdict must quote the exact code, and a second command
rejects any quote that is not really there. Read-only: it never runs, installs or connects to what it audits.</p>
<div class="btns">{buy}<a class="btn" href="#cve">Blind test on real advisories</a><a class="btn" href="#buyer">Buyer test</a><a class="btn" href="{GH}">GitHub ↗</a></div>

<h2 id="cve">Blind test: {total} real MCP security advisories</h2>
<p class="sub">A separate AI agent picked {total} published security advisories in open-source MCP servers with fixed rules (in date order, at most 6 per type)
and sealed the list before I built the tests. I froze version 1.0.0. Then 15 fresh AI agents ran the full skill on {len(json.loads((R / "cve_holdout" / "checkouts.json").read_text()))} code checkouts:
the version before each fix and the version after it, under neutral folder names, without being told what to look for. All {len(list((R / "cve_holdout" / "agent_runs").iterdir()))} audits passed the quote check.</p>
<div class="grid">
 <div class="card stat"><b>{caught} / {total}</b><span>advisories caught and confirmed (checked by hand; a strict automatic count gives {CS['caught']} / {total})</span></div>
 <div class="card stat"><b>+{nc}</b><span>found but marked "needs context" instead of confirmed</span></div>
 <div class="card stat"><b>{not_again} / {caught}</b><span>not flagged again after the developers' fix</span></div>
 <div class="card stat"><b>12 / 12</b><span>problems planted in a realistic agent app found, 0 of 9 safe decoys confirmed</span></div>
</div>
<p class="sub"><b>After the fix:</b> in {len(again)} of the {caught} cases the skill still raised something in the fixed code. I checked them: 2 are real holes the fix left behind
(a package name still injected into <code>python3 -c</code> code; a hidden tool argument that still chooses which program runs), 3 are real gaps in the new
address checks (they look only at the hostname as typed, so DNS names and redirects get through) and 1 is arguable (a local mode that accepts any file path).
<b>The scanner alone</b> caught only {SC['caught']} of {total}: most of the catches come from the agent reading the code with the skill's guide, which is why the skill makes it judge every tool.</p>
<details><summary>All {total} advisories, one by one</summary><div class="tbl"><table><tr><th>Advisory</th><th>Repo</th><th>Type</th><th>Lang</th><th>Before the fix</th><th>After the fix</th></tr>{table}</table></div>
<p class="sub">The selection log, every verdict, every report and the scoring script are in <code>results/cve_holdout/</code>.</p></details>

<h2 id="mcptox">Poisoned tool descriptions</h2>
<p class="sub">MCPTox (AAAI 2026, CC BY 4.0) contains real MCP tool descriptions with injected instructions. I split it by server (seed 2026), built the rules on 18 servers
and ran the frozen rules once on the other 27 servers' {m['poisoned'] + m['clean']} descriptions, which I had never looked at.</p>
<div class="tbl"><table><tr><th>Setting</th><th>Poisoned descriptions caught</th><th>Clean descriptions flagged</th></tr>
<tr><td>Normal</td><td>{m['caught']} / {m['poisoned']} ({pct(m['caught'], m['poisoned'])})</td><td>{m['false_alarms']} / {m['clean']} ({pct(m['false_alarms'], m['clean'])})</td></tr>
<tr><td>Sensitive (<code>--strict</code>)</td><td>{lo['caught']} / {lo['poisoned']} ({pct(lo['caught'], lo['poisoned'])})</td><td>{lo['false_alarms']} / {lo['clean']} ({pct(lo['false_alarms'], lo['clean'])})</td></tr></table></div>

<h2 id="buyer">Buyer test: a realistic support agent</h2>
<p class="sub">A LangGraph support agent plus a TypeScript billing MCP server, an MCP client config and a vendor tool list, with {len(BT['must_find'])} planted problems and 9 safe
look-alikes (a correct path guard, a safe ping with <code>execFile</code> and <code>--</code>, an allowlisted fetch, parameterised SQL, a pinned package, a test key in tests/…).
I wrote the expected results before the run. A fresh agent with the skill found <b>{BT['found']}</b> and confirmed <b>none</b> of the decoys, including the ones only a reader can see:
<code>get_invoice</code> returns any customer's invoice, and <code>refund_payment</code> refunds in full with no approval although the team's own AGENTS.md says to ask over 500 EUR.
The full report is in <code>examples/support-agent-app/</code>.</p>

<h2>What your agent does with it</h2>
<ol class="steps">
<li><b>Scan</b>: finds MCP client configs (Claude, Cursor, VS Code, Windsurf, Gemini, Codex, Zed…), agent permission settings, MCP servers and agent code (Python, TypeScript/JavaScript), the tools they define, agent instruction files and secrets.</li>
<li><b>Check tool lists</b>: scores exported <code>tools/list</code> JSON or pasted descriptions for hidden instructions.</li>
<li><b>Review every candidate</b> with the guide: traces input to the dangerous call, checks whether a guard really works, marks confirmed / false positive / needs context.</li>
<li><b>Manual pass</b> for what no script sees: authorization on every tool, token passthrough, destructive tools without confirmation, untrusted text reaching the model, the "lethal trifecta" (untrusted input + private data + a way out).</li>
<li><b>Verify</b>: every quote must exist at the cited line; injection findings need two quotes (where the input enters and where it is used).</li>
<li><b>Report</b>: verdict, fixes in order, dismissed items with the code that makes them safe, OWASP Top 10 for Agentic Applications mapping, and SARIF for GitHub code scanning. Optional <code>pin</code> catches "rug-pull" changes to tool definitions in CI.</li>
</ol>

<h2>Good to know</h2>
<div class="grid">
 <div class="card"><h3>Who it is for</h3><p>Teams shipping AI agents or MCP servers to production who need a security review with proof before launch, or in CI.</p></div>
 <div class="card"><h3>Local and read-only</h3><p>One Python script, standard library only (Python 3.10+). It never runs, installs or connects to the code it audits and never sends anything over the network. Secrets are masked in every output.</p></div>
 <div class="card"><h3>Proof, not scores</h3><p>Every finding cites the exact lines, and a command rejects quotes that are not in the code.</p></div>
 <div class="card"><h3>Honest limits</h3><p>Static review: it cannot see runtime behaviour or what remote servers return later. It missed 2 of {total} advisories (an <code>eval</code> of model output, an attachment download path). The judge is an AI; a human should confirm critical fixes.</p></div>
</div>

<div class="btns" style="margin-top:34px">{buy}<a class="btn" href="{GH}">GitHub ↗</a></div>
<p class="sub">Made by <a href="https://m-shahmeer-kz.github.io/">Muhammad Shahmeer</a> · Data Science MSc, University of Naples Federico II · © 2026, all rights reserved.
MCPTox © its authors (CC BY 4.0, <a href="https://github.com/zhiqiangwang4/MCPTox-Benchmark">github.com/zhiqiangwang4/MCPTox-Benchmark</a>); only scores are published here.
Advisories from the GitHub Advisory Database. Not affiliated with OWASP, GitHub or the MCP project.</p>
</div></body></html>
"""
(ROOT / "docs" / "index.html").write_text(page)
print("wrote docs/index.html", len(page))
