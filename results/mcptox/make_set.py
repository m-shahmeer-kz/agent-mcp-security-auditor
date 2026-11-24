"""Build the MCPTox tool-description test sets (dev and blind holdout).

Source: MCPTox (Wang et al., AAAI 2026), github.com/zhiqiangwang4/MCPTox-Benchmark,
materials licensed CC BY 4.0. Each record is one MCP tool as an agent would see it:
name + description + argument descriptions. Label "poisoned" = a tool definition
from MCPTox's malicious instances; "clean" = a real tool of the same server.

Split is by SERVER (seed 2026, split.json) so no server is in both sets.
Usage: python make_set.py /path/to/MCPTox-Benchmark
"""
import hashlib, json, re, sys
from pathlib import Path

src = Path(sys.argv[1])
here = Path(__file__).parent
split = json.loads((here / "split.json").read_text())
data = json.loads((src / "response_all.json").read_text())["servers"]


def parse_clean(prompt):
    tools = []
    for block in re.split(r"\n(?=Tool: )", prompt):
        m = re.match(r"Tool: (.+)\nDescription: (.*?)\nArguments:\n?(.*)", block.strip(), re.S)
        if not m:
            continue
        name, desc, args = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        tools.append((name, f"Tool: {name}\nDescription: {desc}\nArguments:\n{args}".strip()))
    return tools


def poisoned_text(pt):
    if isinstance(pt, dict):
        name = pt.get("name") or pt.get("tool_name") or ""
        desc = pt.get("description") or ""
        args = pt.get("inputSchema") or pt.get("parameters") or pt.get("arguments") or ""
        if not isinstance(args, str):
            args = json.dumps(args, ensure_ascii=False)
        return name, f"Tool: {name}\nDescription: {desc}\nArguments:\n{args}".strip()
    s = str(pt)
    m = re.search(r"Tool: (.+)", s)
    return (m.group(1).strip() if m else ""), s.strip()


def build(servers):
    out, seen = [], set()
    for sname in servers:
        s = data[sname]
        for name, text in parse_clean(s.get("clean_system_promot") or ""):
            key = ("clean", text)
            if key not in seen:
                seen.add(key)
                out.append({"server": sname, "tool": name, "label": "clean", "text": text})
        for inst in s.get("malicious_instance") or []:
            name, text = poisoned_text(inst.get("poisoned_tool"))
            meta = inst.get("metadata") or {}
            key = ("poisoned", text)
            if text and key not in seen:
                seen.add(key)
                out.append({"server": sname, "tool": name, "label": "poisoned", "text": text,
                            "risk": inst.get("security_risk_description") if isinstance(inst.get("security_risk_description"), str) else None,
                            "paradigm": meta.get("paradigm") if isinstance(meta, dict) else None})
    for i, r in enumerate(out):
        r["id"] = f"t{i:04d}"
    return out


for part in ("dev", "holdout"):
    rows = build(split[part])
    path = here / f"{part}.jsonl"
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
    n_p = sum(r["label"] == "poisoned" for r in rows)
    print(part, len(rows), "rows,", n_p, "poisoned,", len(rows) - n_p, "clean, sha256",
          hashlib.sha256(path.read_bytes()).hexdigest()[:16])
