"""Score findings against the sealed advisories.
usage: score.py <results_root> <mode>   mode = scanner (findings.json) | agent (verified.json, confirmed only)
A hit = a finding of the advisory's class in one of the advisory's files (or whose input source is in one).
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
labels = json.load(open(HERE / "sealed/labels.json"))
checkouts = json.load(open(HERE / "checkouts.json"))
where = {}
for c in checkouts:
    for hid, kind in c["roles"]:
        where[(hid, kind)] = c["dir"]

CLASS_RULES = {
    "SSRF": {"SSRF"},
    "OS command injection": {"CMD-INJECTION"},
    "argument injection": {"ARG-INJECTION", "CMD-INJECTION"},
    "path traversal": {"PATH-TRAVERSAL"},
    "hardcoded secret": {"SECRET-IN-CODE", "SECRET-IN-CONFIG"},
    "missing authentication on HTTP/SSE transport": {"REMOTE-NO-AUTH", "NETWORK-EXPOSURE", "MISSING-AUTH", "AUTH-BYPASS"},
    "SQL injection": {"SQL-INJECTION"},
    "code injection / eval": {"CODE-INJECTION"},
}


def load(root, d, mode):
    p = Path(root) / d / ("findings.json" if mode == "scanner" else "verified.json")
    if not p.exists():
        return None
    data = json.load(open(p))
    if mode == "agent":
        data = data.get("findings", data) if isinstance(data, dict) else data
        data = [f for f in data if f.get("verdict") == "confirmed"]
    return data


def files_of(f):
    out = {f.get("file", "")}
    for e in f.get("evidence") or []:
        out.add(e.get("file", ""))
    if f.get("source_file"):
        out.add(f["source_file"])
    return {x.lstrip("./") for x in out if x}


def hit(findings, lab):
    rules = CLASS_RULES[lab["class"]]
    return [f for f in findings if f.get("rule") in rules and files_of(f) & set(lab["files"])]


root, mode = sys.argv[1], sys.argv[2]
rows = []
for lab in labels:
    v = load(root, where[(lab["id"], "vuln_ref")], mode)
    fx = load(root, where[(lab["id"], "fixed_ref")], mode)
    rows.append({"id": lab["id"], "class": lab["class"], "lang": lab["language"],
                 "vuln": None if v is None else bool(hit(v, lab)),
                 "fixed_still_flagged": None if fx is None else bool(hit(fx, lab)),
                 "vuln_hits": None if v is None else len(hit(v, lab)),
                 "fixed_hits": None if fx is None else len(hit(fx, lab))})
caught = sum(r["vuln"] is True for r in rows)
ran = sum(r["vuln"] is not None for r in rows)
still = sum(r["fixed_still_flagged"] is True for r in rows if r["vuln"])
print(f"{mode}: caught {caught}/24 advisories (ran on {ran}); of those caught, still flagged after the fix: {still}/{caught}")
for r in rows:
    print(r)
if len(sys.argv) > 3:
    Path(sys.argv[3]).write_text(json.dumps({"caught": caught, "ran": ran, "still_flagged_after_fix": still, "rows": rows}, indent=1))
