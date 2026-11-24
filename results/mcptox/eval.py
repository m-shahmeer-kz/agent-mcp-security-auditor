"""Score tool descriptions with the frozen text rules. Prints counts only (no description text)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "skill/agent-mcp-security-auditor/scripts"))
import textrules  # noqa: E402

LV = {"none": 0, "low": 1, "medium": 2, "high": 3}
rows = [json.loads(l) for l in open(sys.argv[1])]
out = {}
for thr in ("medium", "low"):
    tp = fp = fn = tn = 0
    by_paradigm = {}
    for r in rows:
        flag = LV[textrules.score_text(r["text"])["level"]] >= LV[thr]
        if r["label"] == "poisoned":
            tp += flag
            fn += not flag
            p = by_paradigm.setdefault(r.get("paradigm", "?"), [0, 0])
            p[0] += flag
            p[1] += 1
        else:
            fp += flag
            tn += not flag
    out[thr] = {"caught": tp, "poisoned": tp + fn, "recall": round(tp / (tp + fn), 4),
                "false_alarms": fp, "clean": fp + tn, "false_alarm_rate": round(fp / (fp + tn), 4),
                "by_paradigm": by_paradigm}
    print(f"{Path(sys.argv[1]).name} thr={thr}: caught {tp}/{tp+fn} = {tp/(tp+fn):.1%} | false alarms {fp}/{fp+tn} = {fp/(fp+tn):.1%} | by paradigm {by_paradigm}")
if len(sys.argv) > 2:
    Path(sys.argv[2]).write_text(json.dumps(out, indent=2))
