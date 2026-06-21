"""
Run history and diffing: persist each scan to a JSON file and compare two runs so
you can track posture over time (e.g. in CI: "did anything regress since last run?").
"""

from __future__ import annotations

import glob
import json
import os
from datetime import datetime

HISTORY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "history")

COLUMNS = ["SPF", "DKIM", "DMARC", "MX", "MTA-STS", "TLS-RPT", "BIMI", "DNSSEC", "CAA"]


def save_run(results: list[dict], directory: str = HISTORY_DIR) -> str:
    os.makedirs(directory, exist_ok=True)
    # The Windows clock may not advance between rapid calls, so guarantee a unique
    # filename with a counter rather than relying on timestamp resolution alone.
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(directory, f"run_{ts}.json")
    n = 1
    while os.path.exists(path):
        path = os.path.join(directory, f"run_{ts}_{n}.json")
        n += 1
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"timestamp": datetime.now().isoformat(), "results": results},
                  f, indent=2)
    return path


def list_runs(directory: str = HISTORY_DIR) -> list[str]:
    return sorted(glob.glob(os.path.join(directory, "run_*.json")))


def load_run(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _by_domain(run: dict) -> dict:
    return {r["domain"]: r for r in run.get("results", []) if r.get("valid", True)}


def diff_runs(old: dict, new: dict) -> dict:
    """Compare two saved runs. Returns added/removed domains and per-domain changes
    in score, grade, risk and individual control statuses."""
    old_d, new_d = _by_domain(old), _by_domain(new)
    added = sorted(set(new_d) - set(old_d))
    removed = sorted(set(old_d) - set(new_d))
    changed = []
    for dom in sorted(set(old_d) & set(new_d)):
        o, n = old_d[dom], new_d[dom]
        deltas = {}
        if o.get("score") != n.get("score"):
            deltas["score"] = [o.get("score"), n.get("score")]
        if o.get("grade") != n.get("grade"):
            deltas["grade"] = [o.get("grade"), n.get("grade")]
        if o.get("risk") != n.get("risk"):
            deltas["risk"] = [o.get("risk"), n.get("risk")]
        ctrl = {}
        for c in COLUMNS:
            os_ = o.get("checks", {}).get(c, {}).get("status")
            ns_ = n.get("checks", {}).get(c, {}).get("status")
            if os_ != ns_:
                ctrl[c] = [os_, ns_]
        if deltas or ctrl:
            changed.append({"domain": dom, "deltas": deltas, "controls": ctrl,
                            "regressed": _regressed(o, n)})
    return {
        "old_ts": old.get("timestamp"), "new_ts": new.get("timestamp"),
        "added": added, "removed": removed, "changed": changed,
        "regressions": [c["domain"] for c in changed if c["regressed"]],
    }


def _regressed(old: dict, new: dict) -> bool:
    """A drop in score, or risk moving to a worse tier, counts as a regression."""
    order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3, "Unknown": -1}
    if (new.get("score", 0) < old.get("score", 0)):
        return True
    return order.get(new.get("risk"), -1) > order.get(old.get("risk"), -1)
