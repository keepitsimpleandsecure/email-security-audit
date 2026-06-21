"""
MX Sentinel - local web UI (Flask).

Run:  python app.py   then open http://127.0.0.1:5000

Endpoints:
  GET  /                 -> the single-page UI
  POST /api/scan         -> streams NDJSON: one line per domain result, then a
                            final {"event":"done", ...} summary line
  POST /api/export/<fmt> -> returns csv | json | html report for given results
"""

from __future__ import annotations

import io
import json
from datetime import datetime

from flask import Flask, Response, render_template, request, jsonify, stream_with_context

import audit
import headers as headers_mod
import history
import report

app = Flask(__name__)


# Shared dark color themes. The app switches live (persisted in the browser); the
# exported HTML report is rendered with whatever theme was active at export time
# (the report itself is not switchable - it inherits the app's theme).
THEMES = {
    "default": {  # dark navy + gold (the original, polished look)
        "--bg": "#0e1621", "--panel": "#172230", "--panel2": "#1f2d3d",
        "--line": "#2b3a4d", "--text": "#e8edf3", "--muted": "#92a2b5",
        "--accent": "#c8a24a", "--accent-ink": "#1a1305",
        "--font": "Segoe UI,Roboto,Arial,sans-serif",
    },
    "corporate": {  # light (but not white) - clean, boardroom-friendly
        "--bg": "#e9edf3", "--panel": "#f7f9fc", "--panel2": "#dde4ee",
        "--line": "#c2ccda", "--text": "#1f2a37", "--muted": "#5a6b80",
        "--accent": "#1d4ed8", "--accent-ink": "#ffffff",
        "--font": "Segoe UI,Calibri,Arial,sans-serif",
    },
    "cyber": {  # hacker terminal - neon green on near-black, monospace
        "--bg": "#04070a", "--panel": "#0a1110", "--panel2": "#0c1714",
        "--line": "#163a2a", "--text": "#9dffc4", "--muted": "#4f9e78",
        "--accent": "#2bff88", "--accent-ink": "#02140a",
        "--font": "Consolas,ui-monospace,SFMono-Regular,monospace",
    },
}
DEFAULT_THEME = "default"
THEME_LABELS = [("default", "Default"), ("corporate", "Corporate (light)"),
                ("cyber", "Cybersecurity")]


def _vars_block(palette: dict) -> str:
    return "".join(f"{k}:{v};" for k, v in palette.items())


def _theme_css() -> str:
    """`[data-theme=...]` override blocks injected into the app's <style>."""
    return "\n".join(f'[data-theme="{n}"]{{{_vars_block(p)}}}' for n, p in THEMES.items())


@app.route("/")
def index():
    return render_template("index.html",
                           weights=audit.WEIGHTS,
                           default_selectors=", ".join(audit.DEFAULT_DKIM_SELECTORS),
                           theme_css=_theme_css(),
                           themes=THEME_LABELS,
                           default_theme=DEFAULT_THEME)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    domains = audit.parse_domain_input(data.get("domains", ""))
    nameserver = (data.get("nameserver") or "").strip() or None
    fetch_policy = bool(data.get("fetch_mta_policy", True))
    probe_transport = bool(data.get("probe_transport", False))
    save_hist = bool(data.get("save_history", False))
    sel_text = (data.get("selectors") or "").strip()
    selectors = [s.strip() for s in sel_text.replace("\n", ",").split(",") if s.strip()] \
        if sel_text else None

    if not domains:
        return jsonify({"error": "No valid domains provided."}), 400

    def generate():
        summary = {
            "total": 0, "risk": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
            "dmarc": {"enforced": 0, "monitor": 0, "missing": 0, "ineffective": 0},
            "spf_missing": 0, "dkim_missing": 0,
        }
        collected = []

        # Stream results as each domain finishes.
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {pool.submit(audit.scan_domain, d, selectors, nameserver,
                                   fetch_policy, probe_transport): d for d in domains}
            for fut in as_completed(futures):
                res = fut.result()
                _tally(summary, res)
                collected.append(res.to_dict())
                yield json.dumps({"event": "result", "result": res.to_dict()}) + "\n"

        summary["total"] = len(domains)
        if save_hist and collected:
            try:
                summary["history_file"] = history.save_run(collected)
            except Exception as e:
                summary["history_error"] = str(e)
        yield json.dumps({"event": "done", "summary": summary}) + "\n"

    return Response(stream_with_context(generate()),
                    mimetype="application/x-ndjson")


def _tally(summary, res: audit.DomainResult):
    if not res.valid:
        return
    summary["risk"][res.risk] = summary["risk"].get(res.risk, 0) + 1
    if res.dmarc_base in ("Enforced", "Enf-SPF", "Enf-DKIM", "Enf-NoAuth"):
        summary["dmarc"]["enforced"] += 1
    elif res.dmarc_base == "Monitor":
        summary["dmarc"]["monitor"] += 1
    elif res.dmarc_base == "Missing":
        summary["dmarc"]["missing"] += 1
    elif res.dmarc_base == "Ineffective":
        summary["dmarc"]["ineffective"] += 1
    if not res.checks["SPF"].ok:
        summary["spf_missing"] += 1
    if not res.checks["DKIM"].ok:
        summary["dkim_missing"] += 1


# --------------------------- Extra endpoints ------------------------------- #

@app.route("/api/analyze-headers", methods=["POST"])
def api_analyze_headers():
    data = request.get_json(force=True, silent=True) or {}
    return jsonify(headers_mod.analyze_headers(data.get("raw", "")))


@app.route("/api/scoring")
def api_scoring():
    return jsonify(audit.scoring_model())


@app.route("/api/history")
def api_history():
    runs = [{"path": p, "name": p.replace("\\", "/").split("/")[-1]}
            for p in history.list_runs()]
    return jsonify({"runs": runs})


@app.route("/api/history/compare-latest", methods=["POST"])
def api_compare_latest():
    """Diff the current (posted) results against the most recent saved run."""
    data = request.get_json(force=True, silent=True) or {}
    results = data.get("results", [])
    runs = history.list_runs()
    if not runs:
        return jsonify({"error": "No prior runs saved yet."}), 404
    prev = history.load_run(runs[-1])
    current = {"timestamp": "current", "results": results}
    return jsonify(history.diff_runs(prev, current))


# ----------------------------- Exports ------------------------------------- #

COLUMNS = ["SPF", "DKIM", "DMARC", "MX", "MTA-STS", "TLS-RPT", "BIMI", "DNSSEC", "CAA"]


@app.route("/api/export/<fmt>", methods=["POST"])
def api_export(fmt):
    data = request.get_json(force=True, silent=True) or {}
    results = data.get("results", [])
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        body = json.dumps(results, indent=2)
        return _download(body, f"email_security_{ts}.json", "application/json")

    if fmt == "csv":
        out = io.StringIO()
        out.write("Domain," + ",".join(COLUMNS) + ",Score,Grade,Risk\n")
        for r in results:
            row = [r["domain"]]
            row += [r["checks"][c]["status"].replace(",", " ") for c in COLUMNS]
            row += [str(r["score"]), r["grade"], r["risk"]]
            out.write(",".join(row) + "\n")
        return _download(out.getvalue(), f"email_security_{ts}.csv", "text/csv")

    if fmt == "html":
        theme = data.get("theme") or DEFAULT_THEME
        return _download(_render_html_report(results, ts, theme),
                         f"email_security_{ts}.html", "text/html")

    return jsonify({"error": "Unknown format"}), 400


def _download(body, filename, mimetype):
    return Response(body, mimetype=mimetype,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _render_html_report(results, ts, theme=DEFAULT_THEME):
    """Render the HTML report (see report.py) using the given app theme's palette."""
    theme = theme if theme in THEMES else DEFAULT_THEME
    return report.render(results, ts, COLUMNS, _vars_block(THEMES[theme]), theme,
                         audit.scoring_model())


if __name__ == "__main__":
    print("MX Sentinel UI -> http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
