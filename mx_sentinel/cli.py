"""
Command-line interface for CI/automation.

Examples:
  python cli.py example.com google.com
  python cli.py -c domains.csv --json out.json
  python cli.py -c domains.csv --fail-under 75 --fail-risk High   # CI gate
  python cli.py example.com --transport --save-history
  python cli.py --compare history/run_A.json history/run_B.json

Exit codes:
  0  success (and thresholds met)
  1  usage / input error
  2  threshold breach (--fail-under / --fail-risk) or regression on --compare
"""

from __future__ import annotations

import argparse
import json
import sys

import audit
import history

RISK_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3, "Unknown": -1}


def _read_csv(path: str) -> str:
    with open(path, encoding="utf-8-sig") as f:
        return f.read()


def _print_table(results):
    cols = ["SPF", "DKIM", "DMARC", "DNSSEC", "MTA-STS"]
    print(f"{'Domain':<30} {'Score':>5} {'Grade':<10} {'Risk':<9} " +
          " ".join(f"{c:<14}" for c in cols))
    print("-" * 110)
    for r in sorted(results, key=lambda x: x.get("score", 0)):
        if not r.get("valid", True):
            print(f"{r['domain']:<30} {'-':>5} {'INVALID':<10} {r.get('error','')}")
            continue
        cells = " ".join(f"{r['checks'][c]['status']:<14}" for c in cols)
        print(f"{r['domain']:<30} {r['score']:>5} {r['grade']:<10} "
              f"{r['risk']:<9} {cells}")


def cmd_compare(a: str, b: str) -> int:
    diff = history.diff_runs(history.load_run(a), history.load_run(b))
    print(f"Comparing {diff['old_ts']}  ->  {diff['new_ts']}")
    if diff["added"]:
        print("  Added:   " + ", ".join(diff["added"]))
    if diff["removed"]:
        print("  Removed: " + ", ".join(diff["removed"]))
    for c in diff["changed"]:
        tag = "REGRESSED" if c["regressed"] else "changed"
        bits = []
        for k, (o, n) in {**c["deltas"], **c["controls"]}.items():
            bits.append(f"{k}: {o} -> {n}")
        print(f"  [{tag}] {c['domain']}: " + "; ".join(bits))
    if not diff["changed"] and not diff["added"] and not diff["removed"]:
        print("  No changes.")
    if diff["regressions"]:
        print("\nRegressions: " + ", ".join(diff["regressions"]))
        return 2
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Email security audit (CLI).")
    p.add_argument("domains", nargs="*", help="domains to scan")
    p.add_argument("-c", "--csv", help="CSV/text file of domains")
    p.add_argument("--json", metavar="FILE", help="write JSON results")
    p.add_argument("--csv-out", metavar="FILE", help="write CSV summary")
    p.add_argument("--html", metavar="FILE", help="write interactive HTML report")
    p.add_argument("--nameserver", help="custom DNS resolver IP")
    p.add_argument("--selectors", help="comma-separated DKIM selectors")
    p.add_argument("--workers", type=int, default=8, help="concurrency (default 8)")
    p.add_argument("--transport", action="store_true",
                   help="probe MX STARTTLS/cert/DANE (needs outbound port 25)")
    p.add_argument("--no-mta-policy", action="store_true",
                   help="skip fetching MTA-STS policy files")
    p.add_argument("--save-history", action="store_true",
                   help="save this run under history/ for later diffing")
    p.add_argument("--fail-under", type=int, metavar="SCORE",
                   help="exit 2 if any domain scores below SCORE")
    p.add_argument("--fail-risk", metavar="LEVEL",
                   help="exit 2 if any domain is at/above LEVEL (Medium/High/Critical)")
    p.add_argument("--compare", nargs=2, metavar=("OLD", "NEW"),
                   help="diff two saved history runs and exit")
    p.add_argument("--quiet", action="store_true", help="suppress the table")
    args = p.parse_args(argv)

    if args.compare:
        return cmd_compare(*args.compare)

    text = " ".join(args.domains)
    if args.csv:
        try:
            text += "\n" + _read_csv(args.csv)
        except OSError as e:
            print(f"Cannot read CSV: {e}", file=sys.stderr)
            return 1
    domains = audit.parse_domain_input(text)
    if not domains:
        print("No domains provided.", file=sys.stderr)
        return 1

    selectors = [s.strip() for s in args.selectors.split(",")] if args.selectors else None
    results = audit.scan_domains(
        domains, selectors=selectors, nameserver=args.nameserver,
        fetch_mta_policy=not args.no_mta_policy, probe_transport=args.transport,
        max_workers=args.workers)
    dicts = [r.to_dict() for r in results]

    if not args.quiet:
        _print_table(dicts)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(dicts, f, indent=2)
        print(f"Wrote {args.json}")
    if args.csv_out:
        import app
        with open(args.csv_out, "w", encoding="utf-8", newline="") as f:
            f.write("Domain," + ",".join(app.COLUMNS) + ",Score,Grade,Risk\n")
            for r in dicts:
                if not r.get("valid", True):
                    continue
                row = [r["domain"]] + [r["checks"][c]["status"].replace(",", " ")
                                       for c in app.COLUMNS]
                row += [str(r["score"]), r["grade"], r["risk"]]
                f.write(",".join(row) + "\n")
        print(f"Wrote {args.csv_out}")
    if args.html:
        import app
        from datetime import datetime
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(app._render_html_report(dicts, datetime.now().strftime("%Y%m%d_%H%M%S")))
        print(f"Wrote {args.html}")
    if args.save_history:
        path = history.save_run(dicts)
        print(f"Saved history: {path}")

    # CI gates
    exit_code = 0
    valid = [r for r in dicts if r.get("valid", True)]
    if args.fail_under is not None:
        below = [r["domain"] for r in valid if r["score"] < args.fail_under]
        if below:
            print(f"\nFAIL: below score {args.fail_under}: " + ", ".join(below),
                  file=sys.stderr)
            exit_code = 2
    if args.fail_risk:
        thr = RISK_ORDER.get(args.fail_risk.capitalize())
        if thr is None:
            print(f"Unknown risk level: {args.fail_risk}", file=sys.stderr)
            return 1
        bad = [r["domain"] for r in valid if RISK_ORDER.get(r["risk"], -1) >= thr]
        if bad:
            print(f"\nFAIL: at/above risk {args.fail_risk}: " + ", ".join(bad),
                  file=sys.stderr)
            exit_code = 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
