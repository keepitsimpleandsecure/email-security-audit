# MX Sentinel

A cross-platform **email-security posture auditor**. It checks a domain's
anti-spoofing and mail-hardening DNS records — **SPF, DKIM, DMARC, MX, MTA-STS,
TLS-RPT, BIMI, DNSSEC, CAA** — scores the result, classifies the spoofing risk,
and produces actionable, provider-agnostic remediation. Runs as a local **web
app**, exports a self-contained **interactive HTML report**, and ships a **CLI**
for automation/CI.

Pure Python (no `dig`/`curl`/bash) — works on **Windows, macOS, and Linux**.

---

## Quick start

### Windows
Double-click **`run.bat`**. It creates a virtual environment, installs
dependencies, starts the app, and opens `http://127.0.0.1:5000`.

### Any OS
```bash
pip install -r requirements.txt
python mx_sentinel/app.py
# open http://127.0.0.1:5000
```

---

## Web app

- Paste domains (comma / space / newline separated) **or drag-and-drop a
  `.csv`/`.txt`** file onto the domains box (or use "Load CSV").
- **Concurrent** scanning (8 domains in parallel) with a live progress bar.
- Sortable, colour-coded results table; click a row to expand per-control detail
  and recommendations.
- Summary tiles: **Protected / Partial / At-risk** counts, average score, and
  per-control good/bad breakdowns.
- One-click export to **CSV / JSON** and a **self-contained interactive HTML
  report**.
- **Themes** (top-right, remembered across sessions):
  - **Default** — dark navy + gold
  - **Corporate** — light, boardroom-friendly
  - **Cybersecurity** — neon-green hacker terminal
  The exported HTML report inherits whichever theme is active at export time.
- Extras: optional **MX transport probe** (STARTTLS / cert / DANE), a
  **message-header analyzer** (computes real SPF/DKIM/**DMARC alignment** from a
  pasted email), **run history + "compare to last run"** regression diff, a
  **scoring-rationale** panel, custom DNS resolver, and editable DKIM selectors.

> The HTML report is interactive on screen; its "Print / Save PDF" button is
> currently disabled (PDF layout is a work in progress).

---

## Command line (automation / CI)

```bash
python mx_sentinel/cli.py example.com google.com        # scan + print a table
python mx_sentinel/cli.py -c domains.csv --json out.json --html report.html
python mx_sentinel/cli.py -c domains.csv --fail-under 75 --fail-risk High   # CI gate
python mx_sentinel/cli.py example.com --transport --save-history
python mx_sentinel/cli.py --compare history/run_A.json history/run_B.json   # diff runs
```

Useful flags: `--nameserver <ip>`, `--selectors a,b,c`, `--workers N`,
`--no-mta-policy`, `--quiet`.
**Exit codes:** `0` ok · `1` usage/input error · `2` threshold breach
(`--fail-under` / `--fail-risk`) or a regression on `--compare`.

---

## What it checks

| Control | What it validates |
|---|---|
| **SPF** | Record present & single (multiple = permerror); terminal `all` qualifier (`-all`/`~all`/`?all`/`+all`); **recursive** evaluation following `include:`/`redirect=` to flag the RFC 7208 **>10-lookup PERMERROR**, void lookups and loops. `+all` is flagged HIGH (authorizes any server). |
| **DKIM** | Probes common selectors; distinguishes **active vs revoked** (empty `p=`) keys, weak **<1024-bit** RSA, **testing mode** (`t=y`), and recognizes **key-rotation pairs** (e.g. M365 `selector1`/`selector2`). Selectors can't be enumerated via DNS, so a no-match is "Not detected", not proof of absence. |
| **DMARC** | Policy + **`pct=`** parsing; **RFC 7489 subdomain inheritance** (`sp=`/`p=` from the organizational domain via the Public Suffix List); effectiveness judged against SPF/DKIM (see model below). |
| **MX** | Present / **null MX** (RFC 7505, intentional "no mail") / none / **Unknown** (lookup failed — never inferred as "no mail"). |
| **DNSSEC** | Real validation via a validating resolver's **AD flag**, plus DNSKEY + parent **DS**; signed-but-unanchored = "Partial". |
| **MTA-STS** | TXT + fetched policy **`mode:`** (`enforce` vs `testing`/`none`); missing/invalid policy file = "Broken". |
| **TLS-RPT / BIMI / CAA** | Presence and basic validity. |

Findings are severity-ranked and remediation is **provider-agnostic**
(placeholders, no hard-coded Google/Let's Encrypt) and **phased**
(DMARC `none → quarantine → reject`; SPF `~all → -all`).

---

## Scoring & risk model

The **score** (0–100, weighted) measures control completeness; the **risk** tier
measures anti-spoofing exposure. They are different axes.

- **Weights:** SPF 20 · DKIM 20 · DMARC 20 · MX 15 · DNSSEC 10 · MTA-STS 5 ·
  TLS-RPT 3 · BIMI 2 · CAA 5. **Grades:** Excellent ≥90 · Good ≥75 · Fair ≥50 ·
  Poor <50.
- **Non-sending domains** (no MX / null MX) are graded on **SPF + DMARC only** —
  the mail-flow controls (DKIM/MX/MTA-STS/TLS-RPT/BIMI) don't apply. A correct
  no-mail lockdown (`v=spf1 -all` + `p=reject`) scores Excellent / Low risk.

**Risk tiers:**

| DMARC posture | Sending (has MX) | Non-sending |
|---|---|---|
| Enforced + SPF + DKIM | Low | Low |
| Enf-SPF / Enf-DKIM (single authenticator) | Medium | Low |
| Enf-NoAuth (enforced, no SPF/DKIM) — spoofing blocked, own mail breaks | Medium | Low |
| **Ineffective** (`+all` lets anyone pass DMARC) | **High** | **High** |
| Monitor (`p=none` / `pct=0`) | Medium | Medium |
| Missing / Invalid | High (Critical if no SPF & no DKIM) | High / Critical |

A failed MX lookup (`Unknown`) is treated as a sending domain (full scale,
conservative) so a flaky DNS response never inflates the grade.

---

## Project layout

```
email-security-audit/
├─ run.bat                 one-click Windows launcher (venv + deps + start)
├─ requirements.txt        Flask, dnspython, requests, tldextract, cryptography
├─ README.md  LICENSE  .gitignore
└─ mx_sentinel/            all application code
   ├─ app.py               Flask web UI + JSON/CSV/HTML export + themes
   ├─ audit.py             core checks, recursive SPF, scoring & risk model
   ├─ report.py            self-contained interactive HTML report generator
   ├─ headers.py           message-header SPF/DKIM/DMARC alignment analyzer
   ├─ transport.py         optional MX STARTTLS / certificate / DANE probing
   ├─ history.py           save runs and diff them (regression detection)
   ├─ cli.py               command-line entrypoint for CI/automation
   └─ templates/index.html the single-page web GUI
```

---

## Limitations

- **DKIM** selectors can't be enumerated from DNS — detection is best-effort
  (add known selectors in the scan options); RSA key size is estimated from the
  DER length (nearest standard size), and Ed25519 keys aren't sized.
- The **transport probe** needs outbound **port 25** (blocked on many networks);
  it's off by default and never affects the score.
- The **header analyzer** trusts the receiver's `Authentication-Results`; it does
  not re-verify DKIM signatures cryptographically. DMARC alignment is evaluated
  in **relaxed** mode (organizational-domain match).
- This is a **passive DNS-based** audit: it does not recursively resolve SPF
  `include:` chains to a true lookup count beyond flagging the limit, nor test
  live SMTP delivery.

---

## License

MIT License — see [LICENSE](LICENSE).
