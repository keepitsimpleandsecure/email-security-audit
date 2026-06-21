"""
Message header analyzer: given a raw email (at least its headers), determine the
SPF / DKIM / DMARC verdicts and - crucially - whether they are *aligned* with the
visible From: domain. Alignment is what DMARC actually enforces, and it cannot be
seen from DNS alone.

Verdicts are read from the receiver's Authentication-Results header when present;
alignment is computed from From / Return-Path / DKIM-Signature d=.
"""

from __future__ import annotations

import re
from email import message_from_string
from email.utils import parseaddr

import audit  # reuse the Public-Suffix-List organizational-domain logic


def _domain_of(addr: str) -> str:
    addr = parseaddr(addr or "")[1]
    return addr.split("@")[-1].lower().strip(">").strip() if "@" in addr else ""


def _org(d: str) -> str:
    return audit.org_domain(d) if d else ""


def _ar_verdict(ar_text: str, method: str):
    m = re.search(rf"\b{method}=(\w+)", ar_text, re.IGNORECASE)
    return m.group(1).lower() if m else None


def analyze_headers(raw: str) -> dict:
    raw = (raw or "").strip()
    if not raw:
        return {"error": "No headers provided."}

    msg = message_from_string(raw)
    from_domain = _domain_of(msg.get("From", ""))
    rp_domain = _domain_of(msg.get("Return-Path", ""))

    ar_text = " ".join(msg.get_all("Authentication-Results", []) or [])
    have_ar = bool(ar_text.strip())
    spf_res = _ar_verdict(ar_text, "spf")
    dkim_res = _ar_verdict(ar_text, "dkim")
    dmarc_res = _ar_verdict(ar_text, "dmarc")

    # DKIM-Signature d= domains (there can be several).
    dkim_domains = []
    for sig in msg.get_all("DKIM-Signature", []) or []:
        m = re.search(r"\bd=([^;\s]+)", sig)
        if m:
            dkim_domains.append(m.group(1).lower().rstrip("."))

    # Alignment (DMARC default is relaxed = organizational-domain match).
    spf_aligned = bool(rp_domain and from_domain and _org(rp_domain) == _org(from_domain))
    dkim_aligned_domains = [d for d in dkim_domains
                            if from_domain and _org(d) == _org(from_domain)]
    dkim_aligned = bool(dkim_aligned_domains)

    spf_pass = spf_res == "pass"
    dkim_pass = dkim_res == "pass"
    # DMARC passes when an aligned, authenticated mechanism passes.
    dmarc_pass = (spf_pass and spf_aligned) or (dkim_pass and dkim_aligned)

    notes = []
    if not from_domain:
        notes.append("No parseable From: header found.")
    if not have_ar:
        notes.append("No Authentication-Results header - SPF/DKIM verdicts are "
                     "unknown (this is normal for a message you sent, vs. one you "
                     "received). Alignment below is still computed from the headers.")
    if spf_pass and not spf_aligned:
        notes.append(f"SPF passed for the envelope domain ({rp_domain or 'n/a'}) but "
                     f"it is NOT aligned with From: ({from_domain}) - SPF does not "
                     "contribute to DMARC here.")
    if dkim_pass and not dkim_aligned and dkim_domains:
        notes.append(f"DKIM passed for {', '.join(dkim_domains)} but none align with "
                     f"From: ({from_domain}).")
    if dmarc_res and (dmarc_res == "pass") != dmarc_pass:
        notes.append(f"Receiver reported dmarc={dmarc_res}; computed alignment "
                     f"differs - check the raw Authentication-Results.")

    return {
        "from_domain": from_domain,
        "return_path_domain": rp_domain,
        "auth_results_present": have_ar,
        "spf": {"result": spf_res, "aligned": spf_aligned},
        "dkim": {"result": dkim_res, "aligned": dkim_aligned,
                 "domains": dkim_domains, "aligned_domains": dkim_aligned_domains},
        "dmarc": {"reported": dmarc_res, "computed_pass": dmarc_pass},
        "verdict": "PASS" if dmarc_pass else ("FAIL" if have_ar else "UNKNOWN"),
        "notes": notes,
    }
