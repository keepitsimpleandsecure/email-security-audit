"""
Email Security Audit - core checks (Windows/cross-platform Python port).

Pure logic, no UI. Each public check function inspects DNS (and a little HTTP)
for one email-security control and returns a structured result.

Controls: SPF, DKIM, DMARC, MX, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA.

This is a faithful port of the original email-security-audit.sh scoring model,
with concurrency, timeouts and structured output added on top.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Callable

import dns.resolver
import dns.exception
import dns.message
import dns.query
import dns.flags
import dns.rdatatype

try:
    import requests
except ImportError:  # requests is only needed for the optional MTA-STS policy fetch
    requests = None

try:
    import tldextract
    # suffix_list_urls=() forces the bundled PSL snapshot: no network call, deterministic.
    _extract = tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # tldextract optional; fall back to a naive 2-label heuristic
    _extract = None


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

WEIGHTS = {
    "SPF": 20,
    "DKIM": 20,
    "DMARC": 20,
    "MX": 15,
    "DNSSEC": 10,
    "MTA-STS": 5,
    "TLS-RPT": 3,
    "BIMI": 2,
    "CAA": 5,
}
MAX_SCORE = sum(WEIGHTS.values())  # 100

# Common DKIM selectors (Google + enterprise). Editable from the UI.
DEFAULT_DKIM_SELECTORS = [
    "google", "20220809", "20210223", "20161025", "krs",
    "mx", "s1", "s2", "selector1", "selector2", "dkim",
    "domainkey", "signer", "em", "default", "key1",
    "key2", "phishprotection", "mandrill", "everlytickey1",
]

DNS_TIMEOUT = 5.0  # seconds per query / total lifetime

_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")


def is_valid_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain.strip()))


def scoring_model() -> dict:
    """Expose the (heuristic) scoring rationale so it is transparent, not a black box."""
    return {
        "max_score": MAX_SCORE,
        "weights": dict(WEIGHTS),
        "grades": [
            {"grade": "Excellent", "min": 90},
            {"grade": "Good", "min": 75},
            {"grade": "Fair", "min": 50},
            {"grade": "Poor", "min": 0},
        ],
        "risk": (
            "Risk reflects anti-spoofing posture, not the raw score: "
            "Critical = no DMARC and no SPF/DKIM (fully spoofable); "
            "High = no/invalid DMARC but some authentication present; "
            "Medium = DMARC monitor-only, single-authenticator enforcement, or "
            "enforced-but-no-SPF/DKIM on a mail-sending domain (deliverability risk); "
            "Low = DMARC enforced with SPF and DKIM, or an enforced no-mail lockdown."
        ),
        "notes": (
            "Weights are heuristic and emphasize the controls that actually stop "
            "spoofing (SPF/DKIM/DMARC = 60/100). Partial credit is given for weak "
            "configurations (e.g. ~all, p=quarantine, MTA-STS testing mode). "
            "Domains that neither send nor receive mail (no MX / null MX) are graded "
            "on SPF + DMARC only - the mail-flow controls (DKIM, MX, MTA-STS, TLS-RPT, "
            "BIMI) do not apply and are excluded. The transport probe (STARTTLS/DANE) "
            "and header-alignment analysis are advisory and do not change the score."
        ),
    }


def org_domain(domain: str) -> str:
    """Return the organizational (registrable) domain, e.g.
    mail.corp.example.co.uk -> example.co.uk. Uses the Public Suffix List."""
    domain = domain.strip().lower().rstrip(".")
    if _extract is not None:
        reg = _extract(domain).registered_domain
        if reg:
            return reg
    # Fallback: last two labels (imperfect for multi-level TLDs like co.uk)
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def is_subdomain(domain: str) -> bool:
    """True if domain is below its organizational domain (e.g. mail.example.com)."""
    domain = domain.strip().lower().rstrip(".")
    return domain != org_domain(domain)


# --------------------------------------------------------------------------- #
# DNS helpers
# --------------------------------------------------------------------------- #

# A process-wide DNS cache so repeated lookups across many domains in one run
# (and the recursive SPF walk) don't re-query the same names.
_DNS_CACHE = dns.resolver.LRUCache(max_size=10000)


def _make_resolver(nameserver: str | None = None) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    r.cache = _DNS_CACHE
    if nameserver:
        r.nameservers = [nameserver]
    return r


def _query(resolver: dns.resolver.Resolver, name: str, rdtype: str) -> list[str]:
    """Return record strings for name/rdtype, or [] on any miss/error."""
    try:
        answers = resolver.resolve(name, rdtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.exception.DNSException):
        return []
    out = []
    for rdata in answers:
        if rdtype == "TXT":
            # TXT rdata can be split into multiple quoted strings; join them.
            try:
                out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
            except Exception:
                out.append(str(rdata).strip('"'))
        else:
            out.append(rdata.to_text())
    return out


def _txt(resolver, name: str) -> list[str]:
    return _query(resolver, name, "TXT")


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #

@dataclass
class CheckResult:
    """One control's outcome."""
    status: str          # short label for the table (e.g. "OK (-all)")
    ok: bool             # passed / present
    score: int           # points earned
    weight: int          # max points
    severity: str = ""   # HIGH / MEDIUM / LOW (only when failing)
    detail: str = ""     # human-readable explanation
    records: list = field(default_factory=list)  # raw records found


@dataclass
class DomainResult:
    domain: str
    valid: bool = True
    error: str = ""
    score: int = 0
    grade: str = ""
    risk: str = "Unknown"
    elapsed: float = 0.0
    checks: dict = field(default_factory=dict)        # name -> CheckResult
    dkim_count: int = 0
    dmarc_policy: str = "-"
    dmarc_base: str = "Missing"      # Enforced/Enf-SPF/Enf-DKIM/Enf-NoAuth/Ineffective/Monitor/Missing
    dmarc_inherited: bool = False
    recommendations: list = field(default_factory=list)
    transport: dict = field(default_factory=dict)     # optional STARTTLS/DANE probe

    def to_dict(self) -> dict:
        d = asdict(self)
        d["checks"] = {k: asdict(v) for k, v in self.checks.items()}
        return d


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #

def _spf_all_qualifier(rec: str):
    """Return the qualifier on the terminal 'all' mechanism: '-', '~', '?', '+'
    (bare 'all' == '+'), or None if there is no 'all'."""
    for term in rec.split():
        m = re.fullmatch(r"([-~?+]?)all", term, re.IGNORECASE)
        if m:
            return m.group(1) or "+"
    return None


@dataclass
class SpfEval:
    """Result of recursively evaluating an SPF record per RFC 7208 §4.6.4."""
    lookups: int = 0          # DNS-querying mechanisms encountered (limit 10)
    voids: int = 0            # lookups that returned no data / NXDOMAIN (limit 2)
    permerror: bool = False   # record is unevaluable (over limits, loop, bad include)
    notes: list = field(default_factory=list)


def _spf_record(resolver, domain):
    recs = [r for r in _txt(resolver, domain) if r.strip().lower().startswith("v=spf1")]
    return recs[0] if recs else None


def _spf_evaluate(resolver, domain, record=None, state=None, seen=None, depth=0):
    """Walk an SPF record, following include:/redirect= recursively, and count the
    DNS-lookup mechanisms (include, a, mx, ptr, exists, redirect) against the RFC
    limit of 10. Tracks void lookups and flags permerror conditions."""
    if state is None:
        state = SpfEval()
    if seen is None:
        seen = set()
    key = domain.lower().rstrip(".")
    if key in seen:
        state.permerror = True
        state.notes.append(f"include/redirect loop at {domain}")
        return state
    seen.add(key)
    if depth > 15:
        state.permerror = True
        state.notes.append("excessive recursion depth")
        return state
    if record is None:
        record = _spf_record(resolver, domain)
    if record is None:
        state.voids += 1
        state.permerror = True  # include/redirect target with no SPF record
        state.notes.append(f"{domain}: no SPF record (include/redirect target)")
        return state

    for term in record.split()[1:]:               # skip the leading v=spf1
        bare = term.lstrip("-~?+").lower()
        if bare.startswith("include:"):
            state.lookups += 1
            _spf_evaluate(resolver, term.split(":", 1)[1], None, state, seen, depth + 1)
        elif bare.startswith("redirect="):
            state.lookups += 1
            _spf_evaluate(resolver, term.split("=", 1)[1], None, state, seen, depth + 1)
        elif bare == "mx" or bare.startswith("mx:"):
            state.lookups += 1
            host = domain if bare == "mx" else term.split(":", 1)[1]
            if not _query(resolver, host, "MX"):
                state.voids += 1
        elif bare == "a" or bare.startswith(("a:", "a/")):
            state.lookups += 1
            host = domain if bare == "a" else re.split("[:/]", term, 1)[1]
            if not (_query(resolver, host, "A") or _query(resolver, host, "AAAA")):
                state.voids += 1
        elif bare.startswith("exists:"):
            state.lookups += 1
        elif bare == "ptr" or bare.startswith("ptr:"):
            state.lookups += 1  # ptr is also deprecated; flagged by caller
        # ip4:/ip6:/all and unknown modifiers cost no DNS lookup

        if state.lookups > 10:
            state.permerror = True

    if state.voids > 2:
        state.permerror = True
        if "void" not in " ".join(state.notes):
            state.notes.append(f"{state.voids} void lookups (limit 2)")
    return state


def check_spf(resolver, domain) -> CheckResult:
    w = WEIGHTS["SPF"]
    records = [r for r in _txt(resolver, domain)
               if r.strip().lower().startswith("v=spf1")]

    if not records:
        return CheckResult(
            "Missing", False, 0, w, "HIGH",
            "No SPF record. Receivers cannot tell which servers may send for this "
            "domain. Note: SPF alone does not stop From-header spoofing - it must be "
            "paired with DMARC. A non-sending domain should publish 'v=spf1 -all'.")

    # RFC 7208: more than one SPF record is a permanent error -> SPF is ignored.
    if len(records) > 1:
        return CheckResult(
            "Invalid (multiple)", False, 0, w, "HIGH",
            f"{len(records)} SPF records found. RFC 7208 permits only one; multiple "
            "records cause a permerror and SPF is treated as unverifiable.",
            records=records)

    rec = records[0]
    qual = _spf_all_qualifier(rec)
    ev = _spf_evaluate(resolver, domain, rec)
    lookup_note = ""
    if ev.permerror:
        if ev.lookups > 10:
            lookup_note = (f" Warning: SPF uses {ev.lookups} DNS lookups (recursively "
                           "following includes); RFC 7208 caps this at 10, so "
                           "evaluation returns PERMERROR and SPF is effectively ignored.")
        else:
            lookup_note = " Warning: SPF PERMERROR - " + "; ".join(ev.notes) + "."
    elif ev.lookups >= 8:
        lookup_note = (f" Note: {ev.lookups}/10 SPF DNS lookups used - close to the "
                       "RFC 7208 limit.")

    if qual == "-":
        res = CheckResult("OK (-all)", True, w, w,
                          detail="Hard-fail policy (-all): unlisted senders are "
                                 "rejected." + lookup_note, records=records)
    elif qual == "~":
        res = CheckResult("Soft (~all)", True, w * 3 // 4, w, "LOW",
                          "Soft-fail (~all): unlisted senders are marked, not "
                          "rejected. Move to '-all' once all legitimate senders are "
                          "confirmed." + lookup_note, records=records)
    elif qual == "+":
        res = CheckResult("Dangerous (+all)", False, 0, w, "HIGH",
                          "'+all' authorizes ANY server on the internet to send as "
                          "this domain - worse than having no SPF. Replace with "
                          "'-all'." + lookup_note, records=records)
    elif qual == "?":
        res = CheckResult("Weak (?all)", False, w // 4, w, "MEDIUM",
                          "'?all' (neutral) asserts nothing about unlisted senders, "
                          "giving no protection. Use '-all' or '~all'." + lookup_note,
                          records=records)
    else:  # no 'all' mechanism at all -> default neutral
        res = CheckResult("Weak (no all)", False, w // 4, w, "MEDIUM",
                          "SPF has no terminating 'all' mechanism, so unlisted "
                          "senders default to neutral (no protection). Add '-all'."
                          + lookup_note, records=records)

    # A PERMERROR means receivers cannot evaluate SPF at all - cap an otherwise
    # "good" record hard, since in practice it provides no protection.
    if ev.permerror and res.ok:
        res.ok = False
        res.severity = "HIGH"
        res.score = min(res.score, w // 4)
        res.status = res.status + " · PERMERROR"
    return res


def _dkim_key_bits(p_b64: str):
    """Estimate the public-key size (bits) from a DKIM p= value. Returns None if
    it cannot be parsed. Works for RSA SubjectPublicKeyInfo DER without crypto deps."""
    import base64
    try:
        der = base64.b64decode(p_b64 + "===")
    except Exception:
        return None
    # The modulus is the largest INTEGER in the DER; approximate via DER length.
    # SPKI overhead is ~24-40 bytes; round to the nearest common RSA size.
    approx_bits = max(0, (len(der) - 38)) * 8
    for size in (512, 768, 1024, 2048, 3072, 4096):
        if approx_bits <= size + 64:
            return size
    return approx_bits


# Well-known DKIM key-rotation selector pairs (e.g. Microsoft 365 uses
# selector1/selector2, alternating the live key as it rotates).
_DKIM_ROTATION_PAIRS = [("selector1", "selector2"), ("s1", "s2"),
                        ("key1", "key2"), ("dkim1", "dkim2")]


def _dkim_rotation_sibling(sel: str):
    for a, b in _DKIM_ROTATION_PAIRS:
        if sel == a:
            return b
        if sel == b:
            return a
    return None


def check_dkim(resolver, domain, selectors) -> CheckResult:
    w = WEIGHTS["DKIM"]
    active, revoked, weak, testing = [], [], [], []
    for sel in selectors:
        recs = [r for r in _txt(resolver, f"{sel}._domainkey.{domain}") if "v=DKIM1" in r]
        if not recs:
            continue
        rec = recs[0]
        # A DKIM record with an empty p= tag is a revoked/withdrawn key.
        if re.search(r"\bp=\s*([;\s]|$)", rec):
            revoked.append(sel)
            continue
        active.append(sel)
        # Flag testing mode (t=y) and short keys.
        flags = re.search(r"\bt=([^;\s]+)", rec)
        if flags and "y" in flags.group(1).split(":"):
            testing.append(sel)
        pm = re.search(r"\bp=([A-Za-z0-9+/=]+)", rec)
        ktype = re.search(r"\bk=([^;\s]+)", rec)
        if pm and (not ktype or ktype.group(1).lower() == "rsa"):
            bits = _dkim_key_bits(pm.group(1))
            if bits and bits < 1024:
                weak.append(f"{sel}:{bits}-bit")

    # A revoked (empty p=) selector whose rotation sibling is active is just an
    # idle key-rotation slot (e.g. Microsoft 365 selector1/selector2), not a fault.
    active_set = set(active)
    rotation_idle = [s for s in revoked if _dkim_rotation_sibling(s) in active_set]
    revoked = [s for s in revoked if s not in rotation_idle]
    rotating = len(active) >= 2 or any(a in active_set and b in active_set
                                       for a, b in _DKIM_ROTATION_PAIRS)

    if active:
        detail = "Active selector(s): " + ", ".join(active) + "."
        if rotating:
            detail += " Multiple keys published - key rotation in place (good practice)."
        if weak:
            detail += " Weak RSA key(s) <1024-bit: " + ", ".join(weak) + "."
        if testing:
            detail += " Testing mode (t=y), not enforced: " + ", ".join(testing) + "."
        if rotation_idle:
            detail += (" Idle key-rotation slot(s) (no live key yet): "
                       + ", ".join(rotation_idle) + ".")
        if revoked:
            detail += " Revoked (empty p=): " + ", ".join(revoked) + "."
        sev = "MEDIUM" if (weak or testing) else ""
        return CheckResult(f"Present ({len(active)})", True, w, w, sev,
                           detail=detail, records=active + rotation_idle + revoked)

    if revoked:
        return CheckResult(
            "Revoked", False, 0, w, "MEDIUM",
            "Only revoked DKIM keys (empty p=) were found: " + ", ".join(revoked) +
            ". Republish a valid key or remove the records if DKIM is unused.",
            records=revoked)

    # Selectors cannot be enumerated via DNS, so absence is NOT proof of no DKIM.
    return CheckResult(
        "Not detected", False, 0, w, "MEDIUM",
        "No DKIM key found for the probed selectors. DKIM selectors cannot be "
        "enumerated from DNS, so this is not conclusive - verify with a known "
        "selector (add it in the scan options) or by inspecting a signed message.")


def check_dmarc(resolver, domain, spf_ok: bool, dkim_ok: bool, spf_permissive=False):
    """Returns (CheckResult, policy, base_label, inherited).

    Implements RFC 7489 discovery: if a subdomain has no _dmarc record, the
    organizational domain's policy is inherited (its 'sp=' if set, else 'p=').
    spf_permissive=True (SPF '+all') means DMARC can be passed by any sender, so an
    otherwise-enforced policy is reported as Ineffective.
    """
    w = WEIGHTS["DMARC"]
    records = [r for r in _txt(resolver, f"_dmarc.{domain}") if "v=DMARC1" in r]

    inherited = False
    source = domain
    if not records and is_subdomain(domain):
        od = org_domain(domain)
        org_records = [r for r in _txt(resolver, f"_dmarc.{od}") if "v=DMARC1" in r]
        if org_records:
            records, inherited, source = org_records, True, od

    if not records:
        return (CheckResult(
            "Missing", False, 0, w, "HIGH",
            "No DMARC record (and no inheritable org-domain policy). DMARC is the "
            "only control that stops spoofing of the visible From: address; without "
            "it, SPF/DKIM cannot protect recipients from forged mail."),
            "-", "Missing", False)

    # Only one DMARC record is valid; multiple makes the policy unusable.
    if len(records) > 1 and not inherited:
        return (CheckResult(
            "Invalid (multiple)", False, 0, w, "HIGH",
            f"{len(records)} DMARC records found; RFC 7489 permits one. Receivers "
            "will ignore the policy.", records=records), "-", "Missing", False)

    rec = records[0]
    p = re.search(r"\bp=([^;\s]+)", rec)
    sp = re.search(r"\bsp=([^;\s]+)", rec)
    pct_m = re.search(r"\bpct=(\d+)", rec)
    pct = int(pct_m.group(1)) if pct_m else 100
    # For an inherited record, the subdomain policy (sp=) applies if present.
    if inherited and sp:
        policy, pol_src = sp.group(1), "sp"
    else:
        policy = p.group(1) if p else "unknown"
        pol_src = "p"

    if policy == "reject":
        score, base = w, "Enforced"
    elif policy == "quarantine":
        score, base = w * 3 // 4, "Enforced"
    else:  # none / unknown
        score, base = w // 4, "Monitor"

    if inherited:
        detail = f"No record at _dmarc.{domain}; inherited from {source} ({pol_src}={policy})."
    else:
        detail = f"Policy {pol_src}={policy}."
        if sp:
            detail += f" Subdomain policy sp={sp.group(1)}."

    # pct= controls how much mail the policy applies to. pct=0 enforces nothing;
    # 0<pct<100 only partially enforces.
    if base == "Enforced" and pct == 0:
        base, score = "Monitor", w // 4
        detail += " pct=0 means the enforcement policy is applied to 0% of mail (no enforcement)."
    elif base == "Enforced" and pct < 100:
        score = score * 3 // 4
        detail += f" pct={pct}: policy applies to only {pct}% of mail."

    if "rua=" not in rec:
        detail += " No aggregate reporting (rua) configured - you have no visibility into abuse."

    # Judge effectiveness against the scanned domain's SPF/DKIM state. (DKIM
    # detection is best-effort, so 'no DKIM' here means 'none detected'.)
    if base == "Enforced":
        if spf_ok and dkim_ok:
            pass  # enforced with both authenticators - the strong case
        elif spf_ok:
            base = "Enf-SPF"
            detail += " Enforcement relies on SPF alignment only (no DKIM detected)."
        elif dkim_ok:
            base = "Enf-DKIM"
            detail += " Enforcement relies on DKIM alignment only (no SPF)."
        else:
            # Enforced, but neither SPF nor DKIM detected. This is NOT a spoofing
            # hole: every unauthenticated message (including forgeries) fails DMARC
            # and is quarantined/rejected. The only downside is that the domain's
            # OWN mail is blocked too - a deliverability problem if it sends mail,
            # and the correct "send no mail" lockdown if it does not.
            base = "Enf-NoAuth"
            detail += (" Enforcement blocks ALL unauthenticated mail, so spoofing is "
                       "stopped; but no SPF/DKIM was detected, so this domain's own "
                       "mail would be blocked too. That is a deliverability issue (not "
                       "a spoofing exposure) if it sends mail, and the correct lockdown "
                       "if it does not. Note: DKIM detection is best-effort.")

    # SPF '+all' passes for ANY server, so a spoofer can align the envelope-from and
    # pass DMARC regardless of policy or DKIM -> enforcement gives no protection.
    if spf_permissive and base in ("Enforced", "Enf-SPF", "Enf-DKIM", "Enf-NoAuth"):
        base, score = "Ineffective", 0
        detail += (" However, SPF uses '+all' (passes for ANY server): an attacker can "
                   "align the envelope-from and still pass DMARC, so enforcement "
                   "provides no spoofing protection.")

    ok = base in ("Enforced", "Enf-SPF", "Enf-DKIM", "Enf-NoAuth")
    if base == "Enf-NoAuth":
        sev = "LOW"          # cautionary (verify intent), not a spoofing failure
    elif ok:
        sev = ""
    elif base == "Monitor":
        sev = "MEDIUM"
    else:
        sev = "HIGH"         # Missing / Invalid / Ineffective
    if base == "Enf-NoAuth":
        label = f"Enforced ({policy}, no SPF/DKIM{', inherited' if inherited else ''})"
    elif base == "Ineffective":
        label = f"Ineffective ({policy}, +all defeats DMARC{', inherited' if inherited else ''})"
    else:
        label = f"{base} ({policy}{', inherited' if inherited else ''})"
    return (CheckResult(label, ok, score, w, sev, detail, records=records),
            policy, base, inherited)


def _mx_records(resolver, domain):
    """Return (records, resolved). resolved=False means the MX lookup itself failed
    (timeout / SERVFAIL / no reachable nameserver), so 'no MX' must NOT be inferred -
    only an authoritative empty/NXDOMAIN answer means the domain truly has no MX."""
    try:
        answers = resolver.resolve(domain, "MX", raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return [], True                      # authoritative: name has no records
    except (dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.exception.DNSException):
        return [], False                     # transient/uncertain - cannot conclude
    return [r.to_text() for r in answers], True  # NoAnswer -> empty but authoritative


def check_mx(resolver, domain) -> CheckResult:
    w = WEIGHTS["MX"]
    records, resolved = _mx_records(resolver, domain)  # e.g. "10 mail.example.com."

    if not resolved:
        # The lookup failed (not an authoritative "no MX"). Don't let a flaky DNS
        # response masquerade as a deliberate no-mail domain - that would wrongly
        # narrow the grade scope and soften the risk.
        return CheckResult(
            "Unknown", False, 0, w, "LOW",
            "MX lookup failed (timeout or temporary DNS error); the mail-receiving "
            "configuration could not be determined. Re-run to confirm.")

    if not records:
        # No MX is not itself a security flaw - it's an availability fact. But an
        # unused/no-mail domain is a prime spoofing target, and the correct fix is
        # usually a null MX + SPF -all + DMARC p=reject (not "add an MX").
        return CheckResult(
            "None", False, 0, w, "LOW",
            "No MX - domain does not receive mail. Not a risk by itself, but unused "
            "domains are prime spoofing targets: declare 'no mail' with an RFC 7505 "
            "null MX plus SPF '-all' and DMARC 'p=reject'.")

    # RFC 7505 null MX: a single record "0 ." explicitly declaring the domain
    # sends/receives no mail. This is a deliberate, secure configuration.
    exchanges = [r.split()[-1].rstrip(".") for r in records if r.split()]
    if len(records) == 1 and exchanges and exchanges[0] in ("", "."):
        return CheckResult(
            "Null MX", True, w, w,
            detail="RFC 7505 null MX (0 .) - domain explicitly accepts no mail. "
                   "Pair with SPF '-all' and DMARC 'p=reject' for anti-spoofing.",
            records=records)

    return CheckResult("YES", True, w, w, detail="\n".join(sorted(records)),
                       records=records)


def _dnssec_authenticated(domain, nameserver) -> bool | None:
    """Ask a validating resolver and check the AD (Authenticated Data) flag - i.e.
    the full signature chain actually validated. None if it can't be determined."""
    ns = nameserver or "1.1.1.1"   # Cloudflare validates; system NS may not
    try:
        q = dns.message.make_query(domain, dns.rdatatype.SOA, want_dnssec=True)
        resp = dns.query.udp(q, ns, timeout=DNS_TIMEOUT)
        if resp.flags & dns.flags.TC:
            resp = dns.query.tcp(q, ns, timeout=DNS_TIMEOUT)
        return bool(resp.flags & dns.flags.AD)
    except Exception:
        return None


def check_dnssec(resolver, domain, nameserver=None) -> CheckResult:
    w = WEIGHTS["DNSSEC"]
    keys = _query(resolver, domain, "DNSKEY")
    ds = _query(resolver, domain, "DS")  # published in the parent zone
    ad = _dnssec_authenticated(domain, nameserver)

    if ad:
        return CheckResult("YES", True, w, w,
                           detail="Validated: a validating resolver set the AD flag, "
                                  "so the full DNSSEC chain of trust verified.",
                           records=ds or keys)
    if keys and ds:
        return CheckResult("YES", True, w, w,
                           detail="Zone signed (DNSKEY) and anchored at the parent "
                                  "(DS present): chain of trust is complete.",
                           records=ds)
    if keys and not ds:
        # Signed but no DS at the registrar = "island of security": validators
        # cannot build a trust chain, so it is not actually protected.
        return CheckResult("Partial", False, w // 2, w, "MEDIUM",
                           "Zone is signed (DNSKEY) but has no DS record at the "
                           "parent. The chain of trust is broken - publish the DS at "
                           "your registrar to complete DNSSEC.", records=keys)
    return CheckResult("NO", False, 0, w, "LOW",
                       "Zone not signed with DNSSEC. DNS answers (incl. MX/MTA-STS) "
                       "can be tampered with; relevant chiefly if you rely on DANE.")


def check_mta_sts(resolver, domain, fetch_policy=True) -> CheckResult:
    w = WEIGHTS["MTA-STS"]
    records = [r for r in _txt(resolver, f"_mta-sts.{domain}") if "v=STSv1" in r]
    if not records:
        return CheckResult(
            "NO", False, 0, w, "MEDIUM",
            "No MTA-STS. Inbound mail can be delivered over unencrypted or "
            "downgraded TLS connections (active attacker can strip STARTTLS).")

    mode = None
    if fetch_policy and requests is not None:
        try:
            resp = requests.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                                timeout=DNS_TIMEOUT)
            if "version: STSv1" not in resp.text.lower().replace(" ", "") \
                    and "version:stsv1" not in resp.text.lower().replace(" ", ""):
                return CheckResult("Broken", False, 0, w, "MEDIUM",
                                   "MTA-STS TXT exists but the policy file at "
                                   "https://mta-sts.{d}/.well-known/mta-sts.txt is "
                                   "missing or invalid, so senders ignore it."
                                   .format(d=domain), records=records)
            m = re.search(r"mode:\s*(\w+)", resp.text, re.IGNORECASE)
            mode = m.group(1).lower() if m else None
        except Exception:
            return CheckResult("YES (unverified)", True, w * 3 // 4, w, "LOW",
                               "MTA-STS TXT present but the policy file could not be "
                               "fetched to confirm enforcement mode.", records=records)

    if mode == "enforce":
        return CheckResult("YES (enforce)", True, w, w,
                           detail="MTA-STS in enforce mode: senders require valid TLS.",
                           records=records)
    if mode in ("testing", "none"):
        return CheckResult(f"YES ({mode})", True, w // 2, w, "LOW",
                           f"MTA-STS policy mode is '{mode}', which only reports and "
                           "does not enforce TLS. Switch to 'mode: enforce' after "
                           "validating.", records=records)
    return CheckResult("YES", True, w, w, detail="MTA-STS TXT present.",
                       records=records)


def check_tls_rpt(resolver, domain) -> CheckResult:
    w = WEIGHTS["TLS-RPT"]
    records = [r for r in _txt(resolver, f"_smtp._tls.{domain}") if "v=TLSRPTv1" in r]
    if not records:
        return CheckResult("NO", False, 0, w, "LOW",
                           "No TLS-RPT. You receive no reports of TLS delivery "
                           "failures, so MTA-STS/DANE problems go unnoticed.")
    return CheckResult("YES", True, w, w, detail="TLS-RPT reporting configured.",
                       records=records)


def check_bimi(resolver, domain) -> CheckResult:
    w = WEIGHTS["BIMI"]
    records = [r for r in _txt(resolver, f"default._bimi.{domain}") if "v=BIMI1" in r]
    if not records:
        return CheckResult("NO", False, 0, w, "LOW",
                           "No BIMI record. Optional brand-logo display; only "
                           "effective once DMARC is at enforcement (quarantine/reject).")
    return CheckResult("YES", True, w, w, detail="BIMI record present.", records=records)


def check_caa(resolver, domain) -> CheckResult:
    w = WEIGHTS["CAA"]
    records = _query(resolver, domain, "CAA")
    if not records:
        return CheckResult("NO", False, 0, w, "LOW",
                           "No CAA records. Any certificate authority may issue "
                           "certificates for this domain (incl. the MTA-STS host), "
                           "widening the mis-issuance attack surface.")
    return CheckResult("YES", True, w, w, detail="\n".join(records), records=records)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def _grade(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 50:
        return "Fair"
    return "Poor"


def _risk(dmarc_status: str, spf_ok: bool, dkim_ok: bool, no_mail: bool = False) -> str:
    # No DMARC enforcement at all -> the From: address is spoofable.
    if dmarc_status == "Missing":
        return "Critical" if (not spf_ok and not dkim_ok) else "High"
    # DMARC present but defeated (e.g. SPF +all lets any sender pass) -> spoofable
    # despite the policy, even for a non-sending domain.
    if dmarc_status == "Ineffective":
        return "High"
    if dmarc_status == "Monitor":
        return "Medium"
    # From here DMARC is enforced (Enforced / Enf-SPF / Enf-DKIM / Enf-NoAuth).
    # A non-sending domain with any enforcement is locked down: spoofing is blocked
    # and the single-authenticator / no-auth deliverability concerns don't apply.
    if no_mail:
        return "Low"
    # Enforced but no SPF/DKIM, or relying on a single authenticator: spoofing is
    # blocked, but the domain's own mail is fragile -> deliverability risk.
    if dmarc_status in ("Enf-NoAuth", "Enf-SPF", "Enf-DKIM"):
        return "Medium"
    return "Low"  # Enforced with SPF & DKIM


_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _rec(control, severity, action, record=""):
    return {"control": control, "severity": severity, "action": action, "record": record}


def _recommendations(domain, checks, dmarc_base, dmarc_inherited) -> list[dict]:
    """Context-aware, provider-agnostic, phased remediation guidance.

    Only emits a recommendation for controls that are actually missing or weak,
    and never assumes a specific mail/CA provider (placeholders use <...>).
    """
    recs = []
    spf = checks["SPF"]; dkim = checks["DKIM"]; dmarc = checks["DMARC"]
    mx = checks["MX"]; mta = checks["MTA-STS"]; tls = checks["TLS-RPT"]
    dnssec = checks["DNSSEC"]; caa = checks["CAA"]; bimi = checks["BIMI"]
    no_mail = (mx.status in ("None", "Null MX"))

    # ---- SPF ----
    if spf.status == "Missing":
        if no_mail:
            recs.append(_rec("SPF", "HIGH",
                "This domain does not receive mail. Lock it for sending too so it "
                "cannot be spoofed.", f"TXT  {domain}  →  v=spf1 -all"))
        else:
            recs.append(_rec("SPF", "HIGH",
                "Publish an SPF record listing every server/service that sends mail "
                "for the domain. Start with ~all during rollout, then tighten to -all.",
                f"TXT  {domain}  →  v=spf1 include:<your-mail-provider> -all"))
    elif spf.status.startswith("Dangerous"):
        recs.append(_rec("SPF", "HIGH",
            "Replace '+all' immediately - it lets anyone send as your domain.",
            f"TXT  {domain}  →  v=spf1 include:<senders> -all"))
    elif spf.status.startswith(("Weak", "Invalid")):
        recs.append(_rec("SPF", "MEDIUM",
            "Fix the SPF policy: use a single record ending in '-all' (or '~all' "
            "while validating). Multiple records or a missing/neutral 'all' break SPF."))
    elif spf.status.startswith("Soft"):
        recs.append(_rec("SPF", "LOW",
            "Tighten SPF from '~all' to '-all' once you've confirmed all legitimate "
            "senders are listed."))
    if "PERMERROR" in (spf.status or "") or "PERMERROR" in (spf.detail or ""):
        recs.append(_rec("SPF", "HIGH",
            "Resolve the SPF PERMERROR: reduce DNS lookups below the RFC 7208 limit of "
            "10 (flatten or remove unused includes), and ensure every include/redirect "
            "target actually publishes an SPF record. Until fixed, SPF is ignored."))

    # ---- DKIM ----
    if dkim.status == "Not detected" and not no_mail:
        recs.append(_rec("DKIM", "MEDIUM",
            "Enable DKIM signing at your mail provider and publish the public key for "
            "its selector. (Selectors can't be discovered via DNS - confirm manually.)",
            "TXT  <selector>._domainkey." + domain + "  →  v=DKIM1; k=rsa; p=<public-key>"))
    elif dkim.status == "Revoked":
        recs.append(_rec("DKIM", "MEDIUM",
            "Republish a valid DKIM key, or remove the revoked (empty p=) records if "
            "DKIM is no longer used."))
    elif dkim.status.startswith("Present"):
        if "Weak RSA" in (dkim.detail or ""):
            recs.append(_rec("DKIM", "MEDIUM",
                "Rotate the DKIM key to at least 2048-bit RSA; keys under 1024-bit are "
                "considered breakable."))
        if "Testing mode" in (dkim.detail or ""):
            recs.append(_rec("DKIM", "LOW",
                "Remove the DKIM testing flag (t=y) once validated so receivers enforce "
                "the signature."))

    # ---- DMARC ----
    if dmarc_base == "Missing":
        recs.append(_rec("DMARC", "HIGH",
            "Publish DMARC. Begin at p=none with aggregate reporting to observe "
            "sources, then ramp p=quarantine → p=reject as you confirm legitimate mail.",
            f"TXT  _dmarc.{domain}  →  v=DMARC1; p=none; rua=mailto:dmarc@{domain}"))
    elif dmarc.status.startswith("Invalid"):
        recs.append(_rec("DMARC", "HIGH",
            "Keep exactly one DMARC record; remove the duplicates so receivers honor "
            "the policy."))
    elif dmarc_base == "Ineffective":
        recs.append(_rec("DMARC", "HIGH",
            "DMARC is enforced but SPF '+all' lets any server pass SPF and DMARC "
            "alignment, so spoofing is NOT blocked. Replace '+all' with '-all' (or "
            "'~all' during rollout) so DMARC can actually protect the domain."))
    elif dmarc_base == "Enf-NoAuth":
        if no_mail:
            recs.append(_rec("DMARC", "INFO",
                "DMARC blocks all unauthenticated mail and this domain is not set up to "
                "send - a correct anti-spoofing lockdown. No action needed unless it "
                "should send mail (then add SPF + DKIM before relying on delivery)."))
        else:
            recs.append(_rec("DMARC", "MEDIUM",
                "DMARC enforcement already blocks spoofing, but no SPF/DKIM was detected "
                "- if this domain sends mail it will be blocked too. Configure SPF and "
                "DKIM so legitimate mail passes (this is a deliverability fix, not a "
                "spoofing one). DKIM detection is best-effort; verify with a known selector."))
    elif dmarc_base == "Monitor":
        recs.append(_rec("DMARC", "MEDIUM",
            "DMARC is monitor-only (p=none) and does NOT stop spoofing. After reviewing "
            "rua reports, advance to p=quarantine, then p=reject.",
            f"TXT  _dmarc.{domain}  →  v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"))
    elif dmarc_base in ("Enf-SPF", "Enf-DKIM"):
        recs.append(_rec("DMARC", "LOW",
            "Enforcement relies on a single authenticator. Configure BOTH SPF and DKIM "
            "so mail still passes if one fails (e.g. forwarded mail breaks SPF)."))
    if "pct=" in (dmarc.detail or "") and dmarc_base != "Missing":
        recs.append(_rec("DMARC", "MEDIUM",
            "Set pct=100 (or remove the pct tag) so the policy applies to all mail; "
            "a partial pct leaves a spoofing gap."))
    if dmarc_base not in ("Missing",) and "No aggregate reporting" in (dmarc.detail or ""):
        recs.append(_rec("DMARC", "LOW",
            "Add an rua= address to receive aggregate reports and keep visibility into "
            "who is sending as your domain.",
            f"…; rua=mailto:dmarc@{domain}"))
    if dmarc_inherited:
        recs.append(_rec("DMARC", "INFO",
            "This subdomain has no DMARC record of its own and inherits the "
            "organizational-domain policy. Confirm that is intended; publish a "
            "specific record if it needs different handling."))

    # ---- Transport / hardening ----
    if no_mail and mx.status == "None":
        recs.append(_rec("MX", "LOW",
            "If the domain should never send or receive mail, declare it explicitly "
            "with a null MX (alongside SPF -all and DMARC p=reject).",
            f"MX  {domain}  →  0 ."))
    if mta.status == "NO" and not no_mail:
        recs.append(_rec("MTA-STS", "MEDIUM",
            "Publish an MTA-STS policy in enforce mode to require TLS for inbound mail "
            "and resist STARTTLS-stripping downgrades.",
            f"TXT  _mta-sts.{domain}  →  v=STSv1; id=<timestamp>   (+ policy file at "
            f"https://mta-sts.{domain}/.well-known/mta-sts.txt, mode: enforce)"))
    elif mta.status.startswith(("YES (testing", "YES (none", "Broken")):
        recs.append(_rec("MTA-STS", "LOW",
            "Move the MTA-STS policy to 'mode: enforce' (or fix the broken policy file) "
            "so TLS is actually required, not just reported."))
    if tls.status == "NO" and not no_mail:
        recs.append(_rec("TLS-RPT", "LOW",
            "Publish a TLS-RPT record to receive daily reports of TLS delivery "
            "failures (useful for spotting MTA-STS/DANE issues).",
            f"TXT  _smtp._tls.{domain}  →  v=TLSRPTv1; rua=mailto:tlsrpt@{domain}"))
    if dnssec.status == "Partial":
        recs.append(_rec("DNSSEC", "MEDIUM",
            "Publish the DS record at your registrar to complete the DNSSEC chain of "
            "trust; the zone is signed but not anchored."))
    elif dnssec.status == "NO":
        recs.append(_rec("DNSSEC", "LOW",
            "Consider enabling DNSSEC (sign the zone and publish a DS at the registrar) "
            "to protect MX/MTA-STS lookups from tampering."))
    if caa.status == "NO":
        recs.append(_rec("CAA", "LOW",
            "Publish CAA records to restrict which CAs may issue certificates for the "
            "domain and its mail/MTA-STS hostnames.",
            f'CAA  {domain}  →  0 issue "<your-ca>"'))
    if bimi.status == "NO" and dmarc_base in ("Enforced",):
        recs.append(_rec("BIMI", "INFO",
            "DMARC is enforced - you may optionally add BIMI (with a VMC) to display "
            "your brand logo in supporting mail clients."))

    recs.sort(key=lambda r: _SEV_ORDER.get(r["severity"], 9))
    return recs


def scan_domain(domain: str, selectors=None, nameserver=None,
                fetch_mta_policy=True, probe_transport=False) -> DomainResult:
    """Run all checks for a single domain and compute score/grade/risk.

    probe_transport=True additionally connects to MX hosts (port 25) to test
    STARTTLS/cert/DANE - advisory only, not folded into the score."""
    domain = domain.strip().lower()
    selectors = selectors or DEFAULT_DKIM_SELECTORS

    if not is_valid_domain(domain):
        return DomainResult(domain=domain, valid=False,
                            error="Invalid domain format")

    started = datetime.now()
    resolver = _make_resolver(nameserver)
    result = DomainResult(domain=domain)

    spf = check_spf(resolver, domain)
    dkim = check_dkim(resolver, domain, selectors)
    dmarc, policy, dmarc_base, dmarc_inherited = check_dmarc(
        resolver, domain, spf.ok, dkim.ok, spf.status.startswith("Dangerous"))
    mx = check_mx(resolver, domain)
    mta = check_mta_sts(resolver, domain, fetch_mta_policy)
    tls = check_tls_rpt(resolver, domain)
    bimi = check_bimi(resolver, domain)
    dnssec = check_dnssec(resolver, domain, nameserver)
    caa = check_caa(resolver, domain)

    result.checks = {
        "SPF": spf, "DKIM": dkim, "DMARC": dmarc, "MX": mx,
        "MTA-STS": mta, "TLS-RPT": tls, "BIMI": bimi,
        "DNSSEC": dnssec, "CAA": caa,
    }
    result.dkim_count = len(dkim.records)
    result.dmarc_policy = policy
    result.dmarc_base = dmarc_base
    result.dmarc_inherited = dmarc_inherited
    # Scope the grade to the controls that actually apply. A domain that neither
    # sends nor receives mail (no MX / null MX) is spoof-proof with just SPF + DMARC;
    # DKIM/MX/MTA-STS/TLS-RPT/BIMI are mail-flow features that don't apply, so they
    # are excluded from its grade (still surfaced as advice). This stops a correct
    # no-mail lockdown (e.g. DMARC p=reject) being mislabelled "Poor".
    no_mail = mx.status in ("None", "Null MX")
    if no_mail:
        applicable = ("SPF", "DMARC")
        earned = sum(result.checks[k].score for k in applicable)
        maxv = sum(WEIGHTS[k] for k in applicable)
        result.score = round(earned * 100 / maxv) if maxv else 0
    else:
        result.score = sum(c.score for c in result.checks.values()) * 100 // MAX_SCORE
    result.grade = _grade(result.score)
    result.risk = _risk(dmarc_base, spf.ok, dkim.ok, no_mail)
    result.recommendations = _recommendations(domain, result.checks,
                                              dmarc_base, dmarc_inherited)

    if probe_transport and mx.status in ("YES", "Null MX") and mx.records:
        try:
            import transport
            result.transport = transport.check_transport(resolver, mx.records)
            _transport_recs(result)
        except Exception as e:
            result.transport = {"checked": False, "error": str(e)}

    result.elapsed = round((datetime.now() - started).total_seconds(), 2)
    return result


def _transport_recs(result: DomainResult):
    """Append advisory recommendations from the optional transport probe."""
    t = result.transport
    if not t.get("checked") or not t.get("hosts"):
        return
    if not t.get("starttls_all"):
        result.recommendations.append(_rec("Transport", "MEDIUM",
            "One or more MX hosts did not offer STARTTLS; inbound mail to them can be "
            "sent in cleartext. Enable STARTTLS on every MX."))
    if t.get("cert_expired"):
        result.recommendations.append(_rec("Transport", "HIGH",
            "An MX TLS certificate is expired - senders enforcing TLS will fail to "
            "deliver. Renew the certificate."))
    result.recommendations.sort(key=lambda r: _SEV_ORDER.get(r["severity"], 9))


def scan_domains(domains, selectors=None, nameserver=None, fetch_mta_policy=True,
                 probe_transport=False, max_workers=8,
                 on_result: Callable[[DomainResult], None] = None):
    """Scan many domains concurrently. Calls on_result(result) as each finishes.

    Returns the full list of DomainResult in completion order.
    """
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(scan_domain, d, selectors, nameserver,
                               fetch_mta_policy, probe_transport)
                   for d in domains]
        for fut in futures:
            res = fut.result()
            results.append(res)
            if on_result:
                on_result(res)
    return results


def parse_domain_input(text: str) -> list[str]:
    """Accept domains separated by commas, whitespace or newlines; drop a 'domain'
    header. (Domain names contain no spaces, so splitting on whitespace is safe.)"""
    raw = re.split(r"[\s,]+", text or "")
    out = []
    for token in raw:
        d = token.strip()
        if not d or d.lower() == "domain":
            continue
        out.append(d)
    # de-dupe, preserve order
    seen, uniq = set(), []
    for d in out:
        if d.lower() not in seen:
            seen.add(d.lower())
            uniq.append(d)
    return uniq
