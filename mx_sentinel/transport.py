"""
Transport-security probing for mail servers: STARTTLS support, certificate
validity/expiry, and DANE (TLSA) presence.

This is an ACTIVE check (it connects to MX hosts on port 25), kept separate from
the passive DNS audit and OFF by default - many networks block outbound port 25.
Results are advisory and are not folded into the 0-100 score.
"""

from __future__ import annotations

import smtplib
import socket
import ssl
from datetime import datetime, timezone

import dns.resolver
import dns.exception

try:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID
except ImportError:  # cryptography optional; cert parsing degrades gracefully
    x509 = None

SMTP_TIMEOUT = 8.0


def lookup_tlsa(resolver, host: str, port: int = 25) -> list[str]:
    """DANE TLSA records for a mail host, e.g. _25._tcp.mx.example.com."""
    name = f"_{port}._tcp.{host.rstrip('.')}"
    try:
        ans = resolver.resolve(name, "TLSA", raise_on_no_answer=False)
        return [r.to_text() for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException):
        return []


def _parse_cert(der: bytes, host: str) -> dict:
    info = {"subject": None, "issuer": None, "not_after": None,
            "days_left": None, "expired": None, "host_match": None}
    if x509 is None or not der:
        return info
    try:
        cert = x509.load_der_x509_certificate(der)
        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"] = cert.issuer.rfc4514_string()
        try:
            not_after = cert.not_valid_after_utc
        except AttributeError:  # cryptography < 42
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        info["not_after"] = not_after.isoformat()
        info["days_left"] = (not_after - datetime.now(timezone.utc)).days
        info["expired"] = info["days_left"] < 0
        # Hostname match against SAN dNSNames (incl. simple wildcard).
        names = []
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            names = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            names = [cn[0].value] if cn else []
        info["host_match"] = _host_matches(host.rstrip("."), names)
    except Exception as e:
        info["subject"] = f"(parse error: {e})"
    return info


def _host_matches(host: str, names: list[str]) -> bool:
    host = host.lower()
    for n in names:
        n = n.lower()
        if n == host:
            return True
        if n.startswith("*.") and host.split(".", 1)[-1] == n[2:]:
            return True
    return False


def probe_mx(host: str, timeout: float = SMTP_TIMEOUT) -> dict:
    """Connect to an MX host, negotiate STARTTLS, and inspect its certificate."""
    res = {"host": host, "starttls": False, "tls_version": None,
           "cert": {}, "error": None}
    host = host.rstrip(".")
    try:
        server = smtplib.SMTP(timeout=timeout)
        server.connect(host, 25)
        server.ehlo_or_helo_if_needed()
        if not server.has_extn("starttls"):
            res["error"] = "STARTTLS not offered"
            server.quit()
            return res
        ctx = ssl.create_default_context()
        ctx.check_hostname = False        # inspect even invalid certs
        ctx.verify_mode = ssl.CERT_NONE
        server.starttls(context=ctx)
        res["starttls"] = True
        sock = server.sock
        res["tls_version"] = sock.version()
        res["cert"] = _parse_cert(sock.getpeercert(binary_form=True), host)
        try:
            server.quit()
        except Exception:
            pass
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError,
            smtplib.SMTPException) as e:
        res["error"] = f"{type(e).__name__}: {e}"
    return res


def check_transport(resolver, mx_records: list[str], max_hosts: int = 3,
                     timeout: float = SMTP_TIMEOUT) -> dict:
    """Probe up to max_hosts MX servers for STARTTLS/cert/DANE.

    mx_records are dnspython MX strings like '10 mail.example.com.'.
    Returns a summary dict suitable for the report (not scored).
    """
    hosts = []
    for rec in mx_records:
        parts = rec.split()
        host = parts[-1].rstrip(".") if parts else ""
        if host and host != "." and host not in hosts:
            hosts.append(host)
    hosts = hosts[:max_hosts]

    results = []
    for h in hosts:
        probe = probe_mx(h, timeout)
        probe["tlsa"] = lookup_tlsa(resolver, h)
        results.append(probe)

    any_tls = any(p["starttls"] for p in results)
    all_tls = bool(results) and all(p["starttls"] for p in results)
    any_dane = any(p["tlsa"] for p in results)
    expired = any(p["cert"].get("expired") for p in results if p.get("cert"))
    return {
        "checked": True,
        "hosts": results,
        "starttls_all": all_tls,
        "starttls_any": any_tls,
        "dane": any_dane,
        "cert_expired": expired,
    }
