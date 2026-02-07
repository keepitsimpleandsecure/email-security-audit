# Email Security Audit

A script to perform a comprehensive audit on your email security, including SPF, DKIM, DMARC, MX records, DNSSEC, and more.  
It produces **per-domain reports**, a **summary table**, and a **full consolidated report** with risk overview.

---

## 📌 Overview

This tool checks the security posture of one or many email domains and generates:

- **One detailed TXT report per domain**
- **One summary table** aggregating all results
- **One full report** with:
  - Executive summary
  - Risk overview (Low / Medium / High / Critical)
  - The summary table
  - All per-domain reports appended

You can run it on a single domain or feed it a CSV containing multiple domains.

---

## 🚀 Features

- SPF validation with **quality assessment**:
  - `OK (-all)`, `Soft (~all)`, `Weak/unsafe`, `Missing`, etc.
- DKIM lookup (multiple well-known selectors)
- DMARC policy extraction and **effectiveness analysis**:
  - Distinguishes `Enforced`, `Enf-SPF`, `Enf-DKIM`, `Monitor`, `Ineffective`, `Missing`
- MX records validation
- DNSSEC presence / validation check
- MTA-STS policy check
- TLS-RPT check
- BIMI check
- CAA check
- Weighted scoring system (0–100) with **grade**:
  - Excellent / Good / Fair / Poor
- Global risk classification per domain:
  - Low / Medium / High / Critical

---

## 🖥️ Modes of Execution

### Single Domain Mode

```bash
./email_security_checker.sh -d example.com
./email_security_checker.sh --domain example.com
./email_security_checker.sh -domain example.com
```

### CSV Multi-Domain Mode

```bash
./email_security_checker.sh -c domains.csv
./email_security_checker.sh --csv domains.csv
./email_security_checker.sh -csv domains.csv
```

CSV examples:

```
domain1.com,domain2.com,domain3.com
```

or:

```
domain
domain1.com
domain2.com
domain3.com
```

### Help

```bash
./email_security_checker.sh -h
```

---

## 📄 Output Structure

The script creates a timestamped directory:

```
email_reports_<timestamp>/
```

Containing:

### Per-domain TXT reports

```
email_security_report_<domain>_<timestamp>.txt
```

Includes:
- All checks (SPF, DKIM, DMARC, MX, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA)
- Warnings / notes  
- “Recommended DNS Fixes”  
- A summary block:

```
=== Summary (table view) ===
SPF   : OK (-all)
DKIM  : Present (3)
DMARC : Enforced (reject)
Score : 75% (Good)
Risk  : Low
```

### Summary Table

```
email_security_summary.txt
```

### Full Consolidated Report

```
email_security_full_report.txt
```

Contains:
- Executive summary
- Risk overview
- Summary table
- All per-domain reports appended

---

## 📊 Summary Table Columns

- **Domain** – checked FQDN  
- **SPF** – quality (OK, Soft, Missing…)  
- **DKIM(sel)** – DKIM status and selector count  
- **DMARC(pol)** – DMARC mode + policy  
- **MX** – YES/NO  
- **MTA-STS** – YES/NO  
- **TLS-RPT** – YES/NO  
- **BIMI** – YES/NO  
- **DNSSEC** – YES/NO  
- **CAA** – YES/NO  
- **Score** – 0–100  
- **Grade** – Excellent / Good / Fair / Poor  

Example:

```
example.com | OK (-all) | Present (3) | Enforced (reject) | YES | NO | NO | NO | NO | NO | 75 | Good
```

---

## 📦 Installation

### Dependencies

- dig  
- curl  
- openssl  

### Debian/Ubuntu

```bash
sudo apt update
sudo apt install dnsutils curl openssl
```

### RHEL/CentOS

```bash
sudo yum install bind-utils curl openssl
```

---

## ▶️ Usage

Make executable:

```bash
chmod +x email_security_checker.sh
```

Run:

```bash
./email_security_checker.sh -d example.com
```

Or:

```bash
./email_security_checker.sh -c domains.csv
```

---

## 📝 License

MIT License.
