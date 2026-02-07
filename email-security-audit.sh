#!/bin/bash

# Email Security Audit - CLI + Per-domain reports + Summary & Full report
#
# Modes:
#   - Single domain:  -d example.com   or  --domain example.com  or  -domain example.com
#   - CSV domains:    -c domains.csv   or  --csv domains.csv     or  -csv domains.csv
#   - Help:           -h or --help
#
# Generates (per run):
#   - One TXT report per domain:
#       email_reports_<timestamp>/email_security_report_<domain>_<timestamp>.txt
#   - One summary TXT with an ASCII table:
#       email_reports_<timestamp>/email_security_summary.txt
#   - One consolidated full report (executive summary + risk overview + table + all domain reports):
#       email_reports_<timestamp>/email_security_full_report.txt
#
# Summary table columns:
#   Domain      : FQDN of the checked domain
#   SPF         : SPF quality (e.g. "OK (-all)", "Soft (~all)", "Weak/unsafe", "Missing")
#   DKIM(sel)   : DKIM status + selector count (e.g. "Present (3)", "Missing (0)")
#   DMARC(pol)  : DMARC mode + policy (e.g. "Enforced (reject)", "Enf-SPF (reject)",
#                 "Monitor (none)", "Ineffective (reject)", "Missing (-)")
#   MX          : MX records present (YES/NO)
#   MTA-STS     : MTA-STS TXT/policy presence (YES/NO)
#   TLS-RPT     : SMTP TLS reporting record presence (YES/NO)
#   BIMI        : BIMI record presence (YES/NO)
#   DNSSEC      : DNSSEC validated (YES/NO)
#   CAA         : CAA records present (YES/NO)
#   Score       : Weighted security score (0–100)
#   Grade       : Qualitative grade (Excellent / Good / Fair / Poor)


# Text Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Initialize variables
domain=""
csv_file=""
report_file=""
start_time=0
current_score=0
max_score=0
REPORT_DIR=""
SUMMARY_FILE=""
FULL_REPORT_FILE=""

# Per-check status variables (for the summary table)
spf_status=""
dkim_status=""
dmarc_status=""
mx_status=""
mta_sts_status=""
tls_rpt_status=""
bimi_status=""
dnssec_status=""
caa_status=""

# Extra details for summary
dkim_count=0        # number of DKIM selectors found
dmarc_policy="-"    # DMARC policy (reject/quarantine/none/unknown)

# Global aggregates for full report
declare -a REPORT_FILES=()
declare -a REPORT_DOMAINS=()

total_domains=0

count_dmarc_enforced=0
count_dmarc_monitor=0
count_dmarc_missing=0
count_dmarc_ineffective=0

count_spf_missing=0
count_dkim_missing=0

count_risk_low=0
count_risk_medium=0
count_risk_high=0
count_risk_critical=0

risk_low_list=""
risk_medium_list=""
risk_high_list=""
risk_critical_list=""

risk_level="Unknown"

# Weighted Scoring
declare -A weights=(
    [SPF]=20
    [DKIM]=20
    [DMARC]=20
    [MX]=15
    [DNSSEC]=10
    [MTA-STS]=5
    [TLS-RPT]=3
    [BIMI]=2
    [CAA]=5
)

# Enhanced DKIM Selectors (Google + Enterprise)
DKIM_SELECTORS=(
    "google" "20220809" "20210223" "20161025" "krs"
    "mx" "s1" "s2" "selector1" "selector2" "dkim"
    "domainkey" "signer" "em" "default" "key1"
    "key2" "phishprotection" "mandrill" "everlytickey1"
)



# ---------------- HELP & ARGS ---------------- #

function show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Email Security Checker

Modes:
  -d, --domain, -domain <name>   Check a single domain (e.g., example.com)
  -c, --csv, -csv <file>         Check multiple domains from a CSV file
  -h, --help                     Show this help message

CSV details:
  * CSV can use:
        domain
        example.com
        google.com

    or a single line:
        domain1.com,domain2.com,domain3.com

Outputs (per run):
  * Folder:
        email_reports_<timestamp>/
  * Per-domain TXT report:
        email_security_report_<domain>_<timestamp>.txt
  * Summary table (ASCII):
        email_security_summary.txt

Summary columns:
  Domain, SPF, DKIM(sel), DMARC(pol), MX, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, Score, Grade

Examples:
  Single domain:
    $0 -d example.com

  Multiple domains from CSV:
    $0 -c domains.csv

EOF
}

# Simple manual argument parsing (supports multi-char flags)
function parse_args() {
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain|-domain)
                domain="$2"
                shift 2
                ;;
            -c|--csv|-csv)
                csv_file="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done

    # Validate combination
    if [ -n "$domain" ] && [ -n "$csv_file" ]; then
        echo -e "${RED}You cannot use both --domain and --csv in the same run.${NC}"
        exit 1
    fi

    if [ -z "$domain" ] && [ -z "$csv_file" ]; then
        echo -e "${RED}You must specify either --domain or --csv.${NC}"
        show_help
        exit 1
    fi
}

# ---------------- CORE FUNCTIONS ---------------- #

# Dependency Check
function check_deps() {
    local missing=()
    local install_cmd="sudo apt update && sudo apt install -y dnsutils curl openssl"

    for cmd in dig curl openssl; do
        if ! command -v $cmd &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Missing dependencies: ${missing[*]}${NC}"
        echo -e "${CYAN}On Kali/Linux, run: ${NC}$install_cmd"
        exit 1
    fi
}

# Report Handling
function init_report() {
    domain="$1"
    report_file="${REPORT_DIR}/email_security_report_${domain}_$(date +"%Y%m%d_%H%M%S").txt"
    > "$report_file"
    write_report "=== Email Security Report for ${domain} ==="
    write_report "Generated on: $(date)"
    write_report "=========================================="
}

function write_report() {
    echo -e "$1" | tee -a "$report_file"
}

# Summary table init
function init_summary_file() {
    SUMMARY_FILE="${REPORT_DIR}/email_security_summary.txt"
    {
        echo "Email Security Summary - $(date)"
        echo
        printf "%-30s | %-18s | %-18s | %-24s | %-5s | %-7s | %-7s | %-5s | %-7s | %-5s | %-6s | %-10s\n" \
            "Domain" "SPF" "DKIM(sel)" "DMARC(pol)" "MX" "MTA-STS" "TLS-RPT" "BIMI" "DNSSEC" "CAA" "Score" "Grade"
        printf "%-30s-+-%-18s-+-%-18s-+-%-24s-+-%-5s-+-%-7s-+-%-7s-+-%-5s-+-%-7s-+-%-5s-+-%-6s-+-%-10s\n" \
            "------------------------------" "------------------" "------------------" "------------------------" \
            "-----" "-------" "-------" "-----" "-------" "-----" "------" "----------"
    } > "$SUMMARY_FILE"
}


# Domain Validation (no exit, just return 1 if invalid)
function validate_domain() {
    if [[ $1 =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$ ]]; then
        return 0
    else
        echo -e "${RED}Invalid domain format: '$1'. Use example.com${NC}" >&2
        return 1
    fi
}

# Reset per-domain state (score + statuses + timer + details)
function reset_state() {
    current_score=0
    start_time=$(date +%s)

    # High-level status labels for the summary table
    spf_status="Missing"        # will become: OK (-all), Soft (~all), Weak/unsafe, Missing
    dkim_status="Missing"       # Present / Missing
    dmarc_status="Missing"      # Missing / Monitor / Enforced / Ineffective / Enf-SPF / Enf-DKIM

    mx_status="NO"
    mta_sts_status="NO"
    tls_rpt_status="NO"
    bimi_status="NO"
    dnssec_status="NO"
    caa_status="NO"

    dkim_count=0
    dmarc_policy="-"            # reject / quarantine / none / unknown / -
    risk_level="Unknown"
}


# --- Core Checks --- #

function check_spf() {
    write_report "\n=== SPF Check ==="
    local record
    record=$(dig +short txt "$domain" | grep "v=spf1")
    local weight=${weights[SPF]}

    if [ -z "$record" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🔴 HIGH\nImpact: Email spoofing possible"
        echo -e "${RED}❌ SPF Missing${NC}"
        spf_status="Missing"
        return
    fi

    # Base: SPF exists
    write_report "Status: ✅ Found\nRecord: $record"
    echo -e "${GREEN}✅ SPF Found${NC}"

    # Evaluate quality based on ending mechanism
    # Strong: -all (hard fail)
    # Soft:   ~all
    # Weak:   ?all, +all, or no 'all' at all
    local spf_score=0
    if [[ $record =~ "-all" ]]; then
        spf_status="OK (-all)"
        spf_score=$weight
    elif [[ $record =~ "~all" ]]; then
        spf_status="Soft (~all)"
        spf_score=$((weight * 3 / 4))     # e.g. 15 if weight=20
    elif [[ $record =~ "[?+]all" ]] || [[ ! $record =~ "all" ]]; then
        spf_status="Weak/unsafe"
        spf_score=$((weight / 4))         # e.g. 5 if weight=20
        write_report "Warning: SPF ends with weak or missing 'all' qualifier"
        echo -e "${YELLOW}⚠️ SPF weak or missing 'all' qualifier${NC}"
    else
        spf_status="Present (custom)"
        spf_score=$((weight / 2))
    fi

    ((current_score += spf_score))

    # SPF redirect validation (unchanged)
    if [[ $record =~ redirect=([^ ]+) ]]; then
        local redirect_domain=${BASH_REMATCH[1]}
        local redirect_spf
        redirect_spf=$(dig +short txt "$redirect_domain" | grep "v=spf1")
        [ -z "$redirect_spf" ] && {
            write_report "Warning: Broken SPF redirect to $redirect_domain"
            echo -e "${YELLOW}⚠️ Broken SPF redirect${NC}"
        }
    fi
}

function check_dkim() {
    write_report "\n=== DKIM Check ==="
    local found=0
    local weight=${weights[DKIM]}

    for sel in "${DKIM_SELECTORS[@]}"; do
        local record
        record=$(dig +short txt "${sel}._domainkey.$domain" | grep "v=DKIM1")
        if [ -n "$record" ]; then
            ((found++))
            write_report "Selector Found: $sel"
            echo -e "${GREEN}✅ DKIM (selector: $sel)${NC}"
        fi
    done

    dkim_count=$found

    if ((found > 0)); then
        dkim_status="Present"
        ((current_score += weight))
        write_report "Status: ✅ Found ($found selectors)"
    else
        dkim_status="Missing"
        write_report "Status: ❌ Missing\nSeverity: 🔴 HIGH\nImpact: Email tampering possible"
        echo -e "${RED}❌ DKIM Missing${NC}"
    fi
}

function check_dmarc() {
    write_report "\n=== DMARC Check ==="
    local record
    record=$(dig +short txt "_dmarc.$domain" | grep "v=DMARC1")
    local weight=${weights[DMARC]}

    if [ -z "$record" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🔴 HIGH\nImpact: No fraud protection"
        echo -e "${RED}❌ DMARC Missing${NC}"
        dmarc_status="Missing"
        dmarc_policy="-"
        return
    fi

    write_report "Status: ✅ Found\nRecord: $record"
    echo -e "${GREEN}✅ DMARC Found${NC}"

    # Extract policy
    dmarc_policy="unknown"
    if [[ $record =~ p=([^;[:space:]]+) ]]; then
        dmarc_policy="${BASH_REMATCH[1]}"
    fi
    write_report "DMARC Policy: $dmarc_policy"

    # Base score depending on policy
    local base_score=0
    case "$dmarc_policy" in
        reject)
            base_score=$weight
            dmarc_status="Enforced"
            ;;
        quarantine)
            base_score=$((weight * 3 / 4))
            dmarc_status="Enforced"
            ;;
        none)
            base_score=$((weight / 4))  # monitoring only
            dmarc_status="Monitor"
            ;;
        *)
            base_score=$((weight / 4))
            dmarc_status="Monitor"
            write_report "Warning: Unusual DMARC policy value: $dmarc_policy"
            ;;
    esac

    # --- judge effectiveness based on SPF/DKIM state ---
    # have_spf = 1 if SPF is not 'Missing'
    local have_spf=1
    [[ "$spf_status" == "Missing" ]] && have_spf=0

    # have_dkim = 1 if DKIM is not 'Missing'
    local have_dkim=1
    [[ "$dkim_status" == "Missing" ]] && have_dkim=0

    if [[ "$dmarc_status" == "Enforced" ]]; then
        if (( have_spf == 0 && have_dkim == 0 )); then
            dmarc_status="Ineffective"
            base_score=0
            write_report "Warning: DMARC enforcement policy set, but neither SPF nor DKIM are configured – DMARC cannot effectively protect mail."
            echo -e "${YELLOW}⚠️ DMARC ineffective: no SPF or DKIM${NC}"
        elif (( have_spf == 1 && have_dkim == 0 )); then
            dmarc_status="Enf-SPF"
            write_report "Note: DMARC enforcement relies only on SPF (no DKIM)."
        elif (( have_spf == 0 && have_dkim == 1 )); then
            dmarc_status="Enf-DKIM"
            write_report "Note: DMARC enforcement relies only on DKIM (no SPF)."
        else
            # both present: keep 'Enforced'
            :
        fi
    fi

    ((current_score += base_score))

    # Additional soft checks
    [[ $record =~ rua=mailto: ]] || {
        write_report "Warning: No DMARC aggregate reporting URI (rua)"
        echo -e "${YELLOW}⚠️ No DMARC reports configured${NC}"
    }
}

function check_mx() {
    write_report "\n=== MX Records Check ==="
    local records
    records=$(dig +short mx "$domain" | sort -n)
    local weight=${weights[MX]}

    if [ -z "$records" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🔴 HIGH\nImpact: No email reception"
        echo -e "${RED}❌ MX Missing${NC}"
        mx_status="NO"
    else
        ((current_score += weight))
        write_report "Status: ✅ Found\nRecords:\n$records"
        echo -e "${GREEN}✅ MX Found${NC}"
        mx_status="YES"

        while read -r line; do
            local host
            host=$(awk '{print $NF}' <<< "$line" | tr -d '"')

            # Skip A check for IPv6 MX
            if [[ $host =~ : ]]; then
                write_report "IPv6 MX: $host - A check skipped"
                echo -e "${CYAN}ℹ️ IPv6 MX: $host${NC}"
                continue
            fi

            local ips
            ips=$(dig +short a "$host")
            [ -z "$ips" ] && {
                write_report "Warning: MX $host has no A record"
                echo -e "${YELLOW}⚠️ No A for $host${NC}"
            }
        done <<< "$records"
    fi
}

function check_dnssec() {
    write_report "\n=== DNSSEC Check ==="
    local rrsig
    rrsig=$(dig +dnssec "$domain" SOA | grep "RRSIG")
    local keys
    keys=$(dig +short DNSKEY "$domain")
    local weight=${weights[DNSSEC]}

    if [ -n "$rrsig" ] && [ -n "$keys" ]; then
        ((current_score += weight))
        write_report "Status: ✅ Validated\nDetails: RRSIG + DNSKEY present"
        echo -e "${GREEN}✅ DNSSEC Valid${NC}"
        dnssec_status="YES"
    else
        write_report "Status: ❌ Not Validated\nSeverity: 🔴 HIGH\nImpact: DNS spoofing possible"
        echo -e "${RED}❌ DNSSEC Missing${NC}"
        dnssec_status="NO"
    fi
}

function check_mta_sts() {
    write_report "\n=== MTA-STS Check ==="
    local record
    record=$(dig +short txt "_mta-sts.$domain" | grep "v=STSv1")
    local weight=${weights[MTA-STS]}

    if [ -z "$record" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🔶 MEDIUM\nImpact: Insecure delivery possible"
        echo -e "${RED}❌ MTA-STS Missing${NC}"
        mta_sts_status="NO"
    else
        ((current_score += weight))
        write_report "Status: ✅ Found\nRecord: $record"
        echo -e "${GREEN}✅ MTA-STS Found${NC}"
        mta_sts_status="YES"

        # Policy check
        local policy
        policy=$(curl -s "https://mta-sts.$domain/.well-known/mta-sts.txt")
        [[ $policy =~ "version: STSv1" ]] || {
            write_report "Warning: Invalid policy file"
            echo -e "${YELLOW}⚠️ Invalid policy${NC}"
        }
    fi
}

function check_tls_rpt() {
    write_report "\n=== TLS-RPT Check ==="
    local record
    record=$(dig +short txt "_smtp._tls.$domain" | grep "v=TLSRPTv1")
    local weight=${weights[TLS-RPT]}

    if [ -z "$record" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🟡 LOW\nImpact: No TLS reports"
        echo -e "${RED}❌ TLS-RPT Missing${NC}"
        tls_rpt_status="NO"
    else
        ((current_score += weight))
        write_report "Status: ✅ Found\nRecord: $record"
        echo -e "${GREEN}✅ TLS-RPT Found${NC}"
        tls_rpt_status="YES"
    fi
}

function check_bimi() {
    write_report "\n=== BIMI Check ==="
    local record
    record=$(dig +short txt "default._bimi.$domain" | grep "v=BIMI1")
    local weight=${weights[BIMI]}

    if [ -z "$record" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🟡 LOW\nImpact: No brand indicators"
        echo -e "${RED}❌ BIMI Missing${NC}"
        bimi_status="NO"
    else
        ((current_score += weight))
        write_report "Status: ✅ Found\nRecord: $record"
        echo -e "${GREEN}✅ BIMI Found${NC}"
        bimi_status="YES"
    fi
}

function check_caa() {
    write_report "\n=== CAA Check ==="
    local records
    records=$(dig +short caa "$domain")
    local weight=${weights[CAA]}

    if [ -z "$records" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🔶 MEDIUM\nImpact: Any CA can issue certs"
        echo -e "${RED}❌ CAA Missing${NC}"
        caa_status="NO"
    else
        ((current_score += weight))
        write_report "Status: ✅ Found\nRecords:\n$records"
        echo -e "${GREEN}✅ CAA Found${NC}"
        caa_status="YES"
    fi
}

function suggest_fixes() {
    write_report "\n=== Recommended DNS Fixes ==="

    # Header (console only)
    echo -e "\n${YELLOW}=== Recommended DNS Fixes for $domain ===${NC}"

    local spf_check dmarc_check caa_check

    spf_check=$(dig +short txt "$domain" | grep "v=spf1")
    if [ -z "$spf_check" ]; then
        write_report "[SPF] Add this TXT record to your DNS:"
        write_report "      Host: @"
        write_report "      Value: v=spf1 include:_spf.google.com ~all"

        echo -e "${CYAN}[SPF]${NC} Add this TXT record to your DNS:"
        echo "      Host: @  |  Value: v=spf1 include:_spf.google.com ~all"
    fi

    dmarc_check=$(dig +short txt "_dmarc.$domain" | grep "v=DMARC1")
    if [ -z "$dmarc_check" ]; then
        write_report "[DMARC] Add this TXT record to protect your brand:"
        write_report "        Host: _dmarc"
        write_report "        Value: v=DMARC1; p=quarantine; rua=mailto:admin@$domain"

        echo -e "${CYAN}[DMARC]${NC} Add this TXT record to protect your brand:"
        echo "      Host: _dmarc  |  Value: v=DMARC1; p=quarantine; rua=mailto:admin@$domain"
    fi

    caa_check=$(dig +short caa "$domain")
    if [ -z "$caa_check" ]; then
        write_report "[CAA] To prevent unauthorized SSL certificates:"
        write_report "      Host: @"
        write_report "      Value: 0 issue \"letsencrypt.org\""

        echo -e "${CYAN}[CAA]${NC} To prevent unauthorized SSL certificates:"
        echo "      Host: @  |  Value: 0 issue \"letsencrypt.org\""
    fi

    # If nothing was added, at least say it
    if [ -n "$spf_check" ] && [ -n "$dmarc_check" ] && [ -n "$caa_check" ]; then
        write_report "No immediate DNS record fixes detected for SPF/DMARC/CAA."
    fi
}


# Score Calculation + append to summary table
function generate_summary() {
    local elapsed=$(( $(date +%s) - start_time ))
    local score=$(( current_score * 100 / max_score ))

    local grade_label
    local grade_console

    if (( score >= 90 )); then
        grade_label="Excellent"
        grade_console="🟢 Excellent"
    elif (( score >= 75 )); then
        grade_label="Good"
        grade_console="🟡 Good"
    elif (( score >= 50 )); then
        grade_label="Fair"
        grade_console="🟠 Fair"
    else
        grade_label="Poor"
        grade_console="🔴 Poor"
    fi

    # 1) Global counters for stats
    ((total_domains++))
    [[ "$spf_status"  == "Missing" ]] && ((count_spf_missing++))
    [[ "$dkim_status" == "Missing" ]] && ((count_dkim_missing++))

    case "$dmarc_status" in
        Enforced|Enf-SPF|Enf-DKIM)
            ((count_dmarc_enforced++))
            ;;
        Monitor)
            ((count_dmarc_monitor++))
            ;;
        Missing)
            ((count_dmarc_missing++))
            ;;
        Ineffective)
            ((count_dmarc_ineffective++))
            ;;
    esac

    # 2) Risk classification (Low / Medium / High / Critical)
    local have_spf=1
    [[ "$spf_status" == "Missing" ]] && have_spf=0

    local have_dkim=1
    [[ "$dkim_status" == "Missing" ]] && have_dkim=0

    if [[ "$dmarc_status" == "Ineffective" || "$dmarc_status" == "Missing" ]]; then
        if (( have_spf == 0 && have_dkim == 0 )); then
            risk_level="Critical"
        else
            risk_level="High"
        fi
    elif [[ "$dmarc_status" == "Monitor" ]]; then
        risk_level="Medium"
    elif [[ "$dmarc_status" == Enf-SPF* || "$dmarc_status" == Enf-DKIM* ]]; then
        risk_level="Medium"
    else
        # "Enforced" with both SPF & DKIM present
        risk_level="Low"
    fi

    case "$risk_level" in
        Low)      ((count_risk_low++));;
        Medium)   ((count_risk_medium++));;
        High)     ((count_risk_high++));;
        Critical) ((count_risk_critical++));;
    esac

    local line=" - $domain (Score ${score}%, DMARC: ${dmarc_status} (${dmarc_policy}))"
    case "$risk_level" in
        Low)      risk_low_list+="${line}\n";;
        Medium)   risk_medium_list+="${line}\n";;
        High)     risk_high_list+="${line}\n";;
        Critical) risk_critical_list+="${line}\n";;
    esac

    # 3) Write final section into the single-domain TXT report
    write_report "\n=== Final Report ==="
    write_report "Security Score: ${score}% (${grade_console})"
    write_report "Elapsed Time: ${elapsed}s"
    write_report "File: $report_file"

    write_report "\n=== Summary (table view) ==="
    write_report "SPF   : $spf_status"
    write_report "DKIM  : ${dkim_status} (${dkim_count})"
    write_report "DMARC : ${dmarc_status} (${dmarc_policy})"
    write_report "Score : ${score}% (${grade_label})"
    write_report "Risk  : ${risk_level}"

    # 4) Console display
    echo -e "\n${CYAN}=== Results for $domain ===${NC}"
    echo -e "Score: ${YELLOW}$score%${NC} ($grade_console)"
    echo -e "Report: ${CYAN}$report_file${NC}"
    echo -e "${YELLOW}=== Done in ${elapsed}s ===${NC}"

    # 5) Track this report for the big full report
    REPORT_FILES+=("$report_file")
    REPORT_DOMAINS+=("$domain")

    # 6) Append to summary table
    if [ -n "$SUMMARY_FILE" ]; then
        printf "%-30s | %-18s | %-18s | %-24s | %-5s | %-7s | %-7s | %-5s | %-7s | %-5s | %6s | %-10s\n" \
            "$domain" \
            "$spf_status" \
            "${dkim_status} (${dkim_count})" \
            "${dmarc_status} (${dmarc_policy})" \
            "$mx_status" \
            "$mta_sts_status" \
            "$tls_rpt_status" \
            "$bimi_status" \
            "$dnssec_status" \
            "$caa_status" \
            "$score" \
            "$grade_label" >> "$SUMMARY_FILE"
    fi
}


function finalize_full_report() {
    {
        echo "============================================================"
        echo "EMAIL SECURITY FULL REPORT"
        echo "Generated on: $(date)"
        echo "Domains scanned: $total_domains"
        echo "Reports folder: $REPORT_DIR"
        echo "============================================================"
        echo
        echo "======================="
        echo " EXECUTIVE SUMMARY"
        echo "======================="
        echo "• DMARC enforced (reject/quarantine):  $count_dmarc_enforced domains"
        echo "• DMARC monitor (p=none / unusual):   $count_dmarc_monitor domains"
        echo "• DMARC missing:                       $count_dmarc_missing domains"
        echo "• DMARC ineffective:                   $count_dmarc_ineffective domains"
        echo
        echo "• SPF missing:                         $count_spf_missing domains"
        echo "• DKIM missing:                        $count_dkim_missing domains"
        echo
        echo "Risk levels:"
        echo "• Low risk:        $count_risk_low domains"
        echo "• Medium risk:     $count_risk_medium domains"
        echo "• High risk:       $count_risk_high domains"
        echo "• Critical risk:   $count_risk_critical domains"
        echo
        echo "======================="
        echo " RISK OVERVIEW"
        echo "======================="
        echo
        echo "[CRITICAL RISK]"
        if [ -n "$risk_critical_list" ]; then
            echo -e "$risk_critical_list"
        else
            echo " (none)"
        fi
        echo
        echo "[HIGH RISK]"
        if [ -n "$risk_high_list" ]; then
            echo -e "$risk_high_list"
        else
            echo " (none)"
        fi
        echo
        echo "[MEDIUM RISK]"
        if [ -n "$risk_medium_list" ]; then
            echo -e "$risk_medium_list"
        else
            echo " (none)"
        fi
        echo
        echo "[LOW RISK]"
        if [ -n "$risk_low_list" ]; then
            echo -e "$risk_low_list"
        else
            echo " (none)"
        fi
        echo
        echo "======================="
        echo " SUMMARY TABLE"
        echo "======================="
        echo
        cat "$SUMMARY_FILE"
        echo
        echo "======================="
        echo " DETAILED FINDINGS"
        echo "======================="
        echo

        local i
        for ((i=0; i<${#REPORT_FILES[@]}; i++)); do
            local df="${REPORT_FILES[$i]}"
            local dom="${REPORT_DOMAINS[$i]}"

            echo "------------------------------------------------------------"
            echo "Domain: $dom"
            echo "Report file: $(basename "$df")"
            echo "------------------------------------------------------------"
            echo
            cat "$df"
            echo
            echo
        done

    } > "$FULL_REPORT_FILE"

    echo -e "${GREEN}Full report written to: ${YELLOW}$FULL_REPORT_FILE${NC}"
}



# ---------------- MAIN FLOW ---------------- #

clear

parse_args "$@"
check_deps

# Pre-compute max_score once (same for all domains)
max_score=$(IFS=+; echo "$((${weights[*]}))")

# Create reports folder for this run
RUN_TS=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="email_reports_${RUN_TS}"
mkdir -p "$REPORT_DIR"
echo -e "${CYAN}Reports will be stored in: ${YELLOW}${REPORT_DIR}${NC}"

FULL_REPORT_FILE="${REPORT_DIR}/email_security_full_report.txt"

# Init summary table file
init_summary_file


# Single-domain mode
if [ -n "$domain" ]; then
    if ! validate_domain "$domain"; then
        exit 1
    fi

    echo -e "${YELLOW}--- Checking single domain: $domain ---${NC}"

    reset_state
    init_report "$domain"

    check_spf
    check_dkim
    check_dmarc
    check_mx
    check_mta_sts
    check_tls_rpt
    check_bimi
    check_dnssec
    check_caa
    suggest_fixes
    generate_summary

    finalize_full_report

    echo -e "\n${GREEN}Done. All reports, summary table and full report are in: ${YELLOW}$REPORT_DIR${NC}"
    exit 0
fi


# Multi-domain CSV mode
if [ -n "$csv_file" ]; then
    if [ ! -f "$csv_file" ]; then
        echo -e "${RED}File not found: $csv_file${NC}"
        exit 1
    fi

    echo -e "${CYAN}Processing domains from CSV: ${YELLOW}$csv_file${NC}"

    # Supports:
    #  - one domain per line
    #  - multiple domains per line, comma-separated
    #  - optional header "domain"
    while IFS= read -r line; do
        # Skip completely empty lines
        [[ -z "$line" ]] && continue

        IFS=',' read -ra fields <<< "$line"

        for raw in "${fields[@]}"; do
            domain=$(echo "$raw" | xargs)  # trim spaces

            # Skip empty after trimming
            [ -z "$domain" ] && continue

            # Skip header-like value
            if [[ "$domain" =~ ^[Dd]omain$ ]]; then
                echo -e "${CYAN}Skipping header value: $domain${NC}"
                continue
            fi

            echo -e "\n${YELLOW}--- Checking domain: $domain ---${NC}"

            if ! validate_domain "$domain"; then
                echo -e "${YELLOW}Skipping invalid domain: $domain${NC}"
                continue
            fi

            reset_state
            init_report "$domain"

            check_spf
            check_dkim
            check_dmarc
            check_mx
            check_mta_sts
            check_tls_rpt
            check_bimi
            check_dnssec
            check_caa
            suggest_fixes
            generate_summary
        done

    done < "$csv_file"

    finalize_full_report

    echo -e "\n${GREEN}All domains processed.${NC}"
    echo -e "${CYAN}Per-domain reports, summary table and full report are in: ${YELLOW}$REPORT_DIR${NC}"
fi
