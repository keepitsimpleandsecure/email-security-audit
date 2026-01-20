#!/bin/bash

# Email Security Checker
# Corrects DKIM/DNSSEC issues and IPv6 handling

# Text Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Initialize variables
domain=""
report_file=""
start_time=0
current_score=0
max_score=0

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

# Dependency Check
function check_deps() {
    local missing=()
    # Kali/Debian specific install string
    local install_cmd="sudo apt update && sudo apt install -y dnsutils curl openssl"

    for cmd in dig curl openssl; do
        if ! command -v $cmd &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Missing dependencies: ${missing[*]}${NC}"
        echo -e "${CYAN}On Kali Linux, run: ${NC}$install_cmd"
        exit 1
    fi
}

# Report Handling
function init_report() {
    domain="$1"
    report_file="email_security_report_${domain}_$(date +"%Y%m%d_%H%M%S").txt"
    > "$report_file"
    write_report "=== Email Security Report for ${domain} ==="
    write_report "Generated on: $(date)"
    write_report "=========================================="
}

function write_report() {
    echo -e "$1" | tee -a "$report_file"
}

# Domain Validation
function validate_domain() {
    [[ $1 =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$ ]] || {
        echo -e "${RED}Invalid domain format. Use example.com${NC}"
        exit 1
    }
}

# --- Core Checks --- #

function check_spf() {
    write_report "\n=== SPF Check ==="
    local record=$(dig +short txt "$domain" | grep "v=spf1")
    local weight=${weights[SPF]}

    if [ -z "$record" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🔴 HIGH\nImpact: Email spoofing possible"
        echo -e "${RED}❌ SPF Missing${NC}"
    else
        ((current_score += weight))
        write_report "Status: ✅ Found\nRecord: $record"
        echo -e "${GREEN}✅ SPF Found${NC}"

        # SPF redirect validation
        if [[ $record =~ redirect=([^ ]+) ]]; then
            local redirect_domain=${BASH_REMATCH[1]}
            local redirect_spf=$(dig +short txt "$redirect_domain" | grep "v=spf1")
            [ -z "$redirect_spf" ] && {
                write_report "Warning: Broken SPF redirect to $redirect_domain"
                echo -e "${YELLOW}⚠️ Broken SPF redirect${NC}"
            }
        fi
    fi
}

function check_dkim() {
    write_report "\n=== DKIM Check ==="
    local found=0
    local weight=${weights[DKIM]}

    for sel in "${DKIM_SELECTORS[@]}"; do
        local record=$(dig +short txt "${sel}._domainkey.$domain" | grep "v=DKIM1")
        if [ -n "$record" ]; then
            ((found++))
            write_report "Selector Found: $sel"
            echo -e "${GREEN}✅ DKIM (selector: $sel)${NC}"
        fi
    done

    if ((found > 0)); then
        ((current_score += weight))
        write_report "Status: ✅ Found ($found selectors)"
    else
        write_report "Status: ❌ Missing\nSeverity: 🔴 HIGH\nImpact: Email tampering possible"
        echo -e "${RED}❌ DKIM Missing${NC}"
    fi
}

function check_dmarc() {
    write_report "\n=== DMARC Check ==="
    local record=$(dig +short txt "_dmarc.$domain" | grep "v=DMARC1")
    local weight=${weights[DMARC]}

    if [ -z "$record" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🔴 HIGH\nImpact: No fraud protection"
        echo -e "${RED}❌ DMARC Missing${NC}"
    else
        ((current_score += weight))
        write_report "Status: ✅ Found\nRecord: $record"
        echo -e "${GREEN}✅ DMARC Found${NC}"

        # Policy check
        [[ $record =~ p=(reject|quarantine|none) ]] || {
            write_report "Warning: Invalid DMARC policy"
            echo -e "${YELLOW}⚠️ Invalid policy${NC}"
        }

        # Reporting check
        [[ $record =~ rua=mailto: ]] || {
            write_report "Warning: No reporting URI"
            echo -e "${YELLOW}⚠️ No reports configured${NC}"
        }
    fi
}

function check_mx() {
    write_report "\n=== MX Records Check ==="
    local records=$(dig +short mx "$domain" | sort -n)
    local weight=${weights[MX]}

    if [ -z "$records" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🔴 HIGH\nImpact: No email reception"
        echo -e "${RED}❌ MX Missing${NC}"
    else
        ((current_score += weight))
        write_report "Status: ✅ Found\nRecords:\n$records"
        echo -e "${GREEN}✅ MX Found${NC}"

        while read -r line; do
            local host=$(awk '{print $NF}' <<< "$line" | tr -d '"')

            # Skip A check for IPv6 MX
            if [[ $host =~ : ]]; then
                write_report "IPv6 MX: $host - A check skipped"
                echo -e "${CYAN}ℹ️ IPv6 MX: $host${NC}"
                continue
            fi

            local ips=$(dig +short a "$host")
            [ -z "$ips" ] && {
                write_report "Warning: MX $host has no A record"
                echo -e "${YELLOW}⚠️ No A for $host${NC}"
            }
        done <<< "$records"
    fi
}

function check_dnssec() {
    write_report "\n=== DNSSEC Check ==="
    local rrsig=$(dig +dnssec "$domain" SOA | grep "RRSIG")
    local keys=$(dig +short DNSKEY "$domain")
    local weight=${weights[DNSSEC]}

    if [ -n "$rrsig" ] && [ -n "$keys" ]; then
        ((current_score += weight))
        write_report "Status: ✅ Validated\nDetails: RRSIG + DNSKEY present"
        echo -e "${GREEN}✅ DNSSEC Valid${NC}"
    else
        write_report "Status: ❌ Not Validated\nSeverity: 🔴 HIGH\nImpact: DNS spoofing possible"
        echo -e "${RED}❌ DNSSEC Missing${NC}"
    fi
}

function check_mta_sts() {
    write_report "\n=== MTA-STS Check ==="
    local record=$(dig +short txt "_mta-sts.$domain" | grep "v=STSv1")
    local weight=${weights[MTA-STS]}

    if [ -z "$record" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🔶 MEDIUM\nImpact: Insecure delivery possible"
        echo -e "${RED}❌ MTA-STS Missing${NC}"
    else
        ((current_score += weight))
        write_report "Status: ✅ Found\nRecord: $record"
        echo -e "${GREEN}✅ MTA-STS Found${NC}"

        # Policy check
        local policy=$(curl -s "https://mta-sts.$domain/.well-known/mta-sts.txt")
        [[ $policy =~ "version: STSv1" ]] || {
            write_report "Warning: Invalid policy file"
            echo -e "${YELLOW}⚠️ Invalid policy${NC}"
        }
    fi
}

function check_tls_rpt() {
    write_report "\n=== TLS-RPT Check ==="
    local record=$(dig +short txt "_smtp._tls.$domain" | grep "v=TLSRPTv1")
    local weight=${weights[TLS-RPT]}

    if [ -z "$record" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🟡 LOW\nImpact: No TLS reports"
        echo -e "${RED}❌ TLS-RPT Missing${NC}"
    else
        ((current_score += weight))
        write_report "Status: ✅ Found\nRecord: $record"
        echo -e "${GREEN}✅ TLS-RPT Found${NC}"
    fi
}

function check_bimi() {
    write_report "\n=== BIMI Check ==="
    local record=$(dig +short txt "default._bimi.$domain" | grep "v=BIMI1")
    local weight=${weights[BIMI]}

    if [ -z "$record" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🟡 LOW\nImpact: No brand indicators"
        echo -e "${RED}❌ BIMI Missing${NC}"
    else
        ((current_score += weight))
        write_report "Status: ✅ Found\nRecord: $record"
        echo -e "${GREEN}✅ BIMI Found${NC}"
    fi
}

function check_caa() {
    write_report "\n=== CAA Check ==="
    local records=$(dig +short caa "$domain")
    local weight=${weights[CAA]}

    if [ -z "$records" ]; then
        write_report "Status: ❌ Missing\nSeverity: 🔶 MEDIUM\nImpact: Any CA can issue certs"
        echo -e "${RED}❌ CAA Missing${NC}"
    else
        ((current_score += weight))
        write_report "Status: ✅ Found\nRecords:\n$records"
        echo -e "${GREEN}✅ CAA Found${NC}"
    fi
}

function suggest_fixes() {
    write_report "\n=== Recommended DNS Fixes ==="
    echo -e "\n${YELLOW}=== Recommended DNS Fixes ===${NC}"
    
    # Logic for SPF Fix
    local spf_check=$(dig +short txt "$domain" | grep "v=spf1")
    if [ -z "$spf_check" ]; then
        echo -e "${CYAN}[SPF]${NC} Add this TXT record to your DNS:"
        echo "      Host: @  |  Value: v=spf1 include:_spf.google.com ~all"
    fi

    # Logic for DMARC Fix
    local dmarc_check=$(dig +short txt "_dmarc.$domain" | grep "v=DMARC1")
    if [ -z "$dmarc_check" ]; then
        echo -e "${CYAN}[DMARC]${NC} Add this TXT record to protect your brand:"
        echo "      Host: _dmarc  |  Value: v=DMARC1; p=quarantine; rua=mailto:admin@$domain"
    fi

    # Logic for CAA Fix
    local caa_check=$(dig +short caa "$domain")
    if [ -z "$caa_check" ]; then
        echo -e "${CYAN}[CAA]${NC} To prevent unauthorized SSL certificates:"
        echo "      Host: @  |  Value: 0 issue \"letsencrypt.org\""
    fi
}

# Score Calculation
function generate_summary() {
    local elapsed=$(( $(date +%s) - start_time ))
    local score=$(( current_score * 100 / max_score ))

    local grade
    if (( score >= 90 )); then grade="🟢 Excellent"
    elif (( score >= 75 )); then grade="🟡 Good"
    elif (( score >= 50 )); then grade="🟠 Fair"
    else grade="🔴 Poor"; fi

    write_report "\n=== Final Report ==="
    write_report "Security Score: $score% ($grade)"
    write_report "Elapsed Time: ${elapsed}s"
    write_report "File: $report_file"

    echo -e "\n${CYAN}=== Results ===${NC}"
    echo -e "Score: ${YELLOW}$score%${NC} ($grade)"
    echo -e "Report: ${CYAN}$report_file${NC}"
    echo -e "${YELLOW}=== Done in ${elapsed}s ===${NC}"
}

# Main Flow
clear
check_deps

echo -e "${YELLOW}=== Ultimate Email Security Checker ===${NC}"
read -p "Enter domain (e.g., example.com): " domain
validate_domain "$domain"

# Initialize
init_report "$domain"
start_time=$(date +%s)
max_score=$(IFS=+; echo "$((${weights[*]}))")

# Run Checks
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
