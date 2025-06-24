#!/bin/bash

# ==============================
# 🔐 GoGoGadget SSL - SSL/TLS Security Analyzer
# ==============================

GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
NC="\033[0m"

echo -e "${BLUE}"
echo "┌────────────────────────────────────────────────────────┐"
echo "│  🔐 GoGoGadget SSL - SSL/TLS Security Analyzer        │"
echo "│  🛡️ Certificate & Encryption Security Assessment      │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# Function to check dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command -v openssl &>/dev/null; then
        missing_deps+=("openssl")
    fi
    
    if ! command -v curl &>/dev/null; then
        missing_deps+=("curl")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${YELLOW}📦 Installing missing dependencies: ${missing_deps[*]}${NC}"
        
        if command -v dnf &>/dev/null; then
            sudo dnf install -y "${missing_deps[@]}"
        elif command -v yum &>/dev/null; then
            sudo yum install -y "${missing_deps[@]}"
        elif command -v apt &>/dev/null; then
            sudo apt update && sudo apt install -y "${missing_deps[@]}"
        else
            echo -e "${RED}❌ Please install: ${missing_deps[*]}${NC}"
            exit 1
        fi
    fi
}

# SSL/TLS analysis functions
analyze_certificate() {
    local target=$1
    local port=${2:-443}
    
    echo -e "\n${CYAN}🔍 Analyzing SSL certificate for $target:$port${NC}"
    
    # Get certificate info
    local cert_info=$(echo | openssl s_client -servername "$target" -connect "$target:$port" 2>/dev/null | openssl x509 -noout -dates -subject -issuer -text)
    
    if [[ -z "$cert_info" ]]; then
        echo -e "${RED}❌ Unable to retrieve certificate for $target:$port${NC}"
        return 1
    fi
    
    # Parse certificate details
    local not_before=$(echo "$cert_info" | grep "notBefore" | cut -d'=' -f2-)
    local not_after=$(echo "$cert_info" | grep "notAfter" | cut -d'=' -f2-)
    local subject=$(echo "$cert_info" | grep "subject=" | cut -d'=' -f2-)
    local issuer=$(echo "$cert_info" | grep "issuer=" | cut -d'=' -f2-)
    
    # Check expiration
    local exp_epoch=$(date -d "$not_after" +%s 2>/dev/null)
    local current_epoch=$(date +%s)
    local days_until_exp=$(( (exp_epoch - current_epoch) / 86400 ))
    
    echo -e "${GREEN}📋 Certificate Details:${NC}"
    echo -e "  Subject: $subject"
    echo -e "  Issuer: $issuer"
    echo -e "  Valid From: $not_before"
    echo -e "  Valid Until: $not_after"
    
    if [[ $days_until_exp -lt 0 ]]; then
        echo -e "  ${RED}🚨 Status: EXPIRED ($((days_until_exp * -1)) days ago)${NC}"
        return 2
    elif [[ $days_until_exp -lt 30 ]]; then
        echo -e "  ${YELLOW}⚠️ Status: Expires in $days_until_exp days${NC}"
        return 1
    else
        echo -e "  ${GREEN}✅ Status: Valid ($days_until_exp days remaining)${NC}"
    fi
    
    # Check for SAN (Subject Alternative Names)
    local san_info=$(echo "$cert_info" | grep -A1 "Subject Alternative Name" | tail -1)
    if [[ -n "$san_info" ]]; then
        echo -e "  SANs: $san_info"
    fi
    
    return 0
}

# Check SSL configuration
check_ssl_config() {
    local target=$1
    local port=${2:-443}
    
    echo -e "\n${CYAN}🔧 Analyzing SSL/TLS configuration for $target:$port${NC}"
    
    # Test different TLS versions
    echo -e "${YELLOW}🔍 Testing TLS protocol support:${NC}"
    
    local protocols=("ssl3" "tls1" "tls1_1" "tls1_2" "tls1_3")
    for proto in "${protocols[@]}"; do
        if echo | openssl s_client -"$proto" -connect "$target:$port" -servername "$target" 2>/dev/null | grep -q "Verify return code: 0"; then
            case "$proto" in
                "ssl3"|"tls1"|"tls1_1")
                    echo -e "  ${RED}❌ $proto: SUPPORTED (INSECURE)${NC}"
                    ;;
                "tls1_2")
                    echo -e "  ${YELLOW}⚠️ $proto: SUPPORTED${NC}"
                    ;;
                "tls1_3")
                    echo -e "  ${GREEN}✅ $proto: SUPPORTED (SECURE)${NC}"
                    ;;
            esac
        else
            echo -e "  ${GREEN}✅ $proto: NOT SUPPORTED${NC}"
        fi
    done
    
    # Check cipher suites
    echo -e "\n${YELLOW}🔍 Analyzing cipher suites:${NC}"
    local cipher_info=$(echo | openssl s_client -connect "$target:$port" -servername "$target" 2>/dev/null | grep "Cipher")
    if [[ -n "$cipher_info" ]]; then
        echo -e "  Current cipher: $cipher_info"
        
        # Check for weak ciphers
        if echo "$cipher_info" | grep -qi "rc4\|des\|md5\|null"; then
            echo -e "  ${RED}🚨 WEAK CIPHER DETECTED!${NC}"
        else
            echo -e "  ${GREEN}✅ Strong cipher in use${NC}"
        fi
    fi
    
    # Check for perfect forward secrecy
    if echo | openssl s_client -connect "$target:$port" -servername "$target" 2>/dev/null | grep -q "ECDHE\|DHE"; then
        echo -e "  ${GREEN}✅ Perfect Forward Secrecy: SUPPORTED${NC}"
    else
        echo -e "  ${YELLOW}⚠️ Perfect Forward Secrecy: NOT DETECTED${NC}"
    fi
}

# Check HTTP security headers
check_security_headers() {
    local target=$1
    local port=${2:-443}
    local protocol="https"
    
    [[ $port -eq 80 ]] && protocol="http"
    
    echo -e "\n${CYAN}🛡️ Checking HTTP security headers for $protocol://$target${NC}"
    
    local headers=$(curl -s -I "$protocol://$target" 2>/dev/null)
    
    if [[ -z "$headers" ]]; then
        echo -e "${RED}❌ Unable to retrieve headers from $target${NC}"
        return 1
    fi
    
    # Check important security headers
    declare -A security_headers=(
        ["Strict-Transport-Security"]="HSTS"
        ["X-Frame-Options"]="Clickjacking Protection"
        ["X-Content-Type-Options"]="MIME Type Sniffing Protection"
        ["X-XSS-Protection"]="XSS Protection"
        ["Content-Security-Policy"]="CSP"
        ["Referrer-Policy"]="Referrer Policy"
        ["Permissions-Policy"]="Permissions Policy"
    )
    
    for header in "${!security_headers[@]}"; do
        if echo "$headers" | grep -qi "$header"; then
            echo -e "  ${GREEN}✅ ${security_headers[$header]}: PRESENT${NC}"
        else
            echo -e "  ${RED}❌ ${security_headers[$header]}: MISSING${NC}"
        fi
    done
    
    # Check for server information disclosure
    local server_header=$(echo "$headers" | grep -i "server:" | cut -d':' -f2- | tr -d ' \r\n')
    if [[ -n "$server_header" ]]; then
        echo -e "  ${YELLOW}ℹ️ Server: $server_header${NC}"
        if echo "$server_header" | grep -qi "apache\|nginx\|iis"; then
            echo -e "    ${YELLOW}⚠️ Consider hiding server version information${NC}"
        fi
    fi
}

# Generate SSL security report
generate_ssl_report() {
    local target=$1
    local port=$2
    
    local report_file="ssl_security_report_${target}_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
🔐 SSL/TLS Security Analysis Report
==================================
Target: $target:$port
Generated: $(date)

$(analyze_certificate "$target" "$port" 2>&1)

$(check_ssl_config "$target" "$port" 2>&1)

$(check_security_headers "$target" "$port" 2>&1)

RECOMMENDATIONS:
===============
1. Ensure certificates are renewed before expiration
2. Disable SSL 3.0, TLS 1.0, and TLS 1.1
3. Enable TLS 1.3 for maximum security
4. Implement all security headers
5. Use strong cipher suites only
6. Enable Perfect Forward Secrecy
7. Hide server version information

Report generated by GoGoGadget SSL Security Analyzer
EOF
    
    echo -e "\n${GREEN}📄 Detailed report saved: $report_file${NC}"
}

# Scan multiple targets
scan_multiple_targets() {
    echo -e "\n${BLUE}🎯 Multiple Target SSL Scan${NC}"
    echo "Enter targets (one per line, press Enter twice when done):"
    
    local targets=()
    while true; do
        read -r target
        [[ -z "$target" ]] && break
        targets+=("$target")
    done
    
    if [[ ${#targets[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No targets specified${NC}"
        return
    fi
    
    echo "Target,Port,Certificate Status,Days Until Expiry,TLS 1.3 Support,Security Headers Score" > ssl_scan_results.csv
    
    for target in "${targets[@]}"; do
        echo -e "\n${CYAN}🔍 Scanning $target...${NC}"
        
        # Basic analysis for CSV
        local port=443
        if [[ "$target" == *":"* ]]; then
            port=$(echo "$target" | cut -d':' -f2)
            target=$(echo "$target" | cut -d':' -f1)
        fi
        
        analyze_certificate "$target" "$port" >/dev/null 2>&1
        local cert_status=$?
        
        # Get days until expiry
        local cert_info=$(echo | openssl s_client -servername "$target" -connect "$target:$port" 2>/dev/null | openssl x509 -noout -dates)
        local not_after=$(echo "$cert_info" | grep "notAfter" | cut -d'=' -f2-)
        local exp_epoch=$(date -d "$not_after" +%s 2>/dev/null)
        local current_epoch=$(date +%s)
        local days_until_exp=$(( (exp_epoch - current_epoch) / 86400 ))
        
        # Check TLS 1.3 support
        local tls13_support="No"
        if echo | openssl s_client -tls1_3 -connect "$target:$port" -servername "$target" 2>/dev/null | grep -q "Verify return code: 0"; then
            tls13_support="Yes"
        fi
        
        # Count security headers
        local headers=$(curl -s -I "https://$target" 2>/dev/null)
        local header_count=0
        for header in "Strict-Transport-Security" "X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" "Content-Security-Policy"; do
            if echo "$headers" | grep -qi "$header"; then
                ((header_count++))
            fi
        done
        
        local status_text="Valid"
        [[ $cert_status -eq 1 ]] && status_text="Expiring Soon"
        [[ $cert_status -eq 2 ]] && status_text="Expired"
        
        echo "$target,$port,$status_text,$days_until_exp,$tls13_support,$header_count/5" >> ssl_scan_results.csv
    done
    
    echo -e "\n${GREEN}✅ Multiple target scan completed!${NC}"
    echo -e "${CYAN}📂 Results saved to: ssl_scan_results.csv${NC}"
}

# Main menu
display_menu() {
    echo -e "\n${YELLOW}🔐 SSL/TLS Security Analysis Options:${NC}"
    echo "────────────────────────────────────────────"
    echo "[1] Single target analysis"
    echo "[2] Certificate expiration check"
    echo "[3] SSL configuration audit"
    echo "[4] Security headers check"
    echo "[5] Multiple target scan"
    echo "[6] Generate comprehensive report"
    echo "[Q] Quit"
}

# Main execution
main() {
    check_dependencies
    
    while true; do
        display_menu
        echo -n "Enter your choice: "
        read -r choice
        
        case "$choice" in
            1)
                echo -n "Enter target hostname/IP: "
                read -r target
                echo -n "Enter port (default 443): "
                read -r port
                port=${port:-443}
                
                analyze_certificate "$target" "$port"
                check_ssl_config "$target" "$port"
                check_security_headers "$target" "$port"
                ;;
            2)
                echo -n "Enter target hostname/IP: "
                read -r target
                echo -n "Enter port (default 443): "
                read -r port
                port=${port:-443}
                analyze_certificate "$target" "$port"
                ;;
            3)
                echo -n "Enter target hostname/IP: "
                read -r target
                echo -n "Enter port (default 443): "
                read -r port
                port=${port:-443}
                check_ssl_config "$target" "$port"
                ;;
            4)
                echo -n "Enter target hostname/IP: "
                read -r target
                echo -n "Enter port (default 443): "
                read -r port
                port=${port:-443}
                check_security_headers "$target" "$port"
                ;;
            5)
                scan_multiple_targets
                ;;
            6)
                echo -n "Enter target hostname/IP: "
                read -r target
                echo -n "Enter port (default 443): "
                read -r port
                port=${port:-443}
                generate_ssl_report "$target" "$port"
                ;;
            [Qq])
                echo -e "${BLUE}Exiting SSL analyzer... 🔐${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Invalid choice!${NC}"
                ;;
        esac
    done
}

main
