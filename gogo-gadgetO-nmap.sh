#!/bin/bash

# ==============================
# 🌐 GoGoGadget Nmap - Advanced Network Security Scanner
# ==============================

# Define colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
NC="\033[0m"

# ASCII Art Header
echo -e "${BLUE}"
echo "┌────────────────────────────────────────────────────────┐"
echo "│  🌐 GoGoGadget Nmap - Network Security Scanner        │"
echo "│  🔍 Discovering what attackers see on your network... │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# Function to detect OS and install Nmap
setup_nmap() {
    if ! command -v nmap &> /dev/null; then
        echo -e "${YELLOW}📦 Nmap not found. Installing...${NC}"
        
        if command -v dnf &>/dev/null; then
            sudo dnf install -y nmap
        elif command -v yum &>/dev/null; then
            sudo yum install -y nmap
        elif command -v apt &>/dev/null; then
            sudo apt update && sudo apt install -y nmap
        elif command -v pacman &>/dev/null; then
            sudo pacman -S nmap --noconfirm
        else
            echo -e "${RED}❌ Cannot install Nmap automatically. Please install manually.${NC}"
            exit 1
        fi
    fi
}

# Get network information
get_network_info() {
    echo -e "${CYAN}🔍 Detecting local network...${NC}"
    
    # Get default gateway and local IP
    DEFAULT_GW=$(ip route | grep default | awk '{print $3}' | head -1)
    LOCAL_IP=$(ip route get 8.8.8.8 | awk '{print $7}' | head -1)
    
    # Calculate network range
    if [[ -n "$LOCAL_IP" ]]; then
        INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5}' | head -1)
        SUBNET=$(ip addr show "$INTERFACE" | grep "$LOCAL_IP" | awk '{print $2}' | head -1)
        NETWORK_RANGE=$(echo "$SUBNET" | cut -d'/' -f1 | sed 's/\.[0-9]*$/\.0/' | head -1)/24
    else
        NETWORK_RANGE="192.168.1.0/24"
    fi
    
    echo -e "${GREEN}✅ Local IP: $LOCAL_IP${NC}"
    echo -e "${GREEN}✅ Network Range: $NETWORK_RANGE${NC}"
}

# Scan options
declare -A scans
scans=(
    ["Quick Network Discovery"]="discovery"
    ["Port Scan (Top 1000 Ports)"]="portscan"
    ["Service Detection Scan"]="services"
    ["Aggressive Scan + OS Detection"]="aggressive"
    ["Vulnerability Scan"]="vulnscan"
    ["Stealth SYN Scan"]="stealth"
    ["UDP Scan (Top Ports)"]="udpscan"
    ["Custom Target Scan"]="custom"
)

# Display menu
display_menu() {
    echo -e "\n${YELLOW}🎯 Select Network Scan Type:${NC}"
    echo "────────────────────────────────────────"
    i=1
    for scan in "${!scans[@]}"; do
        echo "[$i] $scan"
        options[$i]="${scans[$scan]}"
        ((i++))
    done
    echo "[A] Run Complete Network Analysis"
    echo "[Q] Quit"
}

# Network discovery
network_discovery() {
    local target=$1
    echo -e "\n${CYAN}🔍 Discovering hosts on $target...${NC}"
    
    echo "IP Address,Hostname,MAC Address,Vendor,Status" > network_scan_report.csv
    
    nmap -sn "$target" | awk '
    BEGIN { ip = ""; hostname = ""; mac = ""; vendor = "" }
    /Nmap scan report for/ { 
        if (ip != "") print ip","hostname","mac","vendor",Up"
        if ($5 ~ /\(.*\)/) {
            hostname = $5; gsub(/[()]/, "", hostname)
            ip = $6; gsub(/[()]/, "", ip)
        } else {
            ip = $5; hostname = ip
        }
        mac = ""; vendor = ""
    }
    /MAC Address:/ {
        mac = $3; vendor = ""
        for (i=4; i<=NF; i++) vendor = vendor " " $i
        gsub(/^ /, "", vendor); gsub(/[()]/, "", vendor)
    }
    END { if (ip != "") print ip","hostname","mac","vendor",Up }
    ' >> network_scan_report.csv
    
    local host_count=$(grep -c "Up" network_scan_report.csv 2>/dev/null || echo "0")
    echo -e "${GREEN}✅ Network discovery completed! Found $host_count active hosts${NC}"
}

# Port scanning
port_scan() {
    local target=$1
    echo -e "\n${CYAN}🔍 Scanning ports on $target...${NC}"
    
    echo "IP Address,Port,State,Service" > services_analysis.csv
    
    nmap -T4 --top-ports 1000 "$target" | awk '
    BEGIN { ip = "" }
    /Nmap scan report for/ { ip = $NF; gsub(/[()]/, "", ip) }
    /^[0-9]+\// {
        port = $1; gsub(/\/.*/, "", port)
        state = $2
        service = $3
        if (state == "open") {
            print ip","port","state","service
        }
    }' >> services_analysis.csv
    
    local open_ports=$(grep -c "open" services_analysis.csv 2>/dev/null || echo "0")
    echo -e "${GREEN}✅ Port scan completed! Found $open_ports open ports${NC}"
}

# Service detection
service_detection() {
    local target=$1
    echo -e "\n${CYAN}🔍 Detecting services on $target...${NC}"
    
    echo "IP Address,Port,Protocol,Service,Version" > services_detailed.csv
    
    nmap -sV -T4 "$target" | awk '
    BEGIN { ip = "" }
    /Nmap scan report for/ { ip = $NF; gsub(/[()]/, "", ip) }
    /^[0-9]+\// {
        port = $1; gsub(/\/.*/, "", port)
        protocol = $1; gsub(/.*\//, "", protocol)
        state = $2
        service = $3
        version = ""
        for (i=4; i<=NF; i++) version = version " " $i
        gsub(/^ /, "", version)
        if (state == "open") {
            print ip","port","protocol","service",\"" version "\""
        }
    }' >> services_detailed.csv
    
    echo -e "${GREEN}✅ Service detection completed!${NC}"
}

# Vulnerability scan
vulnerability_scan() {
    local target=$1
    echo -e "\n${CYAN}🔍 Scanning for vulnerabilities on $target...${NC}"
    echo -e "${YELLOW}⚠️ This may take a while and could be detected!${NC}"
    
    echo "IP Address,Port,Vulnerability,Severity" > vulnerability_scan.csv
    
    if ls /usr/share/nmap/scripts/vuln* &>/dev/null; then
        nmap --script vuln -T4 "$target" | awk '
        BEGIN { ip = ""; port = "" }
        /Nmap scan report for/ { ip = $NF; gsub(/[()]/, "", ip) }
        /^[0-9]+\// { port = $1; gsub(/\/.*/, "", port) }
        /\|.*CVE/ {
            vuln = $0
            gsub(/\|_?/, "", vuln)
            gsub(/^ */, "", vuln)
            print ip","port",\"" vuln "\",Medium"
        }' >> vulnerability_scan.csv
    else
        echo -e "${YELLOW}⚠️ Vulnerability scripts not available${NC}"
    fi
    
    echo -e "${GREEN}✅ Vulnerability scan completed!${NC}"
}

# Comprehensive analysis
comprehensive_analysis() {
    local target=$1
    echo -e "\n${BLUE}🚀 Running comprehensive network analysis...${NC}"
    
    network_discovery "$target"
    sleep 2
    port_scan "$target"
    sleep 2
    service_detection "$target"
    
    echo -e "\n${GREEN}🎯 Comprehensive analysis completed!${NC}"
    
    # Security assessment
    local hosts=$(grep -c "Up" network_scan_report.csv 2>/dev/null || echo "0")
    local open_ports=$(grep -c "open" services_analysis.csv 2>/dev/null || echo "0")
    
    echo -e "\n${CYAN}📊 Security Assessment:${NC}"
    echo -e "  🏠 Active hosts discovered: $hosts"
    echo -e "  🔓 Open ports found: $open_ports"
    
    if [[ $open_ports -gt 50 ]]; then
        echo -e "${RED}⚠️ HIGH: Large attack surface detected!${NC}"
    elif [[ $open_ports -gt 20 ]]; then
        echo -e "${YELLOW}⚠️ MEDIUM: Moderate attack surface${NC}"
    else
        echo -e "${GREEN}✅ LOW: Minimal attack surface${NC}"
    fi
}

# Main execution
main() {
    setup_nmap
    get_network_info
    
    # Target selection
    echo -e "\n${YELLOW}🎯 Target Selection:${NC}"
    echo "1) Scan local network ($NETWORK_RANGE)"
    echo "2) Scan specific IP/hostname"
    echo "3) Scan IP range"
    echo -n "Enter choice (1/2/3): "
    read -r target_choice
    
    case $target_choice in
        1) TARGET="$NETWORK_RANGE" ;;
        2) 
            echo -n "Enter IP address or hostname: "
            read -r TARGET
            ;;
        3)
            echo -n "Enter IP range (e.g., 192.168.1.1-50): "
            read -r TARGET
            ;;
        *) TARGET="$NETWORK_RANGE" ;;
    esac
    
    echo -e "${GREEN}✅ Target set to: $TARGET${NC}"
    
    # Main menu loop
    while true; do
        display_menu
        echo -n "Enter your choice: "
        read -r input
        
        case "$input" in
            [Qq]) 
                echo -e "${BLUE}Exiting... Stay secure! 🛡️${NC}"
                exit 0
                ;;
            [Aa])
                comprehensive_analysis "$TARGET"
                break
                ;;
            [1-8])
                if [[ -n "${options[$input]}" ]]; then
                    case "${options[$input]}" in
                        "discovery") network_discovery "$TARGET" ;;
                        "portscan") port_scan "$TARGET" ;;
                        "services") service_detection "$TARGET" ;;
                        "aggressive") 
                            echo -e "${YELLOW}⚠️ Running aggressive scan...${NC}"
                            nmap -A -T4 "$TARGET" -oN "aggressive_scan_$(date +%Y%m%d_%H%M%S).txt"
                            ;;
                        "vulnscan") vulnerability_scan "$TARGET" ;;
                        "stealth")
                            echo -e "${CYAN}🥷 Running stealth scan...${NC}"
                            nmap -sS -T2 "$TARGET" > "stealth_scan_$(date +%Y%m%d_%H%M%S).txt"
                            ;;
                        "udpscan")
                            echo -e "${CYAN}📡 Running UDP scan...${NC}"
                            nmap -sU --top-ports 100 -T4 "$TARGET" > "udp_scan_$(date +%Y%m%d_%H%M%S).txt"
                            ;;
                        "custom")
                            echo -n "Enter custom nmap options: "
                            read -r custom_opts
                            nmap $custom_opts "$TARGET"
                            ;;
                    esac
                    break
                fi
                ;;
            *)
                echo -e "${RED}❌ Invalid selection!${NC}"
                ;;
        esac
    done
    
    echo -e "\n${GREEN}🎯 Network scan completed!${NC}"
    echo -e "${CYAN}📂 Reports: network_scan_report.csv, services_analysis.csv${NC}"
}

main
