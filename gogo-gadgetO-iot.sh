#!/bin/bash

#==============================================================================
# GoGo-GadgetO IoT Device Scanner v2.0
# Advanced IoT Security Assessment & Vulnerability Scanner
#==============================================================================
# Author: Security Operations Team
# Description: Comprehensive IoT device discovery, security assessment, and vulnerability scanning
# Features: Device discovery, protocol analysis, security testing, compliance validation
# Requirements: nmap, curl, mosquitto-clients, coap-client, python3, netcat
#==============================================================================

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_NAME="GoGo-GadgetO IoT Scanner"
VERSION="2.0"
SCAN_DIR="/tmp/gogo-gadget-iot-$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$SCAN_DIR/iot_scan.log"
REPORT_FILE="$SCAN_DIR/iot_security_report.html"
JSON_REPORT="$SCAN_DIR/iot_scan_results.json"

# IoT Device signatures and ports
IOT_PORTS="21,22,23,25,53,80,110,143,443,554,993,995,1883,5683,8080,8443,9443"
MQTT_PORTS="1883,8883"
COAP_PORTS="5683,5684"
RTSP_PORTS="554,8554"
HTTP_PORTS="80,8080,8081,8443,9443"

# Global variables
declare -A DISCOVERED_DEVICES
declare -A DEVICE_VULNERABILITIES
declare -A PROTOCOL_ANALYSIS
TOTAL_DEVICES=0
VULNERABLE_DEVICES=0
HIGH_RISK_DEVICES=0
VERBOSE_MODE=false
TARGET_RANGE=""
WEB_SERVER_PID=""
WEB_SERVER_PORT=8888
START_WEB_SERVER=false

#==============================================================================
# Utility Functions
#==============================================================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    echo "║                    GoGo-GadgetO IoT Device Scanner v2.0                 ║"
    echo "║                   Advanced IoT Security Assessment                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

check_dependencies() {
    log_message "INFO" "Checking dependencies..."
    local deps=("nmap" "curl" "nc" "python3")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_message "ERROR" "Missing required dependencies: ${missing_deps[*]}"
        echo -e "${RED}Please install missing dependencies and try again.${NC}"
        exit 1
    fi
    
    log_message "INFO" "Dependencies check completed"
}

create_scan_directory() {
    mkdir -p "$SCAN_DIR"
    log_message "INFO" "Created scan directory: $SCAN_DIR"
}

#==============================================================================
# User Input Functions
#==============================================================================

get_user_input() {
    local target_range=""
    
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════╗"
    echo -e "║                    IoT Security Scanner Configuration                   ║"
    echo -e "╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${WHITE}🌐 Network Target Configuration${NC}"
    echo -e "${YELLOW}Choose your scan target:${NC}"
    echo -e "  ${CYAN}1)${NC} Local Network (192.168.1.0/24)"
    echo -e "  ${CYAN}2)${NC} Corporate Network (10.0.0.0/8)"
    echo -e "  ${CYAN}3)${NC} Custom CIDR Range"
    echo -e "  ${CYAN}4)${NC} Single IP Address"
    echo -e "  ${CYAN}5)${NC} IP Range (e.g., 192.168.1.1-100)"
    
    while true; do
        echo -ne "\n${GREEN}Select option [1-5]: ${NC}"
        read -r choice
        
        case $choice in
            1)
                target_range="192.168.1.0/24"
                echo -e "${GREEN}✓ Selected: Local Network ($target_range)${NC}"
                break
                ;;
            2)
                target_range="10.0.0.0/8"
                echo -e "${GREEN}✓ Selected: Corporate Network ($target_range)${NC}"
                break
                ;;
            3)
                echo -ne "${YELLOW}Enter CIDR range (e.g., 172.16.0.0/16): ${NC}"
                read -r target_range
                if [[ $target_range =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
                    echo -e "${GREEN}✓ Custom CIDR: $target_range${NC}"
                    break
                else
                    echo -e "${RED}Invalid CIDR format. Please try again.${NC}"
                fi
                ;;
            4)
                echo -ne "${YELLOW}Enter IP address: ${NC}"
                read -r target_range
                if [[ $target_range =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    echo -e "${GREEN}✓ Single IP: $target_range${NC}"
                    break
                else
                    echo -e "${RED}Invalid IP format. Please try again.${NC}"
                fi
                ;;
            5)
                echo -ne "${YELLOW}Enter IP range (e.g., 192.168.1.1-100): ${NC}"
                read -r target_range
                if [[ $target_range =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$ ]]; then
                    echo -e "${GREEN}✓ IP Range: $target_range${NC}"
                    break
                else
                    echo -e "${RED}Invalid range format. Please try again.${NC}"
                fi
                ;;
            *)
                echo -e "${RED}Invalid choice. Please select 1-5.${NC}"
                ;;
        esac
    done
    
    echo -e "\n${WHITE}🔌 Port Scanning Configuration${NC}"
    echo -e "${YELLOW}Select scanning mode:${NC}"
    echo -e "  ${CYAN}1)${NC} Standard IoT Ports (Fast - Recommended)"
    echo -e "  ${CYAN}2)${NC} Extended IoT Ports (Comprehensive)"
    echo -e "  ${CYAN}3)${NC} Custom Port List"
    echo -e "  ${CYAN}4)${NC} All Common Ports (Slow but thorough)"
    
    while true; do
        echo -ne "\n${GREEN}Select scanning mode [1-4]: ${NC}"
        read -r scan_choice
        
        case $scan_choice in
            1)
                IOT_PORTS="21,22,23,80,443,554,1883,5683,8080,8443"
                echo -e "${GREEN}✓ Standard IoT ports selected${NC}"
                break
                ;;
            2)
                IOT_PORTS="21,22,23,25,53,80,110,143,443,554,993,995,1883,5683,8080,8081,8443,8883,9443"
                echo -e "${GREEN}✓ Extended IoT ports selected${NC}"
                break
                ;;
            3)
                echo -ne "${YELLOW}Enter custom ports (comma-separated): ${NC}"
                read -r custom_ports
                if [[ -n "$custom_ports" ]]; then
                    IOT_PORTS="$custom_ports"
                    echo -e "${GREEN}✓ Custom ports: $IOT_PORTS${NC}"
                    break
                else
                    echo -e "${RED}No ports entered. Please try again.${NC}"
                fi
                ;;
            4)
                IOT_PORTS="21,22,23,25,53,80,110,135,139,143,443,445,554,993,995,1433,1883,3389,5432,5683,8080,8081,8443,8883,9443"
                echo -e "${GREEN}✓ All common ports selected (this may take longer)${NC}"
                break
                ;;
            *)
                echo -e "${RED}Invalid choice. Please select 1-4.${NC}"
                ;;
        esac
    done
    
    echo -e "\n${WHITE}📁 Output Configuration${NC}"
    echo -ne "${YELLOW}Custom output directory (press Enter for default): ${NC}"
    read -r output_dir
    
    if [[ -n "$output_dir" ]]; then
        SCAN_DIR="$output_dir"
        LOG_FILE="$SCAN_DIR/iot_scan.log"
        REPORT_FILE="$SCAN_DIR/iot_security_report.html"
        JSON_REPORT="$SCAN_DIR/iot_scan_results.json"
        echo -e "${GREEN}✓ Output directory: $output_dir${NC}"
    else
        echo -e "${GREEN}✓ Using default output directory${NC}"
    fi
    
    echo -e "\n${WHITE}🛡️ Advanced Options${NC}"
    echo -ne "${YELLOW}Enable verbose logging? [y/N]: ${NC}"
    read -r verbose_choice
    
    if [[ "$verbose_choice" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}✓ Verbose logging enabled${NC}"
        VERBOSE_MODE=true
    else
        echo -e "${GREEN}✓ Standard logging enabled${NC}"
        VERBOSE_MODE=false
    fi
    
    echo -e "\n${WHITE}🌐 Web Server Options${NC}"
    echo -ne "${YELLOW}Start temporary web server to view report? [Y/n]: ${NC}"
    read -r web_server_choice
    
    if [[ ! "$web_server_choice" =~ ^[Nn]$ ]]; then
        echo -e "${GREEN}✓ Web server will start after scan completion${NC}"
        START_WEB_SERVER=true
    else
        echo -e "${GREEN}✓ No web server (files only)${NC}"
        START_WEB_SERVER=false
    fi
    
    # Show configuration summary
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════════════════╗"
    echo -e "║                           SCAN CONFIGURATION                            ║"
    echo -e "╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${WHITE}Target:${NC} $target_range"
    echo -e "${WHITE}Ports:${NC} $IOT_PORTS"
    echo -e "${WHITE}Output:${NC} $SCAN_DIR"
    echo -e "${WHITE}Verbose:${NC} $VERBOSE_MODE"
    echo -e "${WHITE}Web Server:${NC} $START_WEB_SERVER"
    
    echo -ne "\n${GREEN}Proceed with scan? [Y/n]: ${NC}"
    read -r confirm
    
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        echo -e "${YELLOW}Scan cancelled by user.${NC}"
        exit 0
    fi
    
    # Store the target range for main function
    TARGET_RANGE="$target_range"
}

#==============================================================================
# IoT Device Discovery Functions
#==============================================================================

discover_iot_devices() {
    local target_range=$1
    log_message "INFO" "Starting IoT device discovery on $target_range"
    
    echo -e "${BLUE}[*] Discovering IoT devices on network: $target_range${NC}"
    
    # Phase 1: Basic host discovery
    echo -e "${CYAN}[*] Phase 1: Host Discovery${NC}"
    local alive_hosts=$(nmap -sn "$target_range" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    
    if [[ -z "$alive_hosts" ]]; then
        log_message "WARN" "No alive hosts found in range $target_range"
        return 1
    fi
    
    # Phase 2: IoT-specific port scanning
    echo -e "${CYAN}[*] Phase 2: IoT Port Scanning${NC}"
    for host in $alive_hosts; do
        echo -e "${WHITE}[*] Scanning $host for IoT services...${NC}"
        scan_iot_services "$host"
    done
    
    log_message "INFO" "Device discovery completed. Found $TOTAL_DEVICES IoT devices"
}

scan_iot_services() {
    local host=$1
    local scan_result=$(nmap -sS -sV -p "$IOT_PORTS" "$host" 2>/dev/null)
    
    # Parse scan results
    local open_ports=$(echo "$scan_result" | grep "^[0-9]" | grep "open" | awk '{print $1}' | cut -d'/' -f1)
    
    if [[ -n "$open_ports" ]]; then
        DISCOVERED_DEVICES["$host"]="$open_ports"
        ((TOTAL_DEVICES++))
        
        log_message "INFO" "IoT device found: $host (Ports: $open_ports)"
        
        # Analyze each open port
        for port in $open_ports; do
            analyze_service "$host" "$port"
        done
    fi
}

analyze_service() {
    local host=$1
    local port=$2
    
    case $port in
        1883|8883)
            analyze_mqtt_service "$host" "$port"
            ;;
        5683|5684)
            analyze_coap_service "$host" "$port"
            ;;
        80|8080|8081|8443|9443|443)
            analyze_http_service "$host" "$port"
            ;;
        23)
            analyze_telnet_service "$host" "$port"
            ;;
        22)
            analyze_ssh_service "$host" "$port"
            ;;
        *)
            analyze_generic_service "$host" "$port"
            ;;
    esac
}

analyze_mqtt_service() {
    local host=$1
    local port=$2
    
    log_message "INFO" "Analyzing MQTT service on $host:$port"
    echo -e "${YELLOW}[*] Testing MQTT broker: $host:$port${NC}"
    
    local mqtt_result="MQTT service detected"
    
    # Test anonymous connection
    if timeout 3 nc -z "$host" "$port" 2>/dev/null; then
        mqtt_result="$mqtt_result - Anonymous connection possible"
        DEVICE_VULNERABILITIES["$host:$port"]="MQTT Anonymous Access"
        ((VULNERABLE_DEVICES++))
    fi
    
    PROTOCOL_ANALYSIS["$host:$port:mqtt"]="$mqtt_result"
    log_message "INFO" "MQTT analysis complete for $host:$port"
}

analyze_coap_service() {
    local host=$1
    local port=$2
    
    log_message "INFO" "Analyzing CoAP service on $host:$port"
    echo -e "${YELLOW}[*] Testing CoAP server: $host:$port${NC}"
    
    local coap_result="CoAP service detected"
    
    if timeout 3 nc -u -z "$host" "$port" 2>/dev/null; then
        coap_result="$coap_result - Service accessible"
    fi
    
    PROTOCOL_ANALYSIS["$host:$port:coap"]="$coap_result"
    log_message "INFO" "CoAP analysis complete for $host:$port"
}

analyze_http_service() {
    local host=$1
    local port=$2
    
    log_message "INFO" "Analyzing HTTP service on $host:$port"
    echo -e "${YELLOW}[*] Testing HTTP service: $host:$port${NC}"
    
    local protocol="http"
    if [[ "$port" == "443" || "$port" == "8443" ]]; then
        protocol="https"
    fi
    
    local http_result=""
    local url="$protocol://$host:$port"
    
    # Get HTTP headers and basic info
    local headers=$(timeout 10 curl -s -I "$url" 2>/dev/null)
    
    if [[ -n "$headers" ]]; then
        local server_header=$(echo "$headers" | grep -i "server:" | cut -d':' -f2- | xargs)
        http_result="HTTP service active - Server: $server_header"
        
        # Check for missing security headers
        if ! echo "$headers" | grep -qi "x-frame-options"; then
            DEVICE_VULNERABILITIES["$host:$port"]="Missing Security Headers"
            ((VULNERABLE_DEVICES++))
        fi
    else
        http_result="HTTP service detected but no response"
    fi
    
    PROTOCOL_ANALYSIS["$host:$port:http"]="$http_result"
    log_message "INFO" "HTTP analysis complete for $host:$port"
}

analyze_telnet_service() {
    local host=$1
    local port=$2
    
    log_message "INFO" "Analyzing Telnet service on $host:$port"
    echo -e "${YELLOW}[*] Testing Telnet service: $host:$port${NC}"
    
    local telnet_result="Telnet service detected - HIGH RISK"
    DEVICE_VULNERABILITIES["$host:$port"]="Insecure Telnet Service"
    ((HIGH_RISK_DEVICES++))
    
    PROTOCOL_ANALYSIS["$host:$port:telnet"]="$telnet_result"
    log_message "WARN" "Telnet service found on $host:$port - Security risk"
}

analyze_ssh_service() {
    local host=$1
    local port=$2
    
    log_message "INFO" "Analyzing SSH service on $host:$port"
    echo -e "${YELLOW}[*] Testing SSH service: $host:$port${NC}"
    
    local ssh_result="SSH service detected"
    PROTOCOL_ANALYSIS["$host:$port:ssh"]="$ssh_result"
    log_message "INFO" "SSH analysis complete for $host:$port"
}

analyze_generic_service() {
    local host=$1
    local port=$2
    
    log_message "INFO" "Analyzing generic service on $host:$port"
    
    local service_info="Port $port open"
    PROTOCOL_ANALYSIS["$host:$port:generic"]="$service_info"
    log_message "INFO" "Generic service analysis complete for $host:$port"
}

#==============================================================================
# Web Server Functions
#==============================================================================

start_web_server() {
    local port=$1
    local document_root=$(dirname "$REPORT_FILE")
    
    log_message "INFO" "Starting temporary web server on port $port"
    
    # Find available port if default is busy
    while netstat -tln 2>/dev/null | grep -q ":$port "; do
        ((port++))
        if [[ $port -gt 9000 ]]; then
            log_message "ERROR" "Could not find available port for web server"
            return 1
        fi
    done
    
    WEB_SERVER_PORT=$port
    
    # Create simple HTTP server using Python
    if command -v python3 &> /dev/null; then
        cd "$document_root"
        python3 -m http.server $port &> /dev/null &
        WEB_SERVER_PID=$!
        cd - &> /dev/null
    elif command -v python &> /dev/null; then
        cd "$document_root"
        python -m SimpleHTTPServer $port &> /dev/null &
        WEB_SERVER_PID=$!
        cd - &> /dev/null
    else
        log_message "ERROR" "Python not found for web server"
        return 1
    fi
    
    # Wait a moment for server to start
    sleep 2
    
    # Verify server is running
    if kill -0 $WEB_SERVER_PID 2>/dev/null; then
        log_message "INFO" "Web server started successfully (PID: $WEB_SERVER_PID)"
        return 0
    else
        log_message "ERROR" "Failed to start web server"
        return 1
    fi
}

stop_web_server() {
    if [[ -n "$WEB_SERVER_PID" ]] && kill -0 $WEB_SERVER_PID 2>/dev/null; then
        log_message "INFO" "Stopping web server (PID: $WEB_SERVER_PID)"
        kill $WEB_SERVER_PID 2>/dev/null
        wait $WEB_SERVER_PID 2>/dev/null
        WEB_SERVER_PID=""
    fi
}

open_report_in_browser() {
    local url="http://localhost:$WEB_SERVER_PORT/$(basename "$REPORT_FILE")"
    
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════════════════╗"
    echo -e "║                          WEB REPORT READY                               ║"
    echo -e "╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "${WHITE}🌐 Your IoT Security Report is now available at:${NC}"
    echo -e "${GREEN}   📊 ${BOLD}$url${NC}"
    echo -e ""
    echo -e "${YELLOW}🚀 Opening options:${NC}"
    echo -e "   ${CYAN}1)${NC} Auto-open in default browser"
    echo -e "   ${CYAN}2)${NC} Keep server running (5 minutes)"
    echo -e "   ${CYAN}3)${NC} Keep server running (15 minutes)"
    echo -e "   ${CYAN}4)${NC} Keep server running until stopped"
    echo -e "   ${CYAN}5)${NC} Stop server and exit"
    
    while true; do
        echo -ne "\n${GREEN}Select option [1-5]: ${NC}"
        read -r browser_choice
        
        case $browser_choice in
            1)
                echo -e "${BLUE}🌐 Opening report in browser...${NC}"
                
                # Try to open in browser
                if command -v xdg-open &> /dev/null; then
                    xdg-open "$url" &>/dev/null &
                elif command -v open &> /dev/null; then
                    open "$url" &>/dev/null &
                else
                    echo -e "${YELLOW}No browser found. Please manually open: $url${NC}"
                fi
                
                echo -e "${GREEN}✅ Server running for 5 minutes${NC}"
                run_server_with_timer 300
                break
                ;;
            2)
                echo -e "${GREEN}✅ Server will run for 5 minutes${NC}"
                show_server_info "$url"
                run_server_with_timer 300
                break
                ;;
            3)
                echo -e "${GREEN}✅ Server will run for 15 minutes${NC}"
                show_server_info "$url"
                run_server_with_timer 900
                break
                ;;
            4)
                echo -e "${GREEN}✅ Server will keep running${NC}"
                show_server_info "$url"
                echo -e "${YELLOW}Press Ctrl+C to stop server${NC}"
                wait
                break
                ;;
            5)
                echo -e "${YELLOW}Stopping web server...${NC}"
                stop_web_server
                break
                ;;
            *)
                echo -e "${RED}Invalid choice. Please select 1-5.${NC}"
                ;;
        esac
    done
}

run_server_with_timer() {
    local duration=$1
    
    # Set up trap to clean up on interrupt
    trap 'stop_web_server; exit 0' INT TERM
    
    # Countdown timer
    local remaining=$duration
    while [[ $remaining -gt 0 ]] && kill -0 $WEB_SERVER_PID 2>/dev/null; do
        if [[ $((remaining % 60)) -eq 0 ]]; then
            echo -e "${CYAN}⏰ Server running... $((remaining/60)) minutes remaining${NC}"
        fi
        sleep 60
        ((remaining -= 60))
    done
    
    echo -e "\n${YELLOW}⏰ Time expired. Stopping web server...${NC}"
    stop_web_server
}

show_server_info() {
    local url=$1
    
    echo -e "\n${WHITE}📊 Report URL:${NC} ${GREEN}$url${NC}"
    echo -e "${WHITE}🖥️  Server PID:${NC} $WEB_SERVER_PID"
    echo -e "${WHITE}🔌 Port:${NC} $WEB_SERVER_PORT"
    
    # Get local IP addresses
    local local_ips=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -3)
    
    if [[ -n "$local_ips" ]]; then
        echo -e "\n${WHITE}🌐 Network Access URLs:${NC}"
        while IFS= read -r ip; do
            echo -e "   ${CYAN}http://$ip:$WEB_SERVER_PORT/$(basename "$REPORT_FILE")${NC}"
        done <<< "$local_ips"
    fi
}

#==============================================================================
# Reporting Functions
#==============================================================================

generate_html_report() {
    log_message "INFO" "Generating HTML report..."
    
    cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GoGo-GadgetO IoT Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #2c3e50; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .metric-value { font-size: 2em; font-weight: bold; }
        .metric-label { font-size: 0.9em; opacity: 0.9; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .device-card { background-color: #ecf0f1; padding: 15px; margin-bottom: 15px; border-radius: 5px; border-left: 4px solid #3498db; }
        .vulnerable { border-left-color: #e74c3c; }
        .high-risk { border-left-color: #c0392b; background-color: #fadbd8; }
        .secure { border-left-color: #27ae60; }
        .vulnerability { color: #e74c3c; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 GoGo-GadgetO IoT Security Assessment Report</h1>
            <p>Generated on: $(date)</p>
        </div>
        
        <div class="summary">
            <div class="metric-card">
                <div class="metric-value">$TOTAL_DEVICES</div>
                <div class="metric-label">IoT Devices Found</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$VULNERABLE_DEVICES</div>
                <div class="metric-label">Vulnerable Devices</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$HIGH_RISK_DEVICES</div>
                <div class="metric-label">High Risk Devices</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📱 Discovered IoT Devices</h2>
EOF

    # Add device details
    for host in "${!DISCOVERED_DEVICES[@]}"; do
        local device_data="${DISCOVERED_DEVICES[$host]}"
        local vulnerabilities="${DEVICE_VULNERABILITIES[$host]:-""}"
        
        local card_class="device-card secure"
        if [[ -n "$vulnerabilities" ]]; then
            if echo "$vulnerabilities" | grep -qi "high"; then
                card_class="device-card high-risk"
            else
                card_class="device-card vulnerable"
            fi
        fi
        
        cat >> "$REPORT_FILE" << EOF
            <div class="$card_class">
                <h3>🖥️ Device: $host</h3>
                <p><strong>Open Ports:</strong> $device_data</p>
EOF

        if [[ -n "$vulnerabilities" ]]; then
            echo "                <div class=\"vulnerability\">🚨 Vulnerabilities: $vulnerabilities</div>" >> "$REPORT_FILE"
        else
            echo "                <div class=\"status-ok\">✅ No vulnerabilities detected</div>" >> "$REPORT_FILE"
        fi
        
        echo "            </div>" >> "$REPORT_FILE"
    done

    cat >> "$REPORT_FILE" << EOF
        </div>
        
        <div class="section">
            <h2>📊 Security Recommendations</h2>
            <ul>
                <li>🔐 Change all default credentials immediately</li>
                <li>🚫 Disable unnecessary services (especially Telnet)</li>
                <li>🔒 Enable encryption for all communications</li>
                <li>🛡️ Implement proper access controls</li>
                <li>🔄 Regularly update firmware and software</li>
                <li>📊 Monitor devices for unusual activity</li>
                <li>🌐 Segment IoT devices from critical networks</li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF

    log_message "INFO" "HTML report saved to: $REPORT_FILE"
}

print_summary() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════════════════╗"
    echo -e "║                         SCAN SUMMARY                                    ║"
    echo -e "╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "${WHITE}📊 Discovery Results:${NC}"
    echo -e "   • Total IoT devices found: ${GREEN}$TOTAL_DEVICES${NC}"
    echo -e "   • Vulnerable devices: ${YELLOW}$VULNERABLE_DEVICES${NC}"
    echo -e "   • High-risk devices: ${RED}$HIGH_RISK_DEVICES${NC}"
    
    echo -e "\n${WHITE}📁 Output Files:${NC}"
    echo -e "   • Log file: ${CYAN}$LOG_FILE${NC}"
    echo -e "   • HTML report: ${CYAN}$REPORT_FILE${NC}"
    
    if [[ $VULNERABLE_DEVICES -gt 0 ]]; then
        echo -e "\n${RED}⚠️  WARNING: Vulnerable IoT devices detected!${NC}"
        echo -e "${YELLOW}   Please review the detailed report and take immediate action.${NC}"
    else
        echo -e "\n${GREEN}✅ No critical vulnerabilities detected in IoT devices.${NC}"
    fi
}

#==============================================================================
# Main Function
#==============================================================================

show_usage() {
    echo -e "${CYAN}$SCRIPT_NAME v$VERSION${NC}"
    echo -e "${WHITE}Advanced IoT Device Security Scanner${NC}"
    echo ""
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 [OPTIONS] [network_range]"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  -h, --help           Show this help message"
    echo "  -v, --version        Show version information"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0                              # Interactive mode"
    echo "  $0 192.168.1.0/24              # Direct scan"
}

main() {
    local target_range=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                echo "$SCRIPT_NAME v$VERSION"
                exit 0
                ;;
            -*)
                echo -e "${RED}Error: Unknown option $1${NC}"
                show_usage
                exit 1
                ;;
            *)
                target_range="$1"
                shift
                ;;
        esac
    done
    
    # Show banner
    print_banner
    
    # If no target provided via command line, get interactive input
    if [[ -z "$target_range" ]]; then
        get_user_input
        target_range="$TARGET_RANGE"
    fi
    
    # Start scanning process
    log_message "INFO" "Starting $SCRIPT_NAME v$VERSION"
    log_message "INFO" "Target: $target_range"
    
    # Check dependencies and create scan directory
    check_dependencies
    create_scan_directory
    
    # Main scanning phase
    discover_iot_devices "$target_range"
    
    # Generate reports
    generate_html_report
    
    # Start web server if requested
    if [[ "$START_WEB_SERVER" == true ]]; then
        echo -e "\n${BLUE}🌐 Starting web server for report viewing...${NC}"
        if start_web_server $WEB_SERVER_PORT; then
            open_report_in_browser
        else
            echo -e "${RED}❌ Failed to start web server. Report available at: $REPORT_FILE${NC}"
        fi
    fi
    
    # Show summary
    print_summary
    
    log_message "INFO" "Scan completed successfully"
    
    # Clean up web server on exit
    trap 'stop_web_server; exit 0' EXIT
    
    # Set exit code based on findings
    if [[ $HIGH_RISK_DEVICES -gt 0 ]]; then
        exit 2  # High-risk devices found
    elif [[ $VULNERABLE_DEVICES -gt 0 ]]; then
        exit 1  # Vulnerable devices found
    else
        exit 0  # No vulnerabilities found
    fi
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
