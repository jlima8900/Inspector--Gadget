#!/bin/bash

# ==============================
# 📊 GoGoGadget Analytics - Security Intelligence & Reporting
# ==============================

# Define colors for better output
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
PURPLE="\033[1;35m"
NC="\033[0m"

# Global configuration
SAVE_REPORTS=false
SAVE_HISTORY=false

# Header Display
echo -e "${BLUE}"
echo "┌────────────────────────────────────────────────────────┐"
echo "│  📊 GoGoGadget Analytics - Security Intelligence      │"
echo "│  🎯 Advanced Risk Scoring & Trend Analysis            │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# ==============================
# ⚙️ User Configuration
# ==============================
configure_options() {
    echo -e "${YELLOW}📋 Analytics Configuration:${NC}"
    echo "1) Display results only (no files created)"
    echo "2) Save detailed reports to files"
    echo "3) Save reports + enable trend tracking"
    echo -n "Select option (1/2/3): "
    read -r choice
    
    case $choice in
        1)
            SAVE_REPORTS=false
            SAVE_HISTORY=false
            echo -e "${GREEN}✅ Analytics mode: Display only${NC}"
            ;;
        2)
            SAVE_REPORTS=true
            SAVE_HISTORY=false
            echo -e "${GREEN}✅ Analytics mode: Reports saved to files${NC}"
            ;;
        3)
            SAVE_REPORTS=true
            SAVE_HISTORY=true
            echo -e "${GREEN}✅ Analytics mode: Reports + trend tracking enabled${NC}"
            ;;
        *)
            echo -e "${YELLOW}⚠️ Invalid choice, defaulting to display only${NC}"
            SAVE_REPORTS=false
            SAVE_HISTORY=false
            ;;
    esac
    echo ""
}

# ==============================
# 🗂️ Data Validation & Sample Creation
# ==============================
ensure_data_availability() {
    local missing_files=()
    
    # Check for required data files
    [[ ! -f "privileged_containers.csv" ]] && missing_files+=("privileged_containers.csv")
    [[ ! -f "firewalld_rules.csv" ]] && missing_files+=("firewalld_rules.csv")
    [[ ! -f "network_analysis.csv" ]] && missing_files+=("network_analysis.csv")
    [[ ! -f "fail2ban_blocked_ips.csv" ]] && missing_files+=("fail2ban_blocked_ips.csv")
    
    if [[ ${#missing_files[@]} -gt 0 ]]; then
        echo -e "${YELLOW}📊 Creating sample data for analytics demonstration...${NC}"
        
        # Create sample privileged containers data
        [[ ! -f "privileged_containers.csv" ]] && {
            cat > "privileged_containers.csv" << EOF
Container Name,Privileged Mode
web-server,No
database,No
cache-redis,No
monitoring,No
EOF
        }
        
        # Create sample firewall rules
        [[ ! -f "firewalld_rules.csv" ]] && {
            cat > "firewalld_rules.csv" << EOF
Port,Zone,Action
22,public,Allow
80,public,Allow
443,public,Allow
8080,internal,Allow
3306,internal,Allow
EOF
        }
        
        # Create sample network analysis
        [[ ! -f "network_analysis.csv" ]] && {
            cat > "network_analysis.csv" << EOF
Network Name,Externally Accessible,Affected Containers
bridge,No,3
host,Yes,1
internal,No,2
EOF
        }
        
        # Create sample fail2ban data
        [[ ! -f "fail2ban_blocked_ips.csv" ]] && {
            cat > "fail2ban_blocked_ips.csv" << EOF
IP,Jail
192.168.1.100,sshd
10.0.0.50,nginx-limit-req
192.168.1.200,sshd
EOF
        }
        
        echo -e "${GREEN}✅ Sample data created for analytics${NC}\n"
    fi
}

# ==============================
# 🚨 Advanced Security Risk Scoring Algorithm
# ==============================
calculate_security_analytics() {
    echo -e "${PURPLE}🔬 Running Advanced Security Analytics...${NC}"
    
    # Collect security metrics
    local PRIVILEGED_CONTAINERS=$(grep -c ",Yes$" privileged_containers.csv 2>/dev/null || echo "0")
    local TOTAL_CONTAINERS=$(awk -F',' 'NR>1 {count++} END {print count+0}' privileged_containers.csv 2>/dev/null)
    local HIGH_RISK_PORTS=$(grep -E "9000|23|3389|6666|1234|2222" firewalld_rules.csv 2>/dev/null | wc -l)
    local MEDIUM_RISK_PORTS=$(grep -E "25|5900|8080|3306|5432|8888" firewalld_rules.csv 2>/dev/null | wc -l)
    local TOTAL_PORTS=$(awk -F',' 'NR>1 {count++} END {print count+0}' firewalld_rules.csv 2>/dev/null)
    local EXTERNAL_NETWORKS=$(awk -F',' '$2 ~ /Yes/ {count++} END {print count+0}' network_analysis.csv 2>/dev/null)
    local TOTAL_NETWORKS=$(awk -F',' 'NR>1 {count++} END {print count+0}' network_analysis.csv 2>/dev/null)
    local BLOCKED_THREATS=$(awk -F',' 'NR>1 {count++} END {print count+0}' fail2ban_blocked_ips.csv 2>/dev/null)
    
    # Ensure no empty values
    PRIVILEGED_CONTAINERS=${PRIVILEGED_CONTAINERS:-0}
    TOTAL_CONTAINERS=${TOTAL_CONTAINERS:-0}
    HIGH_RISK_PORTS=${HIGH_RISK_PORTS:-0}
    MEDIUM_RISK_PORTS=${MEDIUM_RISK_PORTS:-0}
    TOTAL_PORTS=${TOTAL_PORTS:-0}
    EXTERNAL_NETWORKS=${EXTERNAL_NETWORKS:-0}
    TOTAL_NETWORKS=${TOTAL_NETWORKS:-0}
    BLOCKED_THREATS=${BLOCKED_THREATS:-0}
    
    # Advanced risk calculations
    local CONTAINER_RISK=0
    [[ $TOTAL_CONTAINERS -gt 0 ]] && CONTAINER_RISK=$(((PRIVILEGED_CONTAINERS * 100) / TOTAL_CONTAINERS))
    
    local PORT_RISK=$((HIGH_RISK_PORTS * 25 + MEDIUM_RISK_PORTS * 10))
    
    local NETWORK_RISK=0
    [[ $TOTAL_NETWORKS -gt 0 ]] && NETWORK_RISK=$(((EXTERNAL_NETWORKS * 100) / TOTAL_NETWORKS))
    
    local VOLUME_PENALTY=0
    [[ $TOTAL_PORTS -gt 15 ]] && VOLUME_PENALTY=$(((TOTAL_PORTS - 15) * 2))
    
    # Security bonuses
    local THREAT_DETECTION_BONUS=0
    [[ $BLOCKED_THREATS -gt 0 ]] && THREAT_DETECTION_BONUS=15
    
    local CONTAINER_SECURITY_BONUS=0
    [[ $PRIVILEGED_CONTAINERS -eq 0 && $TOTAL_CONTAINERS -gt 0 ]] && CONTAINER_SECURITY_BONUS=10
    
    # Calculate final risk score
    local TOTAL_RISK=$((CONTAINER_RISK + PORT_RISK + NETWORK_RISK + VOLUME_PENALTY - THREAT_DETECTION_BONUS - CONTAINER_SECURITY_BONUS))
    
    # Bounds checking
    [[ $TOTAL_RISK -lt 0 ]] && TOTAL_RISK=0
    [[ $TOTAL_RISK -gt 100 ]] && TOTAL_RISK=100
    
    # Security score (inverse of risk)
    local SECURITY_SCORE=$((100 - TOTAL_RISK))
    
    # Display comprehensive analytics
    echo -e "\n${CYAN}📊 Security Analytics Dashboard${NC}"
    echo -e "${CYAN}===============================${NC}"
    
    echo -e "\n${YELLOW}🔍 Risk Factor Analysis:${NC}"
    echo -e "├─ 🐳 Container Security: $PRIVILEGED_CONTAINERS/$TOTAL_CONTAINERS privileged (Risk: $CONTAINER_RISK%)"
    echo -e "├─ 🔥 Port Security: $HIGH_RISK_PORTS high-risk, $MEDIUM_RISK_PORTS medium-risk (Risk: +$PORT_RISK)"
    echo -e "├─ 🌍 Network Exposure: $EXTERNAL_NETWORKS/$TOTAL_NETWORKS external (Risk: $NETWORK_RISK%)"
    echo -e "├─ 📊 Volume Penalty: $TOTAL_PORTS total ports (Penalty: +$VOLUME_PENALTY)"
    echo -e "├─ 🛡️ Threat Detection: $BLOCKED_THREATS threats blocked (Bonus: -$THREAT_DETECTION_BONUS)"
    echo -e "└─ 🔒 Container Hardening: (Bonus: -$CONTAINER_SECURITY_BONUS)"
    
    # Security score with recommendations
    echo -e "\n${PURPLE}🎯 Security Assessment:${NC}"
    if [[ $SECURITY_SCORE -ge 85 ]]; then
        echo -e "${GREEN}🟢 Security Score: $SECURITY_SCORE% - EXCELLENT${NC}"
        echo -e "${GREEN}✅ Outstanding security posture! Maintain current practices.${NC}"
    elif [[ $SECURITY_SCORE -ge 70 ]]; then
        echo -e "${GREEN}🟡 Security Score: $SECURITY_SCORE% - GOOD${NC}"
        echo -e "${YELLOW}💡 Strong foundation. Consider reducing high-risk port exposure.${NC}"
    elif [[ $SECURITY_SCORE -ge 50 ]]; then
        echo -e "${YELLOW}🟠 Security Score: $SECURITY_SCORE% - MODERATE${NC}"
        echo -e "${YELLOW}⚠️ Multiple areas need attention. Focus on container and network security.${NC}"
    else
        echo -e "${RED}🔴 Security Score: $SECURITY_SCORE% - CRITICAL${NC}"
        echo -e "${RED}🚨 Immediate security remediation required!${NC}"
    fi
    
    # Generate specific recommendations
    generate_security_recommendations "$PRIVILEGED_CONTAINERS" "$HIGH_RISK_PORTS" "$MEDIUM_RISK_PORTS" "$EXTERNAL_NETWORKS" "$TOTAL_NETWORKS" "$BLOCKED_THREATS" "$TOTAL_PORTS"
    
    # Generate reports if enabled
    if [[ "$SAVE_REPORTS" == "true" ]]; then
        generate_analytics_report "$SECURITY_SCORE" "$TOTAL_RISK" "$PRIVILEGED_CONTAINERS" "$HIGH_RISK_PORTS" "$EXTERNAL_NETWORKS" "$BLOCKED_THREATS"
    fi
    
    # Save history if enabled
    if [[ "$SAVE_HISTORY" == "true" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'),$SECURITY_SCORE,$TOTAL_RISK,$PRIVILEGED_CONTAINERS,$HIGH_RISK_PORTS,$EXTERNAL_NETWORKS" >> security_analytics_history.csv
        analyze_trends
    fi
}

# ==============================
# 📊 Security Metrics Breakdown
# ==============================
display_detailed_metrics() {
    echo -e "\n${BLUE}📈 Detailed Security Metrics${NC}"
    echo -e "${BLUE}=============================${NC}"
    
    # Container security breakdown
    if [[ -f "privileged_containers.csv" ]]; then
        echo -e "\n${YELLOW}🐳 Container Security Analysis:${NC}"
        local PRIV_COUNT=$(grep -c ",Yes$" privileged_containers.csv 2>/dev/null || echo "0")
        local TOTAL_COUNT=$(awk -F',' 'NR>1 {count++} END {print count+0}' privileged_containers.csv 2>/dev/null)
        
        if [[ $PRIV_COUNT -eq 0 ]]; then
            echo -e "${GREEN}✅ All $TOTAL_COUNT containers are running with restricted privileges${NC}"
        else
            echo -e "${RED}⚠️ $PRIV_COUNT out of $TOTAL_COUNT containers have elevated privileges${NC}"
            echo -e "${CYAN}Container Details:${NC}"
            column -t -s ',' privileged_containers.csv 2>/dev/null | head -10
        fi
    fi
    
    # Network security analysis
    if [[ -f "network_analysis.csv" ]]; then
        echo -e "\n${CYAN}🌍 Network Security Analysis:${NC}"
        column -t -s ',' network_analysis.csv 2>/dev/null
    fi
    
    # Threat intelligence summary
    if [[ -f "fail2ban_blocked_ips.csv" ]]; then
        echo -e "\n${GREEN}🛡️ Threat Intelligence:${NC}"
        local THREAT_COUNT=$(awk -F',' 'NR>1 {count++} END {print count+0}' fail2ban_blocked_ips.csv 2>/dev/null)
        echo -e "Active threat blocking: $THREAT_COUNT malicious IPs currently blocked"
        
        # Show threat breakdown by service
        echo -e "${CYAN}Threat Breakdown by Service:${NC}"
        awk -F',' 'NR>1 {services[$2]++} END {for (service in services) printf "  %-15s: %d threats\n", service, services[service]}' fail2ban_blocked_ips.csv 2>/dev/null
    fi
}

# ==============================
# 💡 Security Recommendations Engine
# ==============================
generate_security_recommendations() {
    local priv_containers=$1
    local high_risk_ports=$2
    local medium_risk_ports=$3
    local external_networks=$4
    local total_networks=$5
    local blocked_threats=$6
    local total_ports=$7
    
    echo -e "\n${CYAN}💡 Actionable Security Recommendations:${NC}"
    echo -e "${CYAN}=======================================${NC}"
    
    local priority=1
    
    # Critical: Network Exposure
    if [[ $external_networks -gt 0 && $total_networks -gt 0 ]]; then
        local exposure_rate=$(((external_networks * 100) / total_networks))
        if [[ $exposure_rate -ge 80 ]]; then
            echo -e "\n${RED}🚨 CRITICAL Priority $priority: Network Segmentation${NC}"
            echo -e "${YELLOW}Issue:${NC} $external_networks/$total_networks networks ($exposure_rate%) are externally accessible"
            echo -e "${GREEN}Actions:${NC}"
            echo -e "  🔧 Review network necessity: ${BLUE}docker network inspect <network_name>${NC}"
            echo -e "  🔒 Create internal networks: ${BLUE}docker network create --internal <internal_net>${NC}"
            echo -e "  🛡️ Use reverse proxy: ${BLUE}nginx/traefik for external access control${NC}"
            echo -e "  📋 Audit command: ${BLUE}docker network ls && docker ps --format 'table {{.Names}}\\t{{.Networks}}'${NC}"
            ((priority++))
        fi
    fi
    
    # High: Privileged Containers
    if [[ $priv_containers -gt 0 ]]; then
        echo -e "\n${RED}⚠️ HIGH Priority $priority: Privileged Container Security${NC}"
        echo -e "${YELLOW}Issue:${NC} $priv_containers containers running with elevated privileges"
        echo -e "${GREEN}Actions:${NC}"
        echo -e "  🔍 Identify privileged containers: ${BLUE}docker ps --filter 'label=privileged=true'${NC}"
        echo -e "  🔍 Or check manually: ${BLUE}docker inspect <container> | grep -i privileged${NC}"
        echo -e "  🔒 Remove --privileged flag if possible"
        echo -e "  🎯 Use specific capabilities: ${BLUE}--cap-add=SYS_TIME${NC} instead of --privileged"
        echo -e "  📋 Security scan: ${BLUE}docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image <image>${NC}"
        ((priority++))
    fi
    
    # High: High-Risk Ports
    if [[ $high_risk_ports -gt 0 ]]; then
        echo -e "\n${RED}⚠️ HIGH Priority $priority: High-Risk Port Exposure${NC}"
        echo -e "${YELLOW}Issue:${NC} $high_risk_ports high-risk ports detected (Telnet, RDP, non-standard SSH, etc.)"
        echo -e "${GREEN}Actions:${NC}"
        echo -e "  🔍 Review exposed ports: ${BLUE}netstat -tulpn | grep LISTEN${NC}"
        echo -e "  🔒 Close unnecessary ports: ${BLUE}sudo firewall-cmd --remove-port=<port>/tcp --permanent${NC}"
        echo -e "  🛡️ Use port knocking or VPN for admin access"
        echo -e "  🔑 Change default SSH port: Edit ${BLUE}/etc/ssh/sshd_config${NC}"
        echo -e "  📋 Firewall audit: ${BLUE}sudo firewall-cmd --list-all${NC}"
        ((priority++))
    fi
    
    # Medium: Threat Detection
    if [[ $blocked_threats -eq 0 ]]; then
        echo -e "\n${YELLOW}⚡ MEDIUM Priority $priority: Enable Threat Detection${NC}"
        echo -e "${YELLOW}Issue:${NC} No active threat blocking detected - system may be vulnerable"
        echo -e "${GREEN}Actions:${NC}"
        echo -e "  🛡️ Install/enable fail2ban: ${BLUE}sudo systemctl enable --now fail2ban${NC}"
        echo -e "  ⚙️ Configure SSH protection: Edit ${BLUE}/etc/fail2ban/jail.local${NC}"
        echo -e "  📊 Monitor logs: ${BLUE}sudo fail2ban-client status${NC}"
        echo -e "  🔍 Check fail2ban jails: ${BLUE}sudo fail2ban-client status sshd${NC}"
        ((priority++))
    fi
    
    # Medium: Port Volume
    if [[ $total_ports -gt 20 ]]; then
        echo -e "\n${YELLOW}⚡ MEDIUM Priority $priority: Port Attack Surface${NC}"
        echo -e "${YELLOW}Issue:${NC} $total_ports total ports open - large attack surface"
        echo -e "${GREEN}Actions:${NC}"
        echo -e "  🔍 Audit all services: ${BLUE}ss -tulpn${NC}"
        echo -e "  🗑️ Disable unused services: ${BLUE}sudo systemctl disable <service>${NC}"
        echo -e "  🔒 Bind to localhost: Change ${BLUE}0.0.0.0${NC} to ${BLUE}127.0.0.1${NC} in configs"
        echo -e "  📋 Service review: ${BLUE}sudo systemctl list-unit-files --type=service --state=enabled${NC}"
        ((priority++))
    fi
    
    # Medium: Medium-Risk Ports
    if [[ $medium_risk_ports -gt 0 ]]; then
        echo -e "\n${YELLOW}⚡ MEDIUM Priority $priority: Medium-Risk Services${NC}"
        echo -e "${YELLOW}Issue:${NC} $medium_risk_ports medium-risk ports (SMTP, VNC, HTTP-alt, databases)"
        echo -e "${GREEN}Actions:${NC}"
        echo -e "  🔒 Secure database access: Use firewall rules for DB ports"
        echo -e "  🌍 VPN for remote access: Replace VNC with secure alternatives"
        echo -e "  🔑 Authentication: Enable strong auth for all admin services"
        echo -e "  📋 Service hardening: Follow CIS benchmarks for each service"
        ((priority++))
    fi
    
    # Positive Reinforcement
    echo -e "\n${GREEN}✅ Security Strengths Identified:${NC}"
    local strengths=0
    
    [[ $priv_containers -eq 0 ]] && {
        echo -e "  🔒 No privileged containers detected"
        ((strengths++))
    }
    
    [[ $high_risk_ports -eq 0 ]] && {
        echo -e "  🛡️ No high-risk ports exposed"
        ((strengths++))
    }
    
    [[ $blocked_threats -gt 0 ]] && {
        echo -e "  🚨 Active threat detection ($blocked_threats threats blocked)"
        ((strengths++))
    }
    
    [[ $total_ports -le 10 ]] && {
        echo -e "  📊 Minimal attack surface ($total_ports ports)"
        ((strengths++))
    }
    
    [[ $strengths -eq 0 ]] && {
        echo -e "  💪 Focus on implementing the recommendations above to build security strengths"
    }
    
    # Implementation Priority Guide
    echo -e "\n${BLUE}🗓️ Implementation Timeline:${NC}"
    echo -e "  📅 Week 1: Address CRITICAL network exposure issues"
    echo -e "  📅 Week 2: Secure privileged containers and high-risk ports"  
    echo -e "  📅 Week 3: Implement threat detection and monitoring"
    echo -e "  📅 Week 4: Fine-tune services and reduce attack surface"
    
    # Quick Wins
    echo -e "\n${PURPLE}⚡ Quick Security Wins (30 minutes):${NC}"
    echo -e "  🔧 ${BLUE}sudo systemctl enable --now fail2ban${NC}"
    echo -e "  🔧 ${BLUE}sudo firewall-cmd --set-default-zone=drop${NC}"
    echo -e "  🔧 ${BLUE}docker network create --internal secure-net${NC}"
    echo -e "  🔧 Update system: ${BLUE}sudo dnf update -y${NC} (or appropriate package manager)"
}
generate_analytics_report() {
    local score=$1
    local risk=$2
    local priv_containers=$3
    local high_risk_ports=$4
    local external_networks=$5
    local blocked_threats=$6
    
    local report_file="security_analytics_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
📊 GOGOGADGET SECURITY ANALYTICS REPORT
======================================
Generated: $(date)

🎯 EXECUTIVE SUMMARY:
Security Score: $score/100
Risk Level: $risk/100

🔍 KEY METRICS:
- Privileged Containers: $priv_containers
- High-Risk Ports: $high_risk_ports  
- External Network Exposure: $external_networks
- Blocked Threats: $blocked_threats

📋 DETAILED ANALYSIS:
$(cat privileged_containers.csv 2>/dev/null | column -t -s ',' || echo "No container data available")

🌍 NETWORK ANALYSIS:
$(cat network_analysis.csv 2>/dev/null | column -t -s ',' || echo "No network data available")

🛡️ THREAT INTELLIGENCE:
$(cat fail2ban_blocked_ips.csv 2>/dev/null | column -t -s ',' || echo "No threat data available")

📊 RECOMMENDATIONS:
- Review privileged container configurations
- Audit high-risk port exposures  
- Implement network segmentation
- Monitor threat detection systems

Report generated by GoGoGadget Analytics
EOF
    
    echo -e "\n${GREEN}📄 Detailed report saved: $report_file${NC}"
}

# ==============================
# 📈 Trend Analysis
# ==============================
analyze_trends() {
    if [[ -f "security_analytics_history.csv" ]]; then
        echo -e "\n${PURPLE}📈 Security Trend Analysis:${NC}"
        
        local current_score=$(tail -1 security_analytics_history.csv | cut -d',' -f2 2>/dev/null)
        local previous_score=$(tail -2 security_analytics_history.csv | head -1 | cut -d',' -f2 2>/dev/null || echo "$current_score")
        
        if [[ -n "$current_score" && -n "$previous_score" && "$current_score" != "$previous_score" ]]; then
            local trend=$((current_score - previous_score))
            if [[ $trend -gt 0 ]]; then
                echo -e "${GREEN}📈 Security trend: +$trend points improvement${NC}"
            else
                echo -e "${RED}📉 Security trend: $trend points decline${NC}"
            fi
            
            # Show historical data count
            local data_points=$(wc -l < security_analytics_history.csv 2>/dev/null)
            echo -e "${CYAN}📊 Historical data: $data_points analysis points tracked${NC}"
        fi
    fi
}

# ==============================
# 🚀 Main Execution
# ==============================
main() {
    # Configuration
    configure_options
    
    # Ensure data availability
    ensure_data_availability
    
    # Run analytics
    calculate_security_analytics
    display_detailed_metrics
    
    # Completion summary
    echo -e "\n${GREEN}🎯 Security analytics completed!${NC}"
    
    if [[ "$SAVE_REPORTS" == "true" ]]; then
        echo -e "${CYAN}📂 Reports generated in current directory${NC}"
    fi
    
    if [[ "$SAVE_HISTORY" == "true" ]]; then
        echo -e "${CYAN}📈 Trend data saved to security_analytics_history.csv${NC}"
    fi
}

# Execute main function
main
