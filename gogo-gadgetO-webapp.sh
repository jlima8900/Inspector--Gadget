#!/bin/bash

# ==============================
# 📡 GoGoGadget Logs - Advanced Log Analysis & SIEM
# ==============================

GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
PURPLE="\033[1;35m"
NC="\033[0m"

echo -e "${BLUE}"
echo "┌────────────────────────────────────────────────────────┐"
echo "│  📡 GoGoGadget Logs - Advanced Log Analysis & SIEM    │"
echo "│  🔍 Hunting threats through log correlation           │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# Configuration
SAVE_REPORTS=true
TIME_RANGE="24h"
CORRELATION_ENABLED=true

# Configure analysis options
configure_analysis() {
    echo -e "${YELLOW}📡 Log Analysis Configuration:${NC}"
    echo "1) Quick analysis (last 1 hour)"
    echo "2) Standard analysis (last 24 hours) + reports"
    echo "3) Deep forensic analysis (last 7 days) + correlation"
    echo -n "Select option (1/2/3): "
    read -r choice
    
    case $choice in
        1)
            TIME_RANGE="1h"
            SAVE_REPORTS=false
            CORRELATION_ENABLED=false
            echo -e "${GREEN}✅ Quick analysis mode (1 hour)${NC}"
            ;;
        2)
            TIME_RANGE="24h"
            SAVE_REPORTS=true
            CORRELATION_ENABLED=false
            echo -e "${GREEN}✅ Standard analysis (24 hours) + reports${NC}"
            ;;
        3)
            TIME_RANGE="7d"
            SAVE_REPORTS=true
            CORRELATION_ENABLED=true
            echo -e "${GREEN}✅ Deep forensic analysis (7 days) + correlation${NC}"
            ;;
        *)
            TIME_RANGE="24h"
            echo -e "${YELLOW}⚠️ Invalid choice, defaulting to 24 hours${NC}"
            ;;
    esac
    echo ""
}

# Detect available log files
detect_log_files() {
    echo -e "${CYAN}🔍 Detecting available log files...${NC}"
    
    declare -A LOG_FILES
    
    # System logs
    [[ -f /var/log/messages ]] && LOG_FILES["system"]="/var/log/messages"
    [[ -f /var/log/syslog ]] && LOG_FILES["system"]="/var/log/syslog"
    
    # Authentication logs
    [[ -f /var/log/auth.log ]] && LOG_FILES["auth"]="/var/log/auth.log"
    [[ -f /var/log/secure ]] && LOG_FILES["auth"]="/var/log/secure"
    
    # Web server logs
    [[ -f /var/log/apache2/access.log ]] && LOG_FILES["web_access"]="/var/log/apache2/access.log"
    [[ -f /var/log/nginx/access.log ]] && LOG_FILES["web_access"]="/var/log/nginx/access.log"
    [[ -f /var/log/apache2/error.log ]] && LOG_FILES["web_error"]="/var/log/apache2/error.log"
    [[ -f /var/log/nginx/error.log ]] && LOG_FILES["web_error"]="/var/log/nginx/error.log"
    
    # Kernel logs
    [[ -f /var/log/kern.log ]] && LOG_FILES["kernel"]="/var/log/kern.log"
    [[ -f /var/log/dmesg ]] && LOG_FILES["kernel"]="/var/log/dmesg"
    
    # Mail logs
    [[ -f /var/log/mail.log ]] && LOG_FILES["mail"]="/var/log/mail.log"
    [[ -f /var/log/maillog ]] && LOG_FILES["mail"]="/var/log/maillog"
    
    # Firewall logs
    [[ -f /var/log/ufw.log ]] && LOG_FILES["firewall"]="/var/log/ufw.log"
    [[ -f /var/log/iptables.log ]] && LOG_FILES["firewall"]="/var/log/iptables.log"
    
    echo -e "${GREEN}📋 Available log sources:${NC}"
    for log_type in "${!LOG_FILES[@]}"; do
        echo -e "  📄 ${log_type}: ${LOG_FILES[$log_type]}"
    done
    
    [[ ${#LOG_FILES[@]} -eq 0 ]] && {
        echo -e "${RED}❌ No accessible log files found${NC}"
        echo -e "${YELLOW}💡 Run with sudo for access to system logs${NC}"
        return 1
    }
    
    # Export for use in other functions
    declare -gA DETECTED_LOGS
    for key in "${!LOG_FILES[@]}"; do
        DETECTED_LOGS["$key"]="${LOG_FILES[$key]}"
    done
    
    return 0
}

# Convert time range to seconds for date calculations
get_time_seconds() {
    case "$TIME_RANGE" in
        "1h") echo "3600" ;;
        "24h") echo "86400" ;;
        "7d") echo "604800" ;;
        *) echo "86400" ;;
    esac
}

# Authentication log analysis
analyze_auth_logs() {
    echo -e "\n${CYAN}🔐 Authentication Log Analysis${NC}"
    
    local auth_log="${DETECTED_LOGS[auth]}"
    if [[ -z "$auth_log" || ! -r "$auth_log" ]]; then
        echo -e "${YELLOW}⚠️ Authentication logs not accessible${NC}"
        return 1
    fi
    
    local time_seconds=$(get_time_seconds)
    local since_time=$(date -d "-$time_seconds seconds" '+%b %d %H:%M')
    
    echo -e "${YELLOW}🔍 Analyzing authentication events since $since_time...${NC}"
    
    # Failed login attempts
    local failed_logins=$(grep "Failed password" "$auth_log" | wc -l)
    echo -e "  🚫 Failed login attempts: $failed_logins"
    
    if [[ $failed_logins -gt 10 ]]; then
        echo -e "  ${RED}🚨 HIGH: Excessive failed login attempts detected${NC}"
        
        # Show top attacking IPs
        echo -e "  ${YELLOW}Top attacking IPs:${NC}"
        grep "Failed password" "$auth_log" | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -5 | while read -r count ip; do
            echo -e "    📡 $ip: $count attempts"
        done
    else
        echo -e "  ${GREEN}✅ Normal level of failed logins${NC}"
    fi
    
    # Successful logins
    local successful_logins=$(grep "Accepted password\|Accepted publickey" "$auth_log" | wc -l)
    echo -e "  ✅ Successful logins: $successful_logins"
    
    # Root login attempts
    local root_attempts=$(grep "root" "$auth_log" | grep -c "Failed password\|Accepted password")
    if [[ $root_attempts -gt 0 ]]; then
        echo -e "  ${RED}⚠️ Root login attempts: $root_attempts${NC}"
        echo -e "  ${YELLOW}💡 Consider disabling root SSH access${NC}"
    fi
    
    # Unusual authentication events
    echo -e "\n${YELLOW}🔍 Unusual Authentication Events:${NC}"
    local unusual_events=$(grep -E "BREAK-IN|Invalid user|illegal user|authentication failure" "$auth_log" | wc -l)
    if [[ $unusual_events -gt 0 ]]; then
        echo -e "  ${RED}🚨 Suspicious events detected: $unusual_events${NC}"
        echo -e "  ${BLUE}💡 Review detailed auth log for investigation${NC}"
    else
        echo -e "  ${GREEN}✅ No unusual authentication events detected${NC}"
    fi
}

# System log analysis
analyze_system_logs() {
    echo -e "\n${CYAN}🖥️ System Log Analysis${NC}"
    
    local system_log="${DETECTED_LOGS[system]}"
    if [[ -z "$system_log" || ! -r "$system_log" ]]; then
        echo -e "${YELLOW}⚠️ System logs not accessible${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}🔍 Analyzing system events...${NC}"
    
    # Error analysis
    local error_count=$(grep -i "error\|failed\|fault" "$system_log" | wc -l)
    echo -e "  ❌ Error events: $error_count"
    
    if [[ $error_count -gt 50 ]]; then
        echo -e "  ${RED}🚨 HIGH: Excessive error events detected${NC}"
        
        # Show top error types
        echo -e "  ${YELLOW}Top error patterns:${NC}"
        grep -i "error\|failed\|fault" "$system_log" | awk '{print $5}' | sort | uniq -c | sort -nr | head -5 | while read -r count service; do
            echo -e "    🔧 $service: $count errors"
        done
    else
        echo -e "  ${GREEN}✅ Normal error levels${NC}"
    fi
    
    # Service restarts
    local service_restarts=$(grep -i "starting\|stopping\|restarting" "$system_log" | wc -l)
    echo -e "  🔄 Service restarts: $service_restarts"
    
    # Kernel messages
    local kernel_messages=$(grep "kernel:" "$system_log" | wc -l)
    echo -e "  🔧 Kernel messages: $kernel_messages"
    
    # OOM (Out of Memory) events
    local oom_events=$(grep -i "out of memory\|oom" "$system_log" | wc -l)
    if [[ $oom_events -gt 0 ]]; then
        echo -e "  ${RED}🚨 Out of Memory events: $oom_events${NC}"
        echo -e "  ${YELLOW}💡 System may be under memory pressure${NC}"
    fi
}

# Web server log analysis
analyze_web_logs() {
    echo -e "\n${CYAN}🌐 Web Server Log Analysis${NC}"
    
    local access_log="${DETECTED_LOGS[web_access]}"
    local error_log="${DETECTED_LOGS[web_error]}"
    
    if [[ -z "$access_log" && -z "$error_log" ]]; then
        echo -e "${YELLOW}⚠️ Web server logs not found${NC}"
        return 1
    fi
    
    # Access log analysis
    if [[ -n "$access_log" && -r "$access_log" ]]; then
        echo -e "${YELLOW}🔍 Analyzing web access logs...${NC}"
        
        local total_requests=$(wc -l < "$access_log")
        echo -e "  📊 Total requests: $total_requests"
        
        # HTTP status code analysis
        echo -e "  📋 HTTP Status Codes:"
        awk '{print $9}' "$access_log" | sort | uniq -c | sort -nr | head -5 | while read -r count status; do
            case "$status" in
                2*) echo -e "    ${GREEN}✅ $status: $count${NC}" ;;
                3*) echo -e "    ${BLUE}🔄 $status: $count${NC}" ;;
                4*) echo -e "    ${YELLOW}⚠️ $status: $count${NC}" ;;
                5*) echo -e "    ${RED}❌ $status: $count${NC}" ;;
                *) echo -e "    📊 $status: $count" ;;
            esac
        done
        
        # Top user agents (potential bots/scanners)
        local bot_requests=$(grep -i "bot\|crawler\|spider\|scanner" "$access_log" | wc -l)
        echo -e "  🤖 Bot/Scanner requests: $bot_requests"
        
        # Suspicious patterns
        local attack_patterns=$(grep -iE "\.php\?|union.*select|script.*alert|/etc/passwd|cmd=|exec=" "$access_log" | wc -l)
        if [[ $attack_patterns -gt 0 ]]; then
            echo -e "  ${RED}🚨 Potential attack patterns: $attack_patterns${NC}"
        else
            echo -e "  ${GREEN}✅ No obvious attack patterns detected${NC}"
        fi
    fi
    
    # Error log analysis
    if [[ -n "$error_log" && -r "$error_log" ]]; then
        echo -e "\n${YELLOW}🔍 Analyzing web error logs...${NC}"
        
        local error_count=$(wc -l < "$error_log")
        echo -e "  ❌ Total errors: $error_count"
        
        # Critical errors
        local critical_errors=$(grep -i "critical\|emergency\|alert" "$error_log" | wc -l)
        if [[ $critical_errors -gt 0 ]]; then
            echo -e "  ${RED}🚨 Critical errors: $critical_errors${NC}"
        fi
    fi
}

# Security event correlation
security_event_correlation() {
    echo -e "\n${PURPLE}🔗 Security Event Correlation${NC}"
    
    if [[ "$CORRELATION_ENABLED" != "true" ]]; then
        echo -e "${YELLOW}⚠️ Correlation disabled for this scan${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}🔍 Correlating security events across log sources...${NC}"
    
    # Create temporary correlation file
    local correlation_file="security_correlation_$(date +%Y%m%d_%H%M%S).tmp"
    
    # Extract timestamps and events from multiple logs
    for log_type in "${!DETECTED_LOGS[@]}"; do
        local log_file="${DETECTED_LOGS[$log_type]}"
        [[ ! -r "$log_file" ]] && continue
        
        case "$log_type" in
            "auth")
                grep -E "Failed password|Accepted password|Invalid user" "$log_file" | sed "s/^/$log_type: /" >> "$correlation_file"
                ;;
            "system")
                grep -i "error\|failed\|segfault" "$log_file" | sed "s/^/$log_type: /" >> "$correlation_file"
                ;;
            "web_access")
                grep -E " [45][0-9][0-9] |bot|scanner" "$log_file" | sed "s/^/$log_type: /" >> "$correlation_file"
                ;;
        esac
    done
    
    if [[ -f "$correlation_file" ]]; then
        local correlated_events=$(wc -l < "$correlation_file")
        echo -e "  📊 Correlated events: $correlated_events"
        
        # Timeline analysis
        echo -e "  ⏰ Creating security timeline..."
        sort "$correlation_file" > "security_timeline_$(date +%Y%m%d_%H%M%S).log"
        
        # Look for event clusters (potential coordinated attacks)
        local event_clusters=$(awk '{print $1" "$2" "$3}' "$correlation_file" | sort | uniq -c | sort -nr | head -5)
        if [[ -n "$event_clusters" ]]; then
            echo -e "  ${YELLOW}📈 Event clusters detected:${NC}"
            echo "$event_clusters" | while read -r count timestamp; do
                if [[ $count -gt 10 ]]; then
                    echo -e "    ${RED}🚨 $timestamp: $count events${NC}"
                fi
            done
        fi
        
        # Cleanup
        rm -f "$correlation_file"
    else
        echo -e "  ${YELLOW}⚠️ No events available for correlation${NC}"
    fi
}

# Threat hunting patterns
threat_hunting() {
    echo -e "\n${PURPLE}🎯 Threat Hunting Analysis${NC}"
    
    echo -e "${YELLOW}🔍 Hunting for advanced threat indicators...${NC}"
    
    # Initialize threat score
    local threat_score=0
    local max_threat_score=100
    
    # Hunt through available logs
    for log_type in "${!DETECTED_LOGS[@]}"; do
        local log_file="${DETECTED_LOGS[$log_type]}"
        [[ ! -r "$log_file" ]] && continue
        
        case "$log_type" in
            "auth")
                # Brute force indicators
                local brute_force=$(grep "Failed password" "$log_file" | awk '{print $(NF-3)}' | sort | uniq -c | awk '$1 > 20 {count++} END {print count+0}')
                if [[ $brute_force -gt 0 ]]; then
                    echo -e "  ${RED}🚨 Brute force attack indicators: $brute_force sources${NC}"
                    ((threat_score += 20))
                fi
                
                # Privilege escalation attempts
                local priv_esc=$(grep -c "sudo.*COMMAND\|su:" "$log_file")
                if [[ $priv_esc -gt 50 ]]; then
                    echo -e "  ${YELLOW}⚠️ Elevated privilege usage: $priv_esc events${NC}"
                    ((threat_score += 10))
                fi
                ;;
                
            "system")
                # System compromise indicators
                local compromise_indicators=$(grep -ic "segfault\|core dumped\|killed\|oom" "$log_file")
                if [[ $compromise_indicators -gt 10 ]]; then
                    echo -e "  ${YELLOW}⚠️ System instability indicators: $compromise_indicators${NC}"
                    ((threat_score += 15))
                fi
                ;;
                
            "web_access")
                # Web attack patterns
                local web_attacks=$(grep -icE "union.*select|script.*alert|\.\.\/|cmd=|exec=" "$log_file")
                if [[ $web_attacks -gt 0 ]]; then
                    echo -e "  ${RED}🚨 Web attack patterns: $web_attacks${NC}"
                    ((threat_score += 25))
                fi
                ;;
        esac
    done
    
    # Calculate threat level
    echo -e "\n${PURPLE}🎯 Threat Assessment:${NC}"
    local threat_percentage=$((threat_score * 100 / max_threat_score))
    
    if [[ $threat_score -eq 0 ]]; then
        echo -e "  ${GREEN}🟢 LOW THREAT: No significant indicators detected${NC}"
    elif [[ $threat_percentage -lt 25 ]]; then
        echo -e "  ${YELLOW}🟡 MODERATE THREAT: Some indicators present (Score: $threat_score/$max_threat_score)${NC}"
    elif [[ $threat_percentage -lt 50 ]]; then
        echo -e "  ${RED}🟠 HIGH THREAT: Multiple indicators detected (Score: $threat_score/$max_threat_score)${NC}"
    else
        echo -e "  ${RED}🔴 CRITICAL THREAT: Severe indicators detected (Score: $threat_score/$max_threat_score)${NC}"
        echo -e "  ${YELLOW}💡 Immediate investigation recommended${NC}"
    fi
}

# Generate SIEM-style report
generate_siem_report() {
    local report_file="siem_analysis_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
📡 SIEM LOG ANALYSIS REPORT
==========================
Generated: $(date)
Analysis Period: $TIME_RANGE
System: $(uname -a)

LOG SOURCES ANALYZED:
====================
$(for log_type in "${!DETECTED_LOGS[@]}"; do
    echo "$log_type: ${DETECTED_LOGS[$log_type]}"
done)

AUTHENTICATION ANALYSIS:
=======================
$(grep "Failed password" "${DETECTED_LOGS[auth]}" 2>/dev/null | wc -l) failed login attempts
$(grep "Accepted password\|Accepted publickey" "${DETECTED_LOGS[auth]}" 2>/dev/null | wc -l) successful logins

SYSTEM EVENTS:
=============
$(grep -i "error\|failed" "${DETECTED_LOGS[system]}" 2>/dev/null | wc -l) error events
$(grep -i "starting\|stopping" "${DETECTED_LOGS[system]}" 2>/dev/null | wc -l) service events

WEB ACTIVITY:
============
$(wc -l < "${DETECTED_LOGS[web_access]}" 2>/dev/null || echo "0") total web requests
$(grep -c " [45][0-9][0-9] " "${DETECTED_LOGS[web_access]}" 2>/dev/null || echo "0") error responses

SECURITY RECOMMENDATIONS:
========================
1. Monitor failed authentication attempts
2. Investigate unusual system errors
3. Review web server error patterns
4. Implement real-time log monitoring
5. Set up automated alerting for critical events
6. Regular log retention and archival
7. Consider implementing a full SIEM solution

ANALYSIS METADATA:
=================
Tool: GoGoGadget SIEM Analyzer
Analysis completed: $(date)
Report generated by GoGoGadget Log Analysis Module
EOF
    
    echo -e "\n${GREEN}📄 SIEM analysis report saved: $report_file${NC}"
}

# Display menu
display_menu() {
    echo -e "\n${YELLOW}📡 Log Analysis & SIEM Options:${NC}"
    echo "────────────────────────────────────────────"
    echo "[1] Authentication log analysis"
    echo "[2] System log analysis"
    echo "[3] Web server log analysis"
    echo "[4] Security event correlation"
    echo "[5] Threat hunting analysis"
    echo "[6] Complete SIEM analysis"
    echo "[7] Generate SIEM report"
    echo "[Q] Quit"
}

# Main execution
main() {
    # Check permissions
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}⚠️ Log analysis works better with root privileges${NC}"
        echo -e "${BLUE}Some log files may not be accessible${NC}"
        echo ""
    fi
    
    configure_analysis
    
    if ! detect_log_files; then
        echo -e "${RED}❌ Cannot proceed without accessible log files${NC}"
        exit 1
    fi
    
    while true; do
        display_menu
        echo -n "Enter your choice: "
        read -r choice
        
        case "$choice" in
            1)
                analyze_auth_logs
                ;;
            2)
                analyze_system_logs
                ;;
            3)
                analyze_web_logs
                ;;
            4)
                security_event_correlation
                ;;
            5)
                threat_hunting
                ;;
            6)
                echo -e "${BLUE}🚀 Running complete SIEM analysis...${NC}"
                analyze_auth_logs
                analyze_system_logs
                analyze_web_logs
                security_event_correlation
                threat_hunting
                echo -e "\n${GREEN}🎯 Complete SIEM analysis finished!${NC}"
                ;;
            7)
                generate_siem_report
                ;;
            [Qq])
                echo -e "${BLUE}Exiting log analyzer... 📡${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Invalid choice!${NC}"
                ;;
        esac
    done
}

main
