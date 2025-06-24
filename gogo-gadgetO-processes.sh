#!/bin/bash

# ==============================
# 🕵️ GoGoGadget Processes - System Process Security Monitor
# ==============================

GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
NC="\033[0m"

echo -e "${BLUE}"
echo "┌────────────────────────────────────────────────────────┐"
echo "│  🕵️ GoGoGadget Processes - System Security Monitor    │"
echo "│  👀 Hunting suspicious processes & system activity    │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# Configuration
SAVE_REPORTS=false

# Configure output
configure_options() {
    echo -e "${YELLOW}📋 Process Monitor Configuration:${NC}"
    echo "1) Display results only"
    echo "2) Save detailed reports to files"
    echo -n "Select option (1/2): "
    read -r choice
    
    case $choice in
        2)
            SAVE_REPORTS=true
            echo -e "${GREEN}✅ Reports will be saved to files${NC}"
            ;;
        *)
            SAVE_REPORTS=false
            echo -e "${GREEN}✅ Display only mode${NC}"
            ;;
    esac
    echo ""
}

# Analyze running processes
analyze_processes() {
    echo -e "${CYAN}🔍 Analyzing running processes...${NC}"
    
    # High-level process overview
    local total_processes=$(ps aux | wc -l)
    local root_processes=$(ps aux | grep -c "^root")
    local user_processes=$((total_processes - root_processes))
    
    echo -e "${GREEN}📊 Process Overview:${NC}"
    echo -e "  Total processes: $total_processes"
    echo -e "  Root processes: $root_processes"
    echo -e "  User processes: $user_processes"
    
    # Check for suspicious process names
    echo -e "\n${YELLOW}🚨 Suspicious Process Check:${NC}"
    local suspicious_patterns=("nc" "netcat" "ncat" "socat" "telnet" "wget.*http" "curl.*http" "python.*-c" "perl.*-e" "bash.*-i" "sh.*-i")
    local found_suspicious=false
    
    for pattern in "${suspicious_patterns[@]}"; do
        local matches=$(ps aux | grep -E "$pattern" | grep -v grep)
        if [[ -n "$matches" ]]; then
            echo -e "${RED}⚠️ Suspicious pattern '$pattern' found:${NC}"
            echo "$matches" | while read -r line; do
                echo -e "    $line"
            done
            found_suspicious=true
        fi
    done
    
    [[ "$found_suspicious" == false ]] && echo -e "${GREEN}✅ No obviously suspicious processes detected${NC}"
    
    # Network-connected processes
    echo -e "\n${CYAN}🌐 Network-Connected Processes:${NC}"
    if command -v ss &>/dev/null; then
        local listening_processes=$(ss -tlnp | grep LISTEN | awk '{print $4, $6}' | sort | uniq)
        echo -e "${YELLOW}Listening processes:${NC}"
        echo "$listening_processes" | head -10 | while read -r line; do
            echo -e "  📡 $line"
        done
    else
        local listening_processes=$(netstat -tlnp 2>/dev/null | grep LISTEN | awk '{print $4, $7}' | sort | uniq)
        echo -e "${YELLOW}Listening processes:${NC}"
        echo "$listening_processes" | head -10 | while read -r line; do
            echo -e "  📡 $line"
        done
    fi
    
    # Check for processes without parent (potential orphans)
    echo -e "\n${YELLOW}🔍 Orphaned Processes Check:${NC}"
    local orphans=$(ps -eo pid,ppid,comm | awk '$2 == 1 && $1 != 1 {print $0}' | grep -v "\[")
    if [[ -n "$orphans" ]]; then
        echo -e "${YELLOW}Processes with PPID=1 (potential orphans):${NC}"
        echo "$orphans" | while read -r line; do
            echo -e "  👻 $line"
        done
    else
        echo -e "${GREEN}✅ No orphaned processes detected${NC}"
    fi
}

# Resource consumption analysis
analyze_resource_usage() {
    echo -e "\n${CYAN}📊 Resource Consumption Analysis:${NC}"
    
    # Top CPU consumers
    echo -e "${YELLOW}🔥 Top CPU Consumers:${NC}"
    ps aux --sort=-%cpu | head -6 | tail -5 | while read -r line; do
        local cpu=$(echo "$line" | awk '{print $3}')
        local process=$(echo "$line" | awk '{print $11}')
        echo -e "  🔥 CPU: ${cpu}% - $process"
    done
    
    # Top memory consumers
    echo -e "\n${YELLOW}🧠 Top Memory Consumers:${NC}"
    ps aux --sort=-%mem | head -6 | tail -5 | while read -r line; do
        local mem=$(echo "$line" | awk '{print $4}')
        local process=$(echo "$line" | awk '{print $11}')
        echo -e "  🧠 MEM: ${mem}% - $process"
    done
    
    # System load analysis
    if [[ -f /proc/loadavg ]]; then
        local loadavg=$(cat /proc/loadavg)
        local load1min=$(echo "$loadavg" | awk '{print $1}')
        local load5min=$(echo "$loadavg" | awk '{print $2}')
        local load15min=$(echo "$loadavg" | awk '{print $3}')
        
        echo -e "\n${YELLOW}⚖️ System Load:${NC}"
        echo -e "  1min: $load1min, 5min: $load5min, 15min: $load15min"
        
        # Load assessment
        local cpu_cores=$(nproc)
        local load_ratio=$(echo "$load1min $cpu_cores" | awk '{printf "%.1f", $1/$2}')
        
        if (( $(echo "$load_ratio > 1.5" | bc -l) )); then
            echo -e "  ${RED}🚨 HIGH LOAD: System may be under stress${NC}"
        elif (( $(echo "$load_ratio > 1.0" | bc -l) )); then
            echo -e "  ${YELLOW}⚠️ MODERATE LOAD: Monitor system performance${NC}"
        else
            echo -e "  ${GREEN}✅ NORMAL LOAD: System performing well${NC}"
        fi
    fi
}

# Security-focused process analysis
security_process_analysis() {
    echo -e "\n${CYAN}🔒 Security Process Analysis:${NC}"
    
    # Check for privilege escalation indicators
    echo -e "${YELLOW}🔍 Privilege Escalation Indicators:${NC}"
    
    # SUID/SGID processes
    local suid_processes=$(ps -eo pid,user,comm,args | grep -E "(su |sudo |pkexec)" | grep -v grep)
    if [[ -n "$suid_processes" ]]; then
        echo -e "${YELLOW}Privilege escalation processes:${NC}"
        echo "$suid_processes" | while read -r line; do
            echo -e "  🔑 $line"
        done
    else
        echo -e "${GREEN}✅ No active privilege escalation processes${NC}"
    fi
    
    # Check for unusual shell activities
    echo -e "\n${YELLOW}🐚 Shell Activity Analysis:${NC}"
    local shell_processes=$(ps aux | grep -E "(bash|sh|zsh|csh|tcsh|fish)" | grep -v grep | wc -l)
    local interactive_shells=$(ps aux | grep -E "bash.*-i|sh.*-i" | grep -v grep)
    
    echo -e "  Total shell processes: $shell_processes"
    if [[ -n "$interactive_shells" ]]; then
        echo -e "${YELLOW}Interactive shells detected:${NC}"
        echo "$interactive_shells" | while read -r line; do
            echo -e "    🐚 $line"
        done
    fi
    
    # Check for reverse shell indicators
    local reverse_shell_indicators=$(ps aux | grep -E "nc.*-l|socat.*EXEC|bash.*>&|sh.*>&" | grep -v grep)
    if [[ -n "$reverse_shell_indicators" ]]; then
        echo -e "${RED}🚨 POTENTIAL REVERSE SHELL DETECTED:${NC}"
        echo "$reverse_shell_indicators" | while read -r line; do
            echo -e "    🚨 $line"
        done
    else
        echo -e "${GREEN}✅ No reverse shell indicators detected${NC}"
    fi
}

# Real-time process monitoring
realtime_monitor() {
    echo -e "\n${BLUE}📡 Starting real-time process monitoring...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    
    local counter=0
    while true; do
        clear
        echo -e "${BLUE}🕵️ Real-time Process Monitor - Update $((++counter))${NC}"
        echo -e "${CYAN}$(date)${NC}"
        echo "════════════════════════════════════════════════════════"
        
        # Show top processes
        echo -e "${YELLOW}Top CPU Processes:${NC}"
        ps aux --sort=-%cpu | head -6 | tail -5
        
        echo -e "\n${YELLOW}Top Memory Processes:${NC}"
        ps aux --sort=-%mem | head -6 | tail -5
        
        # Show system stats
        echo -e "\n${YELLOW}System Stats:${NC}"
        local total_procs=$(ps aux | wc -l)
        local load=$(cat /proc/loadavg | awk '{print $1}')
        echo -e "Processes: $total_procs | Load: $load"
        
        sleep 3
    done
}

# Generate process report
generate_process_report() {
    local report_file="process_security_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
🕵️ PROCESS SECURITY ANALYSIS REPORT
===================================
Generated: $(date)
System: $(uname -a)

PROCESS OVERVIEW:
$(ps aux | wc -l) total processes
$(ps aux | grep -c "^root") root processes
$(ps aux | grep -c -v "^root") user processes

TOP CPU CONSUMERS:
$(ps aux --sort=-%cpu | head -6 | tail -5)

TOP MEMORY CONSUMERS:
$(ps aux --sort=-%mem | head -6 | tail -5)

LISTENING PROCESSES:
$(ss -tlnp 2>/dev/null | grep LISTEN || netstat -tlnp 2>/dev/null | grep LISTEN)

SECURITY ANALYSIS:
- Checked for suspicious process patterns
- Analyzed privilege escalation indicators
- Monitored shell activity
- Scanned for reverse shell indicators

RECOMMENDATIONS:
1. Monitor processes with high resource usage
2. Investigate unknown network connections
3. Verify legitimacy of privilege escalation processes
4. Regular process baseline comparisons
5. Implement process monitoring automation

Report generated by GoGoGadget Process Monitor
EOF
    
    echo -e "\n${GREEN}📄 Process report saved: $report_file${NC}"
}

# Display menu
display_menu() {
    echo -e "\n${YELLOW}🕵️ Process Security Monitor Options:${NC}"
    echo "────────────────────────────────────────────"
    echo "[1] Analyze running processes"
    echo "[2] Resource consumption analysis"
    echo "[3] Security-focused analysis"
    echo "[4] Real-time process monitoring"
    echo "[5] Generate comprehensive report"
    echo "[Q] Quit"
}

# Main execution
main() {
    configure_options
    
    while true; do
        display_menu
        echo -n "Enter your choice: "
        read -r choice
        
        case "$choice" in
            1)
                analyze_processes
                ;;
            2)
                analyze_resource_usage
                ;;
            3)
                security_process_analysis
                ;;
            4)
                realtime_monitor
                ;;
            5)
                analyze_processes
                analyze_resource_usage
                security_process_analysis
                [[ "$SAVE_REPORTS" == "true" ]] && generate_process_report
                ;;
            [Qq])
                echo -e "${BLUE}Exiting process monitor... 🕵️${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Invalid choice!${NC}"
                ;;
        esac
    done
}

main
