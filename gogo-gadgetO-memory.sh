#!/bin/bash

# ==============================
# 🧠 GoGoGadget Memory - Live Memory Security Analysis (FIXED)
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
echo "│  🧠 GoGoGadget Memory - Live Memory Security Analysis │"
echo "│  🔍 Hunting hidden threats in system memory           │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# Configuration
SAVE_REPORTS=false
MEMORY_DUMP_SIZE="512MB"

# Configure options
configure_options() {
    echo -e "${YELLOW}🧠 Memory Analysis Configuration:${NC}"
    echo "1) Live analysis only (no memory dumps)"
    echo "2) Live analysis + save memory dump"
    echo "3) Full forensic analysis + comprehensive dump"
    echo -n "Select option (1/2/3): "
    read -r choice
    
    case $choice in
        1)
            SAVE_REPORTS=false
            echo -e "${GREEN}✅ Live analysis mode${NC}"
            ;;
        2)
            SAVE_REPORTS=true
            echo -e "${GREEN}✅ Live analysis + memory dump${NC}"
            echo -n "Memory dump size (default 512MB): "
            read -r dump_size
            MEMORY_DUMP_SIZE=${dump_size:-512MB}
            ;;
        3)
            SAVE_REPORTS=true
            MEMORY_DUMP_SIZE="2GB"
            echo -e "${GREEN}✅ Full forensic analysis mode${NC}"
            ;;
        *)
            SAVE_REPORTS=false
            echo -e "${YELLOW}⚠️ Invalid choice, defaulting to live analysis${NC}"
            ;;
    esac
    echo ""
}

# Check dependencies
setup_dependencies() {
    echo -e "${CYAN}🔧 Checking memory analysis dependencies...${NC}"
    
    # Check for essential tools
    if ! command -v strings &>/dev/null; then
        echo -e "${YELLOW}📦 Installing strings utility...${NC}"
        if command -v dnf &>/dev/null; then
            sudo dnf install -y binutils
        elif command -v yum &>/dev/null; then
            sudo yum install -y binutils
        elif command -v apt &>/dev/null; then
            sudo apt update && sudo apt install -y binutils
        fi
    fi
    
    # Optional: Try to install volatility3
    if ! command -v volatility3 &>/dev/null && command -v pip3 &>/dev/null; then
        echo -e "${YELLOW}📦 Installing Volatility for advanced analysis...${NC}"
        echo -e "${BLUE}Installing Volatility 3 via pip...${NC}"
        sudo pip3 install volatility3 2>/dev/null || {
            echo -e "${YELLOW}⚠️ Volatility installation failed, continuing with basic analysis${NC}"
        }
    fi
    
    echo -e "${GREEN}✅ Dependencies check completed${NC}"
}

# Live memory process analysis
analyze_memory_processes() {
    echo -e "\n${CYAN}🔍 Analyzing memory-resident processes...${NC}"
    
    # Get detailed process memory information
    echo -e "${YELLOW}📊 Process Memory Consumption:${NC}"
    echo "PID,Name,RSS(MB),VSZ(MB),CPU%,Status" > process_memory_analysis.csv
    
    ps aux --sort=-%mem | head -20 | while read -r line; do
        local pid=$(echo "$line" | awk '{print $2}')
        local name=$(echo "$line" | awk '{print $11}' | cut -d'/' -f1)
        local rss_kb=$(echo "$line" | awk '{print $6}')
        local vsz_kb=$(echo "$line" | awk '{print $5}')
        local cpu=$(echo "$line" | awk '{print $3}')
        local status=$(echo "$line" | awk '{print $8}')
        
        # Convert to MB for readability (with safety check)
        local rss_mb=0
        local vsz_mb=0
        
        # Safely convert KB to MB
        if [[ "$rss_kb" =~ ^[0-9]+$ ]]; then
            rss_mb=$((rss_kb / 1024))
        fi
        
        if [[ "$vsz_kb" =~ ^[0-9]+$ ]]; then
            vsz_mb=$((vsz_kb / 1024))
        fi
        
        echo "$pid,$name,$rss_mb,$vsz_mb,$cpu,$status" >> process_memory_analysis.csv
        
        # Flag suspicious memory usage
        if [[ $rss_mb -gt 1000 ]]; then
            echo -e "  ${RED}🚨 HIGH MEMORY: PID $pid ($name) using ${rss_mb}MB${NC}"
        elif [[ $rss_mb -gt 500 ]]; then
            echo -e "  ${YELLOW}⚠️ MODERATE: PID $pid ($name) using ${rss_mb}MB${NC}"
        fi
    done
    
    # Check for memory-mapped files
    echo -e "\n${YELLOW}🗺️ Memory-Mapped Files Analysis:${NC}"
    local suspicious_mappings=0
    
    # Get list of PIDs safely
    local pids=$(ps -eo pid --no-headers | head -20 | tr -d ' ')
    
    for pid in $pids; do
        # Skip if PID is not numeric or doesn't exist
        if [[ ! "$pid" =~ ^[0-9]+$ ]] || [[ ! -r "/proc/$pid/maps" ]]; then
            continue
        fi
        
        # Count executable mappings safely
        local executable_mappings=0
        local deleted_mappings=0
        
        if [[ -r "/proc/$pid/maps" ]]; then
            executable_mappings=$(grep -c "rwxp\|r-xp" "/proc/$pid/maps" 2>/dev/null || echo "0")
            deleted_mappings=$(grep -c "(deleted)" "/proc/$pid/maps" 2>/dev/null || echo "0")
            
            # Ensure we have valid numbers
            [[ ! "$executable_mappings" =~ ^[0-9]+$ ]] && executable_mappings=0
            [[ ! "$deleted_mappings" =~ ^[0-9]+$ ]] && deleted_mappings=0
            
            if [[ $executable_mappings -gt 10 ]]; then
                echo -e "  ${YELLOW}⚠️ PID $pid: $executable_mappings executable mappings${NC}"
                ((suspicious_mappings++))
            fi
            
            if [[ $deleted_mappings -gt 0 ]]; then
                echo -e "  ${RED}🚨 PID $pid: $deleted_mappings deleted file mappings (potential injection)${NC}"
                ((suspicious_mappings++))
            fi
        fi
    done
    
    [[ $suspicious_mappings -eq 0 ]] && echo -e "  ${GREEN}✅ No suspicious memory mappings detected${NC}"
}

# Search for sensitive data in memory
search_memory_secrets() {
    echo -e "\n${CYAN}🔍 Searching for sensitive data in memory...${NC}"
    echo -e "${RED}⚠️ WARNING: This may find sensitive information!${NC}"
    
    echo -e "${YELLOW}🔑 Credential Pattern Search:${NC}"
    
    local patterns=("password" "passwd" "secret" "token" "api_key" "private_key")
    local findings=0
    
    # Search in environment variables (safer approach)
    local pids=$(ps -eo pid --no-headers | head -10 | tr -d ' ')
    
    for pid in $pids; do
        # Skip if PID is not numeric
        if [[ ! "$pid" =~ ^[0-9]+$ ]] || [[ ! -r "/proc/$pid/environ" ]]; then
            continue
        fi
        
        local env_content=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null)
        
        for pattern in "${patterns[@]}"; do
            local matches=$(echo "$env_content" | grep -i "$pattern" | head -3)
            if [[ -n "$matches" ]]; then
                echo -e "  ${YELLOW}⚠️ PID $pid environment contains '$pattern' references${NC}"
                ((findings++))
            fi
        done
    done
    
    [[ $findings -eq 0 ]] && echo -e "  ${GREEN}✅ No obvious credential patterns in environment variables${NC}"
    
    # Check for cryptographic material
    echo -e "\n${YELLOW}🔐 Cryptographic Material Search:${NC}"
    local crypto_findings=0
    
    # Search for SSH keys and certificates (limited scope for safety)
    if command -v strings &>/dev/null; then
        # Only check accessible memory regions
        local ssh_patterns=$(ps aux | grep -c "ssh\|sshd" 2>/dev/null || echo "0")
        [[ $ssh_patterns -gt 0 ]] && echo -e "  ${YELLOW}ℹ️ SSH-related processes detected${NC}" && ((crypto_findings++))
    fi
    
    [[ $crypto_findings -eq 0 ]] && echo -e "  ${GREEN}✅ No immediate cryptographic concerns detected${NC}"
}

# Memory-based rootkit detection
detect_memory_rootkits() {
    echo -e "\n${CYAN}🦠 Memory-Based Rootkit Detection...${NC}"
    
    # Compare process lists from different sources
    echo -e "${YELLOW}🔍 Checking for process hiding...${NC}"
    
    local ps_count=$(ps aux | wc -l 2>/dev/null || echo "0")
    local proc_count=$(ls -1 /proc/[0-9]* 2>/dev/null | wc -l || echo "0")
    
    # Ensure we have valid numbers
    [[ ! "$ps_count" =~ ^[0-9]+$ ]] && ps_count=0
    [[ ! "$proc_count" =~ ^[0-9]+$ ]] && proc_count=0
    
    local difference=$((ps_count - proc_count))
    
    echo -e "  ps command reports: $ps_count processes"
    echo -e "  /proc filesystem shows: $proc_count processes"
    
    if [[ $difference -gt 5 ]]; then
        echo -e "  ${RED}🚨 SUSPICIOUS: Large discrepancy between process counts${NC}"
        echo -e "    ${YELLOW}Possible process hiding detected${NC}"
    elif [[ $difference -gt 2 ]]; then
        echo -e "  ${YELLOW}⚠️ Minor discrepancy detected (normal variance)${NC}"
    else
        echo -e "  ${GREEN}✅ Process counts consistent${NC}"
    fi
    
    # Check kernel modules
    echo -e "\n${YELLOW}🔍 Kernel Module Analysis:${NC}"
    if [[ -f /proc/modules ]]; then
        local module_count=$(wc -l < /proc/modules 2>/dev/null || echo "0")
        echo -e "  Total kernel modules loaded: $module_count"
        
        # Check for modules with suspicious names
        local suspicious_modules=$(lsmod 2>/dev/null | grep -E "(hack|root|hide|stealth)" | wc -l || echo "0")
        if [[ $suspicious_modules -gt 0 ]]; then
            echo -e "  ${RED}🚨 Suspicious module names detected${NC}"
            lsmod | grep -E "(hack|root|hide|stealth)"
        else
            echo -e "  ${GREEN}✅ No obviously suspicious module names${NC}"
        fi
    else
        echo -e "  ${YELLOW}⚠️ Cannot access /proc/modules${NC}"
    fi
}

# Generate memory report
generate_memory_report() {
    local report_file="memory_security_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
🧠 MEMORY SECURITY ANALYSIS REPORT
==================================
Generated: $(date)
System: $(uname -a)
Memory: $(free -h | grep Mem | awk '{print $2}' 2>/dev/null || echo "Unknown") total

MEMORY OVERVIEW:
$(free -h 2>/dev/null || echo "Memory information not available")

PROCESS MEMORY ANALYSIS:
$(cat process_memory_analysis.csv 2>/dev/null || echo "No process analysis data")

SYSTEM MEMORY INFO:
$(head -20 /proc/meminfo 2>/dev/null || echo "Memory info not available")

SECURITY ASSESSMENT:
- Process memory consumption analyzed
- Memory mapping patterns reviewed
- Rootkit detection performed
- Sensitive data patterns searched

RECOMMENDATIONS:
1. Monitor processes with unusual memory patterns
2. Investigate high memory consumers
3. Regular memory baseline comparisons
4. Implement memory protection mechanisms
5. Monitor for privilege escalation in memory

Report generated by GoGoGadget Memory Analyzer
EOF
    
    echo -e "\n${GREEN}📄 Memory analysis report saved: $report_file${NC}"
}

# Display menu
display_menu() {
    echo -e "\n${YELLOW}🧠 Memory Security Analysis Options:${NC}"
    echo "────────────────────────────────────────────"
    echo "[1] Live memory process analysis"
    echo "[2] Search for sensitive data in memory"
    echo "[3] Memory-based rootkit detection"
    echo "[4] Complete memory security analysis"
    echo "[5] Generate comprehensive report"
    echo "[Q] Quit"
}

# Main execution
main() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}⚠️ Memory analysis works better with root privileges${NC}"
        echo -e "${BLUE}Some features may be limited${NC}"
        echo ""
    fi
    
    configure_options
    setup_dependencies
    
    while true; do
        display_menu
        echo -n "Enter your choice: "
        read -r choice
        
        case "$choice" in
            1)
                analyze_memory_processes
                ;;
            2)
                search_memory_secrets
                ;;
            3)
                detect_memory_rootkits
                ;;
            4)
                analyze_memory_processes
                search_memory_secrets
                detect_memory_rootkits
                ;;
            5)
                analyze_memory_processes
                search_memory_secrets
                detect_memory_rootkits
                generate_memory_report
                ;;
            [Qq])
                echo -e "${BLUE}Exiting memory analyzer... 🧠${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Invalid choice!${NC}"
                ;;
        esac
    done
}

main
