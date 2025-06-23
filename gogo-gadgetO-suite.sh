#!/bin/bash

# ==============================
# 🚀 GoGoGadget Security Suite - Master Launcher
# ==============================

GREEN="\033[1;32m"
BLUE="\033[1;34m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
NC="\033[0m"

echo -e "${BLUE}"
echo "┌────────────────────────────────────────────────────────┐"
echo "│  🚀 GoGoGadget Security Suite - Complete Security Kit │"
echo "│  🔍 Choose your security mission...                   │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# Available modules
declare -A modules
modules=(
    ["Inspector Gadget - Core Analysis"]="./inspector-gadget.sh"
    ["Chkrootkit - Rootkit Detection"]="./gogo-gadgetO-chkrootkit.sh"
    ["ClamAV - Malware Scanner"]="./gogo-gadgetO-clamav.sh"
    ["Lynis - Security Audit"]="./gogo-gadgetO-lynis.sh"
    ["RKHunter - Alternative Rootkit Scanner"]="./gogo-gadgetO-rkhunter.sh"
    ["Risk Assessment - Security Scoring"]="./gogo-gadgetO-scan.sh"
    ["Sentinel - SSH Threat Intelligence"]="./gogo-gadgetO-sentinel.sh"
    ["SSH Monitor - Connection Tracking"]="./gogo-gadgetO-ssh-monitor.sh"
    ["Vault - Secure Report Storage"]="./gogo-gadgetO-vault.sh"
)

display_menu() {
    echo -e "\n${YELLOW}🛡️ Available Security Modules:${NC}"
    echo "─────────────────────────────────────"
    i=1
    for module in "${!modules[@]}"; do
        echo "[$i] $module"
        options[$i]="${modules[$module]}"
        ((i++))
    done
    echo "[A] Run Complete Security Suite"
    echo "[Q] Quit"
}

run_complete_suite() {
    echo -e "\n${GREEN}🚀 Running Complete Security Analysis...${NC}"
    
    # Run core analysis first
    echo -e "\n${BLUE}[1/9] Running Inspector-Gadget Core Analysis...${NC}"
    sudo ./inspector-gadget.sh
    
    # Run additional scans
    echo -e "\n${BLUE}[2/9] Running Rootkit Detection...${NC}"
    sudo ./gogo-gadgetO-chkrootkit.sh
    
    echo -e "\n${BLUE}[3/9] Running Malware Scan...${NC}"
    sudo ./gogo-gadgetO-clamav.sh
    
    echo -e "\n${BLUE}[4/9] Running Security Audit...${NC}"
    sudo ./gogo-gadgetO-lynis.sh
    
    echo -e "\n${BLUE}[5/9] Running SSH Threat Analysis...${NC}"
    sudo ./gogo-gadgetO-sentinel.sh
    
    echo -e "\n${BLUE}[6/9] Running SSH Monitoring...${NC}"
    sudo ./gogo-gadgetO-ssh-monitor.sh
    
    echo -e "\n${BLUE}[7/9] Calculating Risk Score...${NC}"
    sudo ./gogo-gadgetO-scan.sh
    
    echo -e "\n${BLUE}[8/9] Securing Reports...${NC}"
    sudo ./gogo-gadgetO-vault.sh
    
    echo -e "\n${GREEN}✅ Complete Security Analysis Finished!${NC}"
}

while true; do
    display_menu
    echo -n "Enter your choice: "
    read -r choice
    
    case "$choice" in
        [Qq]) 
            echo "Exiting..."
            exit 0
            ;;
        [Aa])
            run_complete_suite
            break
            ;;
        [1-9])
            if [[ -n "${options[$choice]}" ]]; then
                echo -e "\n${GREEN}Running: ${options[$choice]}${NC}"
                sudo "${options[$choice]}"
            else
                echo -e "${RED}Invalid selection!${NC}"
            fi
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            ;;
    esac
done