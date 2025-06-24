#!/bin/bash

# ==============================
# 🔬 GoGoGadget Forensics - Memory Dump Analysis & Digital Forensics
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
echo "│  🔬 GoGoGadget Forensics - Memory Dump Analysis       │"
echo "│  🕵️ Digital forensics for incident response           │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# Global variables
DUMP_FILE=""
ANALYSIS_DIR=""
SAVE_ARTIFACTS=true

# Setup forensics environment
setup_forensics_environment() {
    echo -e "${CYAN}🔧 Setting up forensics environment...${NC}"
    
    # Create analysis directory with timestamp
    ANALYSIS_DIR="forensics_analysis_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$ANALYSIS_DIR"/{dumps,artifacts,reports,timeline}
    
    echo -e "${GREEN}✅ Analysis directory created: $ANALYSIS_DIR${NC}"
    
    # Check for forensics tools
    local missing_tools=()
    
    if ! command -v strings &>/dev/null; then
        missing_tools+=("binutils")
    fi
    
    if ! command -v file &>/dev/null; then
        missing_tools+=("file")
    fi
    
    if ! command -v hexdump &>/dev/null; then
        missing_tools+=("util-linux")
    fi
    
    # Install missing tools
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${YELLOW}📦 Installing forensics tools: ${missing_tools[*]}${NC}"
        
        if command -v dnf &>/dev/null; then
            sudo dnf install -y "${missing_tools[@]}"
        elif command -v yum &>/dev/null; then
            sudo yum install -y "${missing_tools[@]}"
        elif command -v apt &>/dev/null; then
            sudo apt update && sudo apt install -y "${missing_tools[@]}"
        fi
    fi
}

# Create memory dump
create_memory_dump() {
    echo -e "\n${CYAN}🧠 Creating system memory dump...${NC}"
    
    local dump_size="1GB"
    echo -n "Memory dump size (default 1GB): "
    read -r user_size
    dump_size=${user_size:-1GB}
    
    DUMP_FILE="$ANALYSIS_DIR/dumps/memory_dump_$(date +%Y%m%d_%H%M%S).raw"
    
    echo -e "${YELLOW}⚠️ Creating memory dump may take several minutes...${NC}"
    echo -e "${BLUE}Target: $DUMP_FILE${NC}"
    echo -e "${BLUE}Size: $dump_size${NC}"
    
    # Multiple methods for memory dump creation
    if [[ -r /proc/kcore ]]; then
        echo -e "${YELLOW}📝 Using /proc/kcore method...${NC}"
        sudo dd if=/proc/kcore of="$DUMP_FILE" bs=1M count=${dump_size%GB}000 skip=1000 2>/dev/null || {
            echo -e "${YELLOW}⚠️ /proc/kcore method failed, trying alternative...${NC}"
            
            # Alternative method using /dev/mem (if available)
            if [[ -r /dev/mem ]]; then
                sudo dd if=/dev/mem of="$DUMP_FILE" bs=1M count=${dump_size%GB}000 2>/dev/null || {
                    echo -e "${RED}❌ Memory dump creation failed${NC}"
                    return 1
                }
            else
                echo -e "${RED}❌ No suitable memory dump method available${NC}"
                return 1
            fi
        }
    else
        echo -e "${RED}❌ /proc/kcore not accessible${NC}"
        return 1
    fi
    
    if [[ -f "$DUMP_FILE" && -s "$DUMP_FILE" ]]; then
        local dump_size_mb=$(du -m "$DUMP_FILE" | cut -f1)
        echo -e "${GREEN}✅ Memory dump created successfully${NC}"
        echo -e "${GREEN}   File: $DUMP_FILE${NC}"
        echo -e "${GREEN}   Size: ${dump_size_mb}MB${NC}"
        
        # Calculate hash for integrity
        local md5_hash=$(md5sum "$DUMP_FILE" | cut -d' ' -f1)
        echo "$md5_hash  $DUMP_FILE" > "$DUMP_FILE.md5"
        echo -e "${GREEN}   MD5: $md5_hash${NC}"
        
        return 0
    else
        echo -e "${RED}❌ Memory dump creation failed${NC}"
        return 1
    fi
}

# Analyze existing memory dump
analyze_memory_dump() {
    local target_file="$1"
    
    if [[ ! -f "$target_file" ]]; then
        echo -e "${RED}❌ Dump file not found: $target_file${NC}"
        return 1
    fi
    
    echo -e "\n${CYAN}🔍 Analyzing memory dump: $(basename "$target_file")${NC}"
    
    # File information
    local file_size=$(du -h "$target_file" | cut -f1)
    local file_type=$(file "$target_file")
    
    echo -e "${GREEN}📋 Dump Information:${NC}"
    echo -e "  Size: $file_size"
    echo -e "  Type: $file_type"
    
    # Verify integrity if hash exists
    if [[ -f "$target_file.md5" ]]; then
        echo -e "${YELLOW}🔍 Verifying integrity...${NC}"
        if md5sum -c "$target_file.md5" &>/dev/null; then
            echo -e "  ${GREEN}✅ Integrity verified${NC}"
        else
            echo -e "  ${RED}❌ Integrity check failed${NC}"
        fi
    fi
    
    DUMP_FILE="$target_file"
}

# Extract strings and keywords
extract_forensic_artifacts() {
    echo -e "\n${CYAN}🔍 Extracting forensic artifacts from dump...${NC}"
    
    if [[ ! -f "$DUMP_FILE" ]]; then
        echo -e "${RED}❌ No dump file available${NC}"
        return 1
    fi
    
    local artifacts_dir="$ANALYSIS_DIR/artifacts"
    
    # Extract strings
    echo -e "${YELLOW}📝 Extracting strings...${NC}"
    strings "$DUMP_FILE" > "$artifacts_dir/all_strings.txt" 2>/dev/null
    local string_count=$(wc -l < "$artifacts_dir/all_strings.txt")
    echo -e "  ${GREEN}✅ Extracted $string_count strings${NC}"
    
    # Search for specific patterns
    echo -e "\n${YELLOW}🔍 Searching for forensic indicators...${NC}"
    
    # Credentials and sensitive data
    echo -e "  🔑 Searching for credentials..."
    grep -i "password\|passwd\|secret\|token\|key\|login" "$artifacts_dir/all_strings.txt" > "$artifacts_dir/credentials.txt" 2>/dev/null
    local cred_count=$(wc -l < "$artifacts_dir/credentials.txt" 2>/dev/null || echo "0")
    echo -e "    Found $cred_count potential credential references"
    
    # URLs and network indicators
    echo -e "  🌐 Searching for network indicators..."
    grep -E "https?://|ftp://|ssh://|(\b([0-9]{1,3}\.){3}[0-9]{1,3}\b)" "$artifacts_dir/all_strings.txt" > "$artifacts_dir/network_indicators.txt" 2>/dev/null
    local net_count=$(wc -l < "$artifacts_dir/network_indicators.txt" 2>/dev/null || echo "0")
    echo -e "    Found $net_count network indicators"
    
    # Email addresses
    echo -e "  📧 Searching for email addresses..."
    grep -E "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b" "$artifacts_dir/all_strings.txt" > "$artifacts_dir/email_addresses.txt" 2>/dev/null
    local email_count=$(wc -l < "$artifacts_dir/email_addresses.txt" 2>/dev/null || echo "0")
    echo -e "    Found $email_count email addresses"
    
    # File paths
    echo -e "  📁 Searching for file paths..."
    grep -E "^/[a-zA-Z0-9_./\-]+|[A-Z]:\\\\[a-zA-Z0-9_\\\\.\-]+" "$artifacts_dir/all_strings.txt" > "$artifacts_dir/file_paths.txt" 2>/dev/null
    local path_count=$(wc -l < "$artifacts_dir/file_paths.txt" 2>/dev/null || echo "0")
    echo -e "    Found $path_count file path references"
    
    # Cryptocurrency wallets
    echo -e "  💰 Searching for cryptocurrency indicators..."
    grep -E "\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|0x[a-fA-F0-9]{40}" "$artifacts_dir/all_strings.txt" > "$artifacts_dir/crypto_wallets.txt" 2>/dev/null
    local crypto_count=$(wc -l < "$artifacts_dir/crypto_wallets.txt" 2>/dev/null || echo "0")
    echo -e "    Found $crypto_count potential cryptocurrency references"
    
    # Malware indicators
    echo -e "  🦠 Searching for malware indicators..."
    grep -iE "(backdoor|trojan|rootkit|keylog|botnet|c2|command.control)" "$artifacts_dir/all_strings.txt" > "$artifacts_dir/malware_indicators.txt" 2>/dev/null
    local malware_count=$(wc -l < "$artifacts_dir/malware_indicators.txt" 2>/dev/null || echo "0")
    echo -e "    Found $malware_count potential malware indicators"
    
    echo -e "\n${GREEN}✅ Artifact extraction completed${NC}"
}

# Hex analysis for specific patterns
hex_pattern_analysis() {
    echo -e "\n${CYAN}🔬 Performing hex pattern analysis...${NC}"
    
    if [[ ! -f "$DUMP_FILE" ]]; then
        echo -e "${RED}❌ No dump file available${NC}"
        return 1
    fi
    
    local hex_dir="$ANALYSIS_DIR/artifacts"
    
    # Search for executable headers (PE, ELF, Mach-O)
    echo -e "${YELLOW}🔍 Searching for executable headers...${NC}"
    
    # PE headers (Windows executables)
    local pe_count=$(hexdump -C "$DUMP_FILE" | grep -c "4d 5a" || echo "0")
    echo -e "  PE headers (MZ): $pe_count"
    
    # ELF headers (Linux executables)
    local elf_count=$(hexdump -C "$DUMP_FILE" | grep -c "7f 45 4c 46" || echo "0")
    echo -e "  ELF headers: $elf_count"
    
    # ZIP/JAR headers
    local zip_count=$(hexdump -C "$DUMP_FILE" | grep -c "50 4b 03 04" || echo "0")
    echo -e "  ZIP/JAR headers: $zip_count"
    
    # PDF headers
    local pdf_count=$(hexdump -C "$DUMP_FILE" | grep -c "25 50 44 46" || echo "0")
    echo -e "  PDF headers: $pdf_count"
    
    # Search for encryption signatures
    echo -e "\n${YELLOW}🔐 Searching for encryption signatures...${NC}"
    
    # SSH private key headers
    if command -v strings &>/dev/null; then
        local ssh_keys=$(strings "$DUMP_FILE" | grep -c "BEGIN.*PRIVATE KEY" || echo "0")
        echo -e "  SSH private keys: $ssh_keys"
        
        # PGP keys
        local pgp_keys=$(strings "$DUMP_FILE" | grep -c "BEGIN PGP" || echo "0")
        echo -e "  PGP keys: $pgp_keys"
        
        # SSL certificates
        local certificates=$(strings "$DUMP_FILE" | grep -c "BEGIN CERTIFICATE" || echo "0")
        echo -e "  SSL certificates: $certificates"
    fi
}

# Timeline analysis
create_forensic_timeline() {
    echo -e "\n${CYAN}📅 Creating forensic timeline...${NC}"
    
    local timeline_file="$ANALYSIS_DIR/timeline/forensic_timeline.txt"
    
    cat > "$timeline_file" << EOF
FORENSIC TIMELINE - Memory Dump Analysis
========================================
Analysis started: $(date)
Dump file: $(basename "$DUMP_FILE")
Dump size: $(du -h "$DUMP_FILE" 2>/dev/null | cut -f1 || echo "Unknown")
System: $(uname -a)

TIMELINE EVENTS:
$(date): Memory dump creation initiated
$(date): Artifact extraction completed
$(date): Pattern analysis completed

ARTIFACT SUMMARY:
$(ls -la "$ANALYSIS_DIR/artifacts/" 2>/dev/null | tail -n +2 | while read -r line; do
    local filename=$(echo "$line" | awk '{print $9}')
    local size=$(echo "$line" | awk '{print $5}')
    echo "  $filename: $size bytes"
done)

ANALYSIS COMPLETED: $(date)
EOF
    
    echo -e "${GREEN}✅ Timeline created: $timeline_file${NC}"
}

# Generate comprehensive forensics report
generate_forensics_report() {
    echo -e "\n${CYAN}📄 Generating comprehensive forensics report...${NC}"
    
    local report_file="$ANALYSIS_DIR/reports/forensics_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
🔬 DIGITAL FORENSICS ANALYSIS REPORT
====================================
Generated: $(date)
Analyst: $(whoami)
System: $(uname -a)

CASE INFORMATION:
================
Dump File: $(basename "$DUMP_FILE")
Dump Size: $(du -h "$DUMP_FILE" 2>/dev/null | cut -f1 || echo "Unknown")
MD5 Hash: $(md5sum "$DUMP_FILE" 2>/dev/null | cut -d' ' -f1 || echo "Not available")
Analysis Directory: $ANALYSIS_DIR

MEMORY DUMP ANALYSIS:
====================
$(file "$DUMP_FILE" 2>/dev/null || echo "File type analysis not available")

ARTIFACT EXTRACTION SUMMARY:
============================
Strings extracted: $(wc -l < "$ANALYSIS_DIR/artifacts/all_strings.txt" 2>/dev/null || echo "0")
Credential references: $(wc -l < "$ANALYSIS_DIR/artifacts/credentials.txt" 2>/dev/null || echo "0")
Network indicators: $(wc -l < "$ANALYSIS_DIR/artifacts/network_indicators.txt" 2>/dev/null || echo "0")
Email addresses: $(wc -l < "$ANALYSIS_DIR/artifacts/email_addresses.txt" 2>/dev/null || echo "0")
File paths: $(wc -l < "$ANALYSIS_DIR/artifacts/file_paths.txt" 2>/dev/null || echo "0")
Cryptocurrency refs: $(wc -l < "$ANALYSIS_DIR/artifacts/crypto_wallets.txt" 2>/dev/null || echo "0")
Malware indicators: $(wc -l < "$ANALYSIS_DIR/artifacts/malware_indicators.txt" 2>/dev/null || echo "0")

KEY FINDINGS:
=============
$(if [[ $(wc -l < "$ANALYSIS_DIR/artifacts/credentials.txt" 2>/dev/null || echo "0") -gt 0 ]]; then
    echo "⚠️ SENSITIVE: Potential credential information found"
fi)
$(if [[ $(wc -l < "$ANALYSIS_DIR/artifacts/malware_indicators.txt" 2>/dev/null || echo "0") -gt 0 ]]; then
    echo "🚨 CRITICAL: Potential malware indicators detected"
fi)
$(if [[ $(wc -l < "$ANALYSIS_DIR/artifacts/crypto_wallets.txt" 2>/dev/null || echo "0") -gt 0 ]]; then
    echo "💰 INFO: Cryptocurrency-related data found"
fi)

RECOMMENDATIONS:
================
1. Review all extracted artifacts for relevance to investigation
2. Correlate findings with system logs and network traffic
3. Preserve all evidence with proper chain of custody
4. Consider additional analysis tools for deeper investigation
5. Document all findings thoroughly for legal proceedings

EVIDENCE FILES:
===============
$(ls -la "$ANALYSIS_DIR/artifacts/" 2>/dev/null | tail -n +2)

ANALYSIS METADATA:
==================
Tool: GoGoGadget Forensics
Version: 1.0
Analysis completed: $(date)
Total analysis time: [To be filled manually]

Report generated by GoGoGadget Digital Forensics Module
EOF
    
    echo -e "${GREEN}✅ Comprehensive report generated: $report_file${NC}"
    echo -e "${BLUE}📂 All analysis files saved in: $ANALYSIS_DIR${NC}"
}

# Display menu
display_menu() {
    echo -e "\n${YELLOW}🔬 Digital Forensics Options:${NC}"
    echo "────────────────────────────────────────────"
    echo "[1] Create new memory dump"
    echo "[2] Analyze existing dump file"
    echo "[3] Extract forensic artifacts"
    echo "[4] Hex pattern analysis"
    echo "[5] Create forensic timeline"
    echo "[6] Generate comprehensive report"
    echo "[7] Complete forensic analysis (all steps)"
    echo "[Q] Quit"
}

# Main execution
main() {
    # Check root privileges
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}⚠️ Digital forensics requires root privileges${NC}"
        echo -e "${YELLOW}Please run with sudo for memory dump creation${NC}"
        echo ""
    fi
    
    setup_forensics_environment
    
    while true; do
        display_menu
        echo -n "Enter your choice: "
        read -r choice
        
        case "$choice" in
            1)
                create_memory_dump
                ;;
            2)
                echo -n "Enter path to existing dump file: "
                read -r dump_path
                analyze_memory_dump "$dump_path"
                ;;
            3)
                extract_forensic_artifacts
                ;;
            4)
                hex_pattern_analysis
                ;;
            5)
                create_forensic_timeline
                ;;
            6)
                generate_forensics_report
                ;;
            7)
                echo -e "${BLUE}🚀 Running complete forensic analysis...${NC}"
                if [[ -z "$DUMP_FILE" ]]; then
                    create_memory_dump || continue
                fi
                extract_forensic_artifacts
                hex_pattern_analysis
                create_forensic_timeline
                generate_forensics_report
                echo -e "\n${GREEN}🎯 Complete forensic analysis finished!${NC}"
                ;;
            [Qq])
                echo -e "${BLUE}Exiting forensics analyzer... 🔬${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Invalid choice!${NC}"
                ;;
        esac
    done
}

main
