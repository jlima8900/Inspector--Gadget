#!/bin/bash

# GoGoGadget ClamAV Security Scanner
echo "==========================================="
echo "    🦠 GoGoGadget ClamAV Malware Scanner    "
echo "==========================================="

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
    elif [[ -f /etc/redhat-release ]]; then
        OS="rhel"
    else
        OS="unknown"
    fi
}

# Function to install ClamAV based on OS
install_clamav() {
    detect_os
    echo "[+] Detected OS: $OS"

    case "$OS" in
        ubuntu|debian)
            INSTALL_CMD="sudo apt update && sudo apt install clamav clamav-daemon -y"
            ;;
        centos|rhel|almalinux|rocky)
            INSTALL_CMD="sudo yum install epel-release -y && sudo yum install clamav clamav-update clamd -y"
            ;;
        fedora)
            INSTALL_CMD="sudo dnf install clamav clamav-update clamd -y"
            ;;
        arch)
            INSTALL_CMD="sudo pacman -S clamav --noconfirm"
            ;;
        *)
            echo "[!] Unsupported OS! Install ClamAV manually."
            return 1
            ;;
    esac

    echo "Do you want to install ClamAV? (y/n)"
    read -r install_choice
    if [[ "$install_choice" =~ ^[Yy]$ ]]; then
        eval "$INSTALL_CMD"
    else
        echo "[!] ClamAV installation skipped!"
        return 1
    fi
}

# Check if ClamAV is installed, if not, install it
if ! command -v clamscan &> /dev/null; then
    echo "[!] ClamAV not found."
    install_clamav || exit 1
fi

# Start ClamAV daemon if not running
if systemctl list-units --full -all | grep -Fq "clamd.service"; then
    echo "[+] Starting ClamAV daemon..."
    sudo systemctl enable --now clamd
fi

# Define the available ClamAV scan options
declare -A scans
scans=(
    ["Quick Scan (Home Folder)"]="clamscan -r --bell ~/"
    ["Full System Scan"]="clamscan -r --bell --log=/var/log/clamav_scan.log /"
    ["Custom Directory Scan"]="custom"
    ["Scan Emails Only"]="clamscan -r --bell --include='*.eml' ~/Mail"
    ["Scan Archives & Compressed Files"]="clamscan -r --bell --scan-archive=yes ~/Downloads"
    ["Exclude System Directories"]="clamscan -r --bell --exclude-dir='/proc|/sys|/dev' /"
    ["Use ClamAV Daemon for Faster Scanning"]="clamdscan -r /"
    ["Update Virus Definitions"]="sudo freshclam"
)

# Function to display menu
display_menu() {
    echo ""
    echo "Select the type of malware scan:"
    echo "-----------------------------------"
    i=1
    for scan in "${!scans[@]}"; do
        echo "[$i] $scan"
        options[$i]="${scans[$scan]}"
        ((i++))
    done
    echo "[Q] Quit"
}

# Ask user for verbosity preference
echo "Do you want detailed output (verbose)? (y/n)"
read -r verbose_choice
if [[ "$verbose_choice" =~ ^[Yy]$ ]]; then
    VERBOSE_MODE=true
else
    VERBOSE_MODE=false
fi

# Prompt user for selection
while true; do
    display_menu
    echo -n "Enter the number of the scan to run, or Q to quit: "
    read -r input

    if [[ "$input" =~ ^[Qq]$ ]]; then
        echo "Exiting..."
        exit 0
    elif [[ "$input" =~ ^[0-9]+$ ]] && (( input > 0 && input <= ${#scans[@]} )); then
        selected_scan="${options[$input]}"
    else
        echo "[!] Invalid selection. Please try again."
        continue
    fi

    # If custom scan, prompt for directory
    if [[ "$selected_scan" == "custom" ]]; then
        echo -n "Enter the directory to scan: "
        read -r custom_dir
        selected_scan="clamscan -r --bell --log=/var/log/clamav_scan.log $custom_dir"
    fi

    # Confirm selection
    echo "-----------------------------------"
    echo "✅ Running: $selected_scan"
    echo "-----------------------------------"

    # Run the selected ClamAV scan
    LOG_FILE="/var/log/gogo-gadgetO-clamav.log"

    if [[ "$VERBOSE_MODE" == true ]]; then
        sudo $selected_scan | tee -a "$LOG_FILE"
    else
        sudo $selected_scan | tee -a "$LOG_FILE" | while read -r line; do
            echo -ne "[>] Scanning... $line\r"
        done
        echo -ne "\\n✔ Scan completed.\\n"
    fi

    echo "🎯 Scan Complete! Full logs available at: $LOG_FILE"
    exit 0
done
