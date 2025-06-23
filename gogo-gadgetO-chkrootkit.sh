#!/bin/bash

# GoGoGadget Chkrootkit Security Scanner
echo "==========================================="
echo "    🕵️ GoGoGadget Chkrootkit Security Scanner    "
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

# Function to install Chkrootkit based on OS
install_chkrootkit() {
    detect_os
    echo "[+] Detected OS: $OS"

    case "$OS" in
        ubuntu|debian)
            INSTALL_CMD="sudo apt update && sudo apt install chkrootkit -y"
            ;;
        centos|rhel|almalinux|rocky)
            INSTALL_CMD="sudo yum install epel-release -y && sudo yum install chkrootkit -y"
            ;;
        fedora)
            INSTALL_CMD="sudo dnf install chkrootkit -y"
            ;;
        arch)
            INSTALL_CMD="sudo pacman -S chkrootkit --noconfirm"
            ;;
        *)
            echo "[!] Unsupported OS! Install Chkrootkit manually."
            return 1
            ;;
    esac

    echo "Do you want to install Chkrootkit? (y/n)"
    read -r install_choice
    if [[ "$install_choice" =~ ^[Yy]$ ]]; then
        eval "$INSTALL_CMD"
    else
        echo "[!] Chkrootkit installation skipped!"
        return 1
    fi
}

# Locate Chkrootkit binary
CHKROOTKIT_PATH=$(command -v chkrootkit)

# If Chkrootkit is not in $PATH, manually find it
if [[ -z "$CHKROOTKIT_PATH" ]]; then
    echo "[!] Chkrootkit not found in system PATH. Searching manually..."
    for dir in /usr/sbin /usr/local/bin /usr/local/sbin /sbin /bin; do
        if [[ -x "$dir/chkrootkit" ]]; then
            CHKROOTKIT_PATH="$dir/chkrootkit"
            break
        fi
    done
fi

# If still not found, install it
if [[ -z "$CHKROOTKIT_PATH" ]]; then
    echo "[!] Chkrootkit not found."
    install_chkrootkit || exit 1
    CHKROOTKIT_PATH=$(command -v chkrootkit)
    if [[ -z "$CHKROOTKIT_PATH" ]]; then
        echo "[!] Chkrootkit installation failed. Exiting."
        exit 1
    fi
fi

# Add Chkrootkit path to $PATH if it's not already included
CHKROOTKIT_DIR=$(dirname "$CHKROOTKIT_PATH")
if [[ ":$PATH:" != *":$CHKROOTKIT_DIR:"* ]]; then
    echo "[+] Adding $CHKROOTKIT_DIR to PATH"
    export PATH="$CHKROOTKIT_DIR:$PATH"
fi

# Define the available Chkrootkit tests
declare -A tests
tests=(
    ["Full Rootkit Scan"]=""
    ["Hidden Processes Check"]="-p"
    ["Network Sniffer Check"]="-s"
    ["Login Backdoor Check"]="-l"
    ["Malicious Cronjob Check"]="-c"
    ["Suspicious Kernel Modules"]="-m"
)

# Function to display menu
display_menu() {
    echo ""
    echo "Select the type of security scan:"
    echo "-----------------------------------"
    i=1
    for test in "${!tests[@]}"; do
        echo "[$i] $test"
        options[$i]="${tests[$test]}"
        ((i++))
    done
    echo "[A] Run All Tests"
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
    echo -n "Enter the number(s) of the checks to run (comma-separated), A for all, or Q to quit: "
    read -r input

    if [[ "$input" =~ ^[Qq]$ ]]; then
        echo "Exiting..."
        exit 0
    elif [[ "$input" =~ ^[Aa]$ ]]; then
        selected_tests=""
        for key in "${!tests[@]}"; do
            selected_tests+="${tests[$key]} "
        done
    else
        selected_tests=""
        IFS=',' read -ra selections <<< "$input"
        for index in "${selections[@]}"; do
            if [[ "$index" =~ ^[0-9]+$ ]] && (( index > 0 && index <= ${#tests[@]} )); then
                selected_tests+="${options[$index]} "
            fi
        done
    fi

    # If no valid selection, loop again
    if [[ -z "$selected_tests" ]]; then
        echo "[!] Invalid selection. Please try again."
        continue
    fi

    # Confirm selection
    echo "-----------------------------------"
    echo "✅ Running selected checks: $selected_tests"
    echo "-----------------------------------"

    # Run the selected Chkrootkit tests
    LOG_FILE="/var/log/gogo-gadgetO-chkrootkit.log"

    # Run tests one by one for live updates
    echo "[>] Running: $CHKROOTKIT_PATH $selected_tests..."
    if [[ "$VERBOSE_MODE" == true ]]; then
        sudo "$CHKROOTKIT_PATH" $selected_tests | tee -a "$LOG_FILE"
    else
        sudo "$CHKROOTKIT_PATH" $selected_tests | tee -a "$LOG_FILE" | while read -r line; do
            echo -ne "[>] Running: chkrootkit... $line\r"
        done
        echo -ne "\n✔ Chkrootkit scan completed.\n"
    fi

    echo "🎯 Scan Complete! Full logs available at: $LOG_FILE"
    exit 0
done
