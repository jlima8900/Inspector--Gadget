#!/bin/bash

# GoGoGadget Lynis Interactive Security Scanner
echo "==========================================="
echo "    🕵️ GoGoGadget Lynis Security Scanner    "
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

# Function to install Lynis based on OS
install_lynis() {
    detect_os
    echo "[+] Detected OS: $OS"

    case "$OS" in
        ubuntu|debian)
            INSTALL_CMD="sudo apt update && sudo apt install lynis -y"
            ;;
        centos|rhel|almalinux|rocky)
            INSTALL_CMD="sudo yum install epel-release -y && sudo yum install lynis -y"
            ;;
        fedora)
            INSTALL_CMD="sudo dnf install lynis -y"
            ;;
        arch)
            INSTALL_CMD="sudo pacman -S lynis --noconfirm"
            ;;
        *)
            echo "[!] Unsupported OS! Install Lynis manually."
            return 1
            ;;
    esac

    echo "Do you want to install Lynis? (y/n)"
    read -r install_choice
    if [[ "$install_choice" =~ ^[Yy]$ ]]; then
        eval "$INSTALL_CMD"
    else
        echo "[!] Lynis installation skipped!"
        return 1
    fi
}

# Check if Lynis is installed, if not, install it
if ! command -v lynis &> /dev/null; then
    echo "[!] Lynis not found."
    install_lynis || exit 1
fi

# Define the available Lynis tests
declare -A tests
tests=(
    ["Full System Audit"]="audit system"
    ["Remote System Audit"]="audit system remote"
    ["Dockerfile Security Analysis"]="audit dockerfile"
    ["Forensics Mode"]="--forensics"
    ["Pentesting Mode"]="--pentest"
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
        selected_tests="audit system,audit system remote,audit dockerfile,--forensics,--pentest"
    else
        selected_tests=""
        IFS=',' read -ra selections <<< "$input"
        for index in "${selections[@]}"; do
            if [[ "$index" =~ ^[0-9]+$ ]] && (( index > 0 && index <= ${#tests[@]} )); then
                selected_tests+="${options[$index]},"
            fi
        done
        selected_tests=${selected_tests%,}  # Remove trailing comma
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

    # Run the selected Lynis tests
    LOG_FILE="/var/log/gogo-gadgetO-lynis.log"

    # Run tests one by one for live updates
    IFS=',' read -ra TEST_ARRAY <<< "$selected_tests"
    for test in "${TEST_ARRAY[@]}"; do
        echo -ne "[>] Running: ${test}...\r"
        if [[ "$VERBOSE_MODE" == true ]]; then
            sudo lynis ${test} | tee -a "$LOG_FILE"
        else
            sudo lynis ${test} | tee -a "$LOG_FILE" | while read -r line; do
                echo -ne "[>] Running: ${test}... $line\r"
            done
            echo -ne "\n✔ ${test} completed.\n"
        fi
    done

    echo "🎯 Scan Complete! Full logs available at: $LOG_FILE"
    exit 0
done
