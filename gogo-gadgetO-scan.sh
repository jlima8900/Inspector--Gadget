#!/bin/bash

# ==============================
# 🚀 GoGo-Gadget-Scan - Security Enhancements Module
# ==============================

# This script extends Inspector-Gadget with additional reporting features.
# 🚨 It does NOT modify firewall rules, containers, or system settings.
# ✅ Strictly read-only.

# ==============================
# 🔄 Security Scan History Tracking
# ==============================
log_scan_history() {
    SCAN_LOG="scan_history.log"
    echo "[$(date)] Security scan completed." >> "$SCAN_LOG"
    echo "📜 Security scan logged in $SCAN_LOG"
}

# ==============================
# 🚨 Dynamic Security Risk Score Calculation
# ==============================

calculate_risk_score() {
    echo "📊 Calculating Security Risk Score..."

    # Ensure numerical values (default to 0 if empty)
    PRIVILEGED_CONTAINERS=$(grep -c ",Yes$" privileged_containers.csv 2>/dev/null)
    HIGH_RISK_PORTS=$(grep -E "9000|23|3389" firewalld_rules.csv 2>/dev/null | wc -l)
    TOTAL_PORTS=$(awk -F ',' 'NR>1 {count++} END {print count+0}' firewalld_rules.csv 2>/dev/null)
    NETWORK_EXPOSURES=$(awk -F ',' '$2 ~ /Yes/ {count++} END {print count+0}' network_analysis.csv 2>/dev/null)

    # Convert potential empty values explicitly to zero
    PRIVILEGED_CONTAINERS=$(( ${PRIVILEGED_CONTAINERS:-0} ))
    HIGH_RISK_PORTS=$(( ${HIGH_RISK_PORTS:-0} ))
    TOTAL_PORTS=$(( ${TOTAL_PORTS:-0} ))
    NETWORK_EXPOSURES=$(( ${NETWORK_EXPOSURES:-0} ))

    # Ensure minimum safe values
    (( TOTAL_PORTS < 1 )) && TOTAL_PORTS=1  # Avoid division by zero

    # Calculate Excessive Open Ports (Only penalize if >5 open ports)
    NON_STANDARD_PORTS=$(( TOTAL_PORTS > 5 ? TOTAL_PORTS - 5 : 0 ))

    # 🚀 Dynamic Weight Scaling
    PRIV_WEIGHT=15
    HIGH_PORT_WEIGHT=10
    NON_STANDARD_PORT_WEIGHT=5
    NETWORK_EXP_WEIGHT=10

    TOTAL_RISKS=$(( PRIVILEGED_CONTAINERS + HIGH_RISK_PORTS + NON_STANDARD_PORTS + NETWORK_EXPOSURES ))

    # Adjust weight dynamically based on total risks
    if (( TOTAL_RISKS > 10 )); then
        PRIV_WEIGHT=10
        HIGH_PORT_WEIGHT=7
        NON_STANDARD_PORT_WEIGHT=3
        NETWORK_EXP_WEIGHT=7
    elif (( TOTAL_RISKS > 20 )); then
        PRIV_WEIGHT=7
        HIGH_PORT_WEIGHT=5
        NON_STANDARD_PORT_WEIGHT=2
        NETWORK_EXP_WEIGHT=5
    fi

    # Apply Risk Score Calculation
    RISK_SCORE=$((
        (PRIVILEGED_CONTAINERS * PRIV_WEIGHT) +
        (HIGH_RISK_PORTS * HIGH_PORT_WEIGHT) +
        (NON_STANDARD_PORTS * NON_STANDARD_PORT_WEIGHT) +
        (NETWORK_EXPOSURES * NETWORK_EXP_WEIGHT)
    ))

    # **Ensure Scoring is Out of 100%**
    MAX_SCORE=$(( TOTAL_RISKS * 15 + 1 ))  # Avoid division by zero
    SECURITY_SCORE=$(( 100 - (RISK_SCORE * 100 / MAX_SCORE) ))

    # Ensure score remains within logical bounds
    (( SECURITY_SCORE > 100 )) && SECURITY_SCORE=100
    (( SECURITY_SCORE < 0 )) && SECURITY_SCORE=0

    # Print Breakdown
    echo "🔎 Risk Breakdown:"
    echo "  🛑 Privileged Containers: $PRIVILEGED_CONTAINERS (x$PRIV_WEIGHT pts each)"
    echo "  🔥 High-Risk Ports: $HIGH_RISK_PORTS (x$HIGH_PORT_WEIGHT pts each)"
    echo "  🌍 External Network Exposures: $NETWORK_EXPOSURES (x$NETWORK_EXP_WEIGHT pts each)"
    echo "  🚪 Excessive Open Ports: $NON_STANDARD_PORTS (x$NON_STANDARD_PORT_WEIGHT pts each)"
    echo "🟢 Final Security Score: $SECURITY_SCORE% Secure (100% = Fully Secured)"
}


# ==============================
# 🛑 Firewall & Iptables Analysis (Read-Only)
# ==============================
analyze_firewall_rules() {
    FIREWALL_LOG="firewall_analysis.log"
    echo "🔍 Analyzing firewall rules... (results in $FIREWALL_LOG)"
    echo "🚧 Firewall Analysis - $(date)" > "$FIREWALL_LOG"

    HIGH_RISK_PORTS=$(grep -E "9000|23|3389" firewalld_rules.csv 2>/dev/null)
    if [[ -n "$HIGH_RISK_PORTS" ]]; then
        echo "⚠️ High-Risk Ports Detected:" >> "$FIREWALL_LOG"
        echo "$HIGH_RISK_PORTS" >> "$FIREWALL_LOG"
    else
        echo "✅ No high-risk ports found." >> "$FIREWALL_LOG"
    fi

    MEDIUM_RISK_PORTS=$(grep -E "25|5900" firewalld_rules.csv 2>/dev/null)
    if [[ -n "$MEDIUM_RISK_PORTS" ]]; then
        echo "⚠️ Medium-Risk Ports Detected:" >> "$FIREWALL_LOG"
        echo "$MEDIUM_RISK_PORTS" >> "$FIREWALL_LOG"
    else
        echo "✅ No medium-risk ports found." >> "$FIREWALL_LOG"
    fi
}

# ==============================
# 📊 Structured ASCII Table Output
# ==============================

display_security_summary() {
    echo "📊 Displaying Security Summary..."

    # Define maximum lengths for trimming names
    MAX_NAME_LENGTH=24
    MAX_NETWORK_LENGTH=24

    # Create temporary files for side-by-side display
    PRIVILEGED_TEMP=$(mktemp)
    NETWORK_TEMP=$(mktemp)

    # 🛑 Privileged Containers Output (Boxed)
    {
        printf "┌────────────────────────────┬──────────────────┐\n"
        printf "│ 🛑 Privileged Containers   │ Privileged Mode  │\n"
        printf "├────────────────────────────┼──────────────────┤\n"
        awk -F ',' -v max_len="$MAX_NAME_LENGTH" 'NR>1 {printf "│ %-26s │ %-16s │\n", substr($1, 1, max_len), $2}' privileged_containers.csv
        printf "└────────────────────────────┴──────────────────┘\n"
    } > "$PRIVILEGED_TEMP"

    # 🌍 Network Exposure Analysis Output (Boxed) with manually adjusted column widths
    {
        printf "┌────────────────────────────┬───────────┬──────────────┐\n"
        printf "│ 🌍 Network Exposure        │ Exposed   │ Containers   │\n"
        printf "├────────────────────────────┼───────────┼──────────────┤\n"
        awk -F ',' -v max_len="$MAX_NETWORK_LENGTH" 'NR>1 {printf "│ %-26s │ %-9s │ %-12s │\n", substr($1, 1, max_len), $2, $3}' network_analysis.csv
        printf "└────────────────────────────┴───────────┴──────────────┘\n"
    } > "$NETWORK_TEMP"

    # Merge both tables side by side while preserving spacing
    paste -d '  ' "$PRIVILEGED_TEMP" "$NETWORK_TEMP"

    # Clean up temp files
    rm -f "$PRIVILEGED_TEMP" "$NETWORK_TEMP"
}

# ==============================
# 🚀 Run All Enhancements
# ==============================
run_enhancements() {
    log_scan_history
    analyze_firewall_rules
    display_security_summary
    calculate_risk_score
}
