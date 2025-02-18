




#!/bin/bash

# ==============================
# 🔍 Advanced Security & Exposure Analysis Tool
# ==============================

# Define colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BLUE="\033[1;34m"
NC="\033[0m" # No Color

# Define CSV report files
FIREWALL_CSV="firewalld_rules.csv"
IPTABLES_CSV="iptables_rules.csv"
FAIL2BAN_CSV="fail2ban_blocked_ips.csv"
CONTAINER_CSV="container_analysis.csv"
PRIVILEGED_CSV="privileged_containers.csv"
NETWORK_CSV="network_analysis.csv"

# Clean up old reports
rm -f "$FIREWALL_CSV" "$IPTABLES_CSV" "$FAIL2BAN_CSV" "$CONTAINER_CSV" "$PRIVILEGED_CSV" "$NETWORK_CSV"

# ==============================
# 🔄 UI FUNCTIONS
# ==============================

# Spinner Animation (No Percentage Output)
spinner() {
    local pid=$1
    local message=$2
    local spin_chars=('🔵' '🟢' '🟡' '🟠' '🔴')
    local i=0

    while kill -0 $pid 2>/dev/null; do
        printf "\r%s %s..." "${spin_chars[i % ${#spin_chars[@]}]}" "$message"
        sleep 0.2
        ((i++))
    done

    printf "\r${GREEN}✔ %s Completed! ${NC}\n" "$message"
}

# ==============================
# 🚀 EXECUTION - Run Tasks in Parallel
# ==============================

echo -e "\n${GREEN}✔ Processing...${NC}\n"

# 1️⃣ Extract Fail2Ban Blocked IPs
extract_fail2ban() {
    echo "IP,Jail" > "$FAIL2BAN_CSV"
    JAILS=$(fail2ban-client status | awk -F':\t' '/Jail list:/ {gsub(/,/, "", $2); print $2}')

    for JAIL in $JAILS; do
        JAIL=$(echo "$JAIL" | xargs)
        if [[ -n "$JAIL" ]]; then
            BANNED_IPS=$(fail2ban-client status "$JAIL" | awk -F':\t' '/Banned IP list:/ {print $2}')
            if [[ -n "$BANNED_IPS" ]]; then
                for IP in $BANNED_IPS; do
                    echo "$IP,$JAIL" >> "$FAIL2BAN_CSV"
                done
            fi
        fi
    done
}

extract_firewalld() {
    echo "Port,Zone,Action" > "$FIREWALL_CSV"
    if command -v firewall-cmd &>/dev/null; then
        zones=$(firewall-cmd --get-active-zones | awk 'NR % 2 == 1')
        for zone in $zones; do
            ports=$(firewall-cmd --zone="$zone" --list-ports)
            for port in $ports; do
                echo "$port,$zone,Allow" >> "$FIREWALL_CSV"
            done
        done
    else
        echo "Firewalld not found." >> "$FIREWALL_CSV"
    fi
}

extract_iptables() {
    echo "Chain,Rule,Source,Destination,Action" > "$IPTABLES_CSV"
    iptables -L -n -v | awk '/^Chain/ {chain=$2} /^[0-9]/ {print chain","$1","$8","$9","$4}' >> "$IPTABLES_CSV" 2>/dev/null || echo "Iptables not active" >> "$IPTABLES_CSV"
}

analyze_containers() {
    echo "Container Name,Restart Policy,Image,Ports" > "$CONTAINER_CSV"
    docker ps --format "{{.Names}},{{.Image}},{{.Ports}}" | while IFS=',' read -r name image ports; do
        restart_policy=$(docker inspect --format '{{ .HostConfig.RestartPolicy.Name }}' "$name" 2>/dev/null || echo "Unknown")

        # Handle empty ports
        [[ -z "$ports" ]] && ports="N/A"

        # Proper CSV encapsulation
        echo "\"$name\",\"$restart_policy\",\"$image\",\"$ports\"" >> "$CONTAINER_CSV"
    done
}

detect_privileged_containers() {
    echo "Container Name,Privileged Mode" > "$PRIVILEGED_CSV"
    for container in $(docker ps -q); do
        privileged_status=$(docker inspect --format '{{.HostConfig.Privileged}}' "$container" 2>/dev/null || echo "false")
        container_name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null || echo "Unknown")
        [[ "$privileged_status" == "true" ]] && echo "$container_name,Yes" >> "$PRIVILEGED_CSV" || echo "$container_name,No" >> "$PRIVILEGED_CSV"
    done
}

analyze_networks() {
    echo "Network Name,Externally Accessible,Affected Containers" > "$NETWORK_CSV"
    for network in $(docker network ls --format "{{.Name}}"); do
        container_count=$(docker network inspect "$network" --format "{{json .Containers}}" | jq length 2>/dev/null || echo "0")
        [[ "$container_count" -gt 0 ]] && echo "$network,Yes,$container_count" >> "$NETWORK_CSV"
    done
}

# Execute in parallel
extract_fail2ban & fail2ban_pid=$!
extract_firewalld & firewalld_pid=$!
extract_iptables & iptables_pid=$!
analyze_containers & container_pid=$!
detect_privileged_containers & privileged_pid=$!
analyze_networks & network_pid=$!

# Show progress indicators
spinner $fail2ban_pid "Extracting Fail2Ban blocked IPs"
spinner $firewalld_pid "Extracting Firewalld rules"
spinner $iptables_pid "Extracting Iptables rules"
spinner $container_pid "Analyzing Docker containers"
spinner $privileged_pid "Checking privileged containers"
spinner $network_pid "Analyzing Docker networks"

wait  # Ensure all processes finish

echo -e "\nDone!\n"

# ==============================
# 📊 FINAL SECURITY SUMMARY
# ==============================

echo -e "\n${GREEN}✅ Security analysis completed! Reports saved:${NC}"
echo "📂 $FAIL2BAN_CSV"
echo "📂 $FIREWALL_CSV"
echo "📂 $IPTABLES_CSV"
echo "📂 $CONTAINER_CSV"
echo "📂 $PRIVILEGED_CSV"
echo "📂 $NETWORK_CSV"

echo -e "\n${GREEN}🎯 Security analysis is fully complete!${NC}"

