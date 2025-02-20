#!/bin/bash

# ==============================
# 🕵️‍♂️ GoGo-GadgetO SSH Monitor - Tracking SSH Access
# ==============================

# Define colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
RED="\033[1;31m"
NC="\033[0m" # No Color

# Define the SSH activity log file
SSH_REPORT="ssh_activity_report.csv"

# Header Display
clear
echo -e "${BLUE}┌──────────────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│  🕵️‍♂️ GoGo-GadgetO SSH Monitor - Tracking SSH Access  │${NC}"
echo -e "${BLUE}│  🔍 Scanning Active & Past SSH Connections...       │${NC}"
echo -e "${BLUE}└──────────────────────────────────────────────────────┘${NC}\n"

# ==============================
# 🔎 CHECKING ACTIVE SSH CONNECTIONS
# ==============================
echo -e "🔎 ${YELLOW}Checking active SSH connections...${NC}\n"

ACTIVE_SESSIONS=$(who | awk '{print $1,$5}' | sed 's/[()]//g' | sort | uniq -c)

if [[ -z "$ACTIVE_SESSIONS" ]]; then
    echo -e "🛑 No active SSH sessions found.\n"
else
    echo -e "🟢 ${GREEN}Currently Active SSH Sessions:${NC}"
    echo "┌──────────┬───────────────────┐"
    echo "│  Count   │ IP Address        │"
    echo "├──────────┼───────────────────┤"
    echo "$ACTIVE_SESSIONS" | awk '{printf "│ %-8s │ %-17s │\n", $1, $3}'
    echo "└──────────┴───────────────────┘"
fi

# ==============================
# 📜 ANALYZING PAST SSH LOGINS
# ==============================
echo -e "\n📜 ${YELLOW}Analyzing past SSH login attempts...${NC}\n"

# Define log file (varies between distros)
LOG_FILE="/var/log/auth.log"
[[ ! -f "$LOG_FILE" ]] && LOG_FILE="/var/log/secure"

# Ensure the log file exists
if [[ ! -f "$LOG_FILE" ]]; then
    echo -e "🟡 No SSH logins detected in the past 30 days.\n"
else
    # Extract successful SSH logins in the last 30 days
    LAST_30_DAYS=$(grep "Accepted password" "$LOG_FILE" | awk '{print $(NF-3),$1,$2,$3}' | sort)

    # Output CSV header
    echo "IP Address, Connection Count, Last Connection Time" > "$SSH_REPORT"

    if [[ -z "$LAST_30_DAYS" ]]; then
        echo -e "🟡 No successful SSH logins in the past 30 days.\n"
    else
        echo -e "📊 ${GREEN}SSH Login Summary (Last 30 Days):${NC}"
        echo "┌──────────┬───────────────────┬───────────────────────┐"
        echo "│  Count   │ IP Address        │ Last Connection Time  │"
        echo "├──────────┼───────────────────┼───────────────────────┤"

        # Process and group data
        echo "$LAST_30_DAYS" | awk '
        {
            ip = $1
            timestamp = $2 " " $3 " " $4
            count[ip]++
            last_seen[ip] = timestamp
        }
        END {
            for (ip in count) {
                printf "│ %-8s │ %-17s │ %-21s │\n", count[ip], ip, last_seen[ip]
                print ip "," count[ip] "," last_seen[ip] >> "'"$SSH_REPORT"'"
            }
        }'

        echo "└──────────┴───────────────────┴───────────────────────┘"
    fi
fi

# ==============================
# 🎯 COMPLETION MESSAGE
# ==============================
echo -e "\n${GREEN}✅ SSH Activity Analysis Complete!${NC}"
echo -e "📂 Report saved: ${BLUE}$SSH_REPORT${NC}\n"
