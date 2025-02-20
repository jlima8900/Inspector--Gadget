#!/bin/bash

# ==============================
# 🕵️‍♂️ GoGo-GadgetO Sentinel - SSH Security Log Analysis
# ==============================

# Define colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
RED="\033[1;31m"
NC="\033[0m" # No Color

# Define log files (include rotated logs)
LOG_FILES=("/var/log/secure" "/var/log/secure.1" "/var/log/secure-*.gz")

# Define report file
REPORT_FILE="gogo-gadgetO-sentinel.csv"

# ==============================
# 🔄 USER INPUT: Timeframe & IP Limit
# ==============================
echo -e "${BLUE}Select timeframe for analysis:${NC}"
echo -e "1) Last 24 hours"
echo -e "2) Last 7 days"
echo -e "3) Last 30 days"
echo -ne "Enter your choice (1/2/3): "
read TIME_OPTION

# Convert selection to days
case $TIME_OPTION in
    1) TIME_FILTER=$(date --date="1 day ago" "+%b %_d") ;;
    2) TIME_FILTER=$(date --date="7 days ago" "+%b %_d") ;;
    3)
        START_DATE=$(date --date="30 days ago" "+%b %_d")
        END_DATE=$(date "+%b %_d")  # Today
        # echo -e "${YELLOW}DEBUG: Searching logs from '$START_DATE' to '$END_DATE'${NC}"  # Debug (commented)

        # Capture entries for all days in the last 30 days
        > failed_attempts.tmp  # Clear previous results
        for LOG_FILE in "${LOG_FILES[@]}"; do
            if [[ -f $LOG_FILE ]]; then
                if [[ $LOG_FILE == *.gz ]]; then
                    zgrep "Failed password" "$LOG_FILE" | awk -v start="$START_DATE" -v end="$END_DATE" \
                        '$0 ~ start || $0 ~ end' >> failed_attempts.tmp
                else
                    grep "Failed password" "$LOG_FILE" | awk -v start="$START_DATE" -v end="$END_DATE" \
                        '$0 ~ start || $0 ~ end' >> failed_attempts.tmp
                fi
            fi
        done
        ;;
    *)
        echo -e "${RED}Invalid option! Defaulting to last 30 days.${NC}"
        TIME_OPTION=3
        ;;
esac

echo -ne "${BLUE}How many top IPs to display? (default: 5): ${NC}"
read TOP_IPS
TOP_IPS=${TOP_IPS:-5}  # Default to 5 if no input

# ==============================
# 🔎 Extract & Process SSH Failures
# ==============================

echo -e "\n🔎 ${YELLOW}Analyzing SSH failed login attempts...${NC}"

# Search all relevant log files (handles rotated logs)
> failed_ips.tmp  # Clear previous results
for LOG_FILE in "${LOG_FILES[@]}"; do
    if [[ -f $LOG_FILE ]]; then
        if [[ $LOG_FILE == *.gz ]]; then
            zgrep "Failed password" "$LOG_FILE" | awk '{print $(NF-3)}' >> failed_ips.tmp
        else
            grep "Failed password" "$LOG_FILE" | awk '{print $(NF-3)}' >> failed_ips.tmp
        fi
    fi
done

# Count failed attempts and sort
sort failed_ips.tmp | uniq -c | sort -nr | head -n "$TOP_IPS" > failed_ips_sorted.tmp

# Check if there are failed attempts
if [[ ! -s failed_ips_sorted.tmp ]]; then
    echo -e "🟡 ${YELLOW}No failed SSH attempts found in the selected timeframe.${NC}"
    rm -f failed_ips.tmp failed_ips_sorted.tmp
    exit 0
fi

# Output CSV header
echo "TOR Status,Attempts,IP Address,Last Seen,Location" > "$REPORT_FILE"

# ==============================
# 🌍 Geolocation & TOR Detection
# ==============================

declare -A GEO_CACHE
while read -r COUNT IP; do
    # TOR detection (DNS query) - First column
    TOR_STATUS=$(dig +short -t a "$IP".dnsel.torproject.org @8.8.8.8 | grep -q "127.0.0.2" && echo "TOR Exit" || echo "Non-TOR")

    # Extract last seen timestamp (search all log files)
    LAST_SEEN="Unknown"
    for LOG_FILE in "${LOG_FILES[@]}"; do
        if [[ -f $LOG_FILE ]]; then
            if [[ $LOG_FILE == *.gz ]]; then
                LAST_FOUND=$(zgrep "$IP" "$LOG_FILE" | grep "Failed password" | tail -1 | awk '{print $1, $2, $3}')
            else
                LAST_FOUND=$(grep "$IP" "$LOG_FILE" | grep "Failed password" | tail -1 | awk '{print $1, $2, $3}')
            fi
            [[ -n $LAST_FOUND ]] && LAST_SEEN="$LAST_FOUND"
        fi
    done

    # Geolocation lookup (caching to avoid duplicate API calls)
    if [[ -z "${GEO_CACHE[$IP]}" ]]; then
        GEO_JSON=$(curl -s -m 5 "http://ipinfo.io/$IP/json")
        CITY=$(echo "$GEO_JSON" | jq -r '.city // "Unknown"')
        REGION=$(echo "$GEO_JSON" | jq -r '.region // "Unknown"')
        COUNTRY=$(echo "$GEO_JSON" | jq -r '.country // "Unknown"')

        if [[ "$CITY" == "Unknown" && "$REGION" == "Unknown" && "$COUNTRY" == "Unknown" ]]; then
            LOCATION="Lookup Failed"
        else
            LOCATION="$CITY, $REGION, $COUNTRY"
        fi
        GEO_CACHE[$IP]="$LOCATION"
    fi

    LOCATION="${GEO_CACHE[$IP]}"

    # Save to CSV with new column order
    echo "$TOR_STATUS,$COUNT,$IP,$LAST_SEEN,\"$LOCATION\"" >> "$REPORT_FILE"

done < failed_ips_sorted.tmp

rm -f failed_ips.tmp failed_ips_sorted.tmp  # Cleanup temp files

# ==============================
# ✅ DISPLAY USING CSVTOOL + COLUMN FORMATTING
# ==============================

echo -e "\n📊 ${GREEN}Top $TOP_IPS IPs with failed SSH attempts:${NC}"
csvtool col 1-5 "$REPORT_FILE" | column -s, -t

# ==============================
# ✅ COMPLETION MESSAGE
# ==============================

echo -e "\n${GREEN}✅ SSH Security Analysis Complete!${NC}"
echo -e "📂 Report saved: ${BLUE}$REPORT_FILE${NC}\n"
