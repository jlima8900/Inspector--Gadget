#!/bin/bash

# ==============================
#  🛡️ GoGo-GadgetO Vault - Secure Encryption & Keeper Storage
#  🚀 Locks down reports & stores them safely!
# ==============================

# Define Colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BLUE="\033[1;34m"
NC="\033[0m"

# Define Report Files
REPORTS=("firewalld_rules.csv" "iptables_rules.csv" "fail2ban_blocked_ips.csv" \
         "container_analysis.csv" "privileged_containers.csv" "network_analysis.csv")

# Generate Timestamp for Unique Naming
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
ENCRYPTED_FILE="secure_reports_${TIMESTAMP}.tar.gpg"

# ASCII Art for Gadget Vibes
echo -e "${BLUE}"
echo "┌────────────────────────────────────────────────────────┐"
echo "│  🛡️ GoGo-GadgetO Vault - The Ultimate Security Lock 🔐 │"
echo "│  🚀 Encrypting & Storing Inspector-Gadget Reports...  │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# Generate a 20-character Secure Passphrase
PASSPHRASE=$(openssl rand -base64 20 | tr -d '\n')

# ==============================
# 🔄 Check if Reports Exist
# ==============================
echo -e "\n${YELLOW}🔎 Scanning for reports...${NC}"
MISSING=false
for FILE in "${REPORTS[@]}"; do
    if [[ ! -f "$FILE" ]]; then
        echo -e "${RED}❌ Missing: $FILE${NC}"
        MISSING=true
    fi
done

if [[ "$MISSING" == true ]]; then
    echo -e "${RED}⚠️ Some reports are missing. Ensure Inspector-Gadget has been run before encrypting.${NC}"
    exit 1
fi

# ==============================
# 🔐 Encrypt Reports with GPG
# ==============================
echo -e "\n${BLUE}🔐 Engaging GadgetO Encryption...${NC}"

# Create a tar archive
tar -cf "secure_reports_${TIMESTAMP}.tar" "${REPORTS[@]}"

# Encrypt the tar archive with GPG
gpg --batch --symmetric --cipher-algo AES256 --passphrase "$PASSPHRASE" -o "$ENCRYPTED_FILE" "secure_reports_${TIMESTAMP}.tar"

# Cleanup Unencrypted Tar File
rm -f "secure_reports_${TIMESTAMP}.tar"

if [[ -f "$ENCRYPTED_FILE" ]]; then
    echo -e "${GREEN}✅ Reports securely locked inside $ENCRYPTED_FILE${NC}"
else
    echo -e "${RED}❌ Encryption failed!${NC}"
    exit 1
fi

# ==============================
# 🔑 Store in Keeper Vault (Auto Detect CLI)
# ==============================

echo -e "\n${BLUE}🔑 Transmitting encrypted reports to Keeper Vault...${NC}"

# Detect if `ksm` or `keeper` is available
if command -v ksm &>/dev/null; then
    KEEPER_CLI="ksm"
elif command -v keeper &>/dev/null; then
    KEEPER_CLI="keeper"
else
    echo -e "${RED}❌ Neither 'ksm' nor 'keeper' CLI found! Install Keeper Commander.${NC}"
    exit 1
fi

# Keeper record details
KEEPER_RECORD_NAME="Inspector-Gadget Secure Reports - $TIMESTAMP"
KEEPER_FOLDER="Security Reports"

# Step 1: Create a new Keeper record for each timestamped report
RECORD_UID=$($KEEPER_CLI record-create --title "$KEEPER_RECORD_NAME" --folder "$KEEPER_FOLDER" \
    --field type=login title="Inspector-Gadget" \
    --field type=password password="$PASSPHRASE" \
    --custom "Description=Encrypted Security Reports from Inspector-Gadget ($TIMESTAMP)" \
    --output json | jq -r '.recordUid')

if [[ -z "$RECORD_UID" || "$RECORD_UID" == "null" ]]; then
    echo -e "${RED}❌ Failed to create Keeper record.${NC}"
    exit 1
fi

# Step 2: Upload the encrypted report to Keeper as an attachment
$KEEPER_CLI record-append "$RECORD_UID" --file "$ENCRYPTED_FILE"

if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}✅ Encrypted reports stored in Keeper Vault!${NC}"
else
    echo -e "${RED}❌ Failed to store reports in Keeper Vault.${NC}"
    exit 1
fi

# ==============================
# 🔑 Display Passphrase to User
# ==============================
echo -e "\n${YELLOW}🔑 GadgetO Passphrase (Do NOT lose it!):${NC}"
echo -e "${GREEN}$PASSPHRASE${NC}"

# ==============================
# 🎯 Completion Message
# ==============================
echo -e "\n${GREEN}🎯 Vault Secured! Reports are encrypted & stored safely! 🔒${NC}"
echo -e "${BLUE}🔍 Retrieve your passphrase & reports using Keeper Commander.${NC}"

exit 0
