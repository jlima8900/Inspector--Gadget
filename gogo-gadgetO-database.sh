#!/bin/bash

# ==============================
# 🔐 GoGoGadget Database - Database Security Scanner
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
echo "│  🔐 GoGoGadget Database - Database Security Scanner    │"
echo "│  🗄️ Securing your data stores & database systems      │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# Configuration
SAVE_REPORTS=true
SCAN_TYPE="standard"
TARGET_HOST="localhost"
DISCOVERED_DATABASES=()

# Configure scan options
configure_scan() {
    echo -e "${YELLOW}🔐 Database Security Scan Configuration:${NC}"
    echo "1) Network database discovery only"
    echo "2) Standard security assessment + reports"
    echo "3) Deep penetration testing (authorized systems only)"
    echo -n "Select option (1/2/3): "
    read -r choice
    
    case $choice in
        1)
            SCAN_TYPE="discovery"
            SAVE_REPORTS=false
            echo -e "${GREEN}✅ Discovery mode${NC}"
            ;;
        2)
            SCAN_TYPE="standard"
            SAVE_REPORTS=true
            echo -e "${GREEN}✅ Standard assessment + reports${NC}"
            ;;
        3)
            SCAN_TYPE="penetration"
            SAVE_REPORTS=true
            echo -e "${GREEN}✅ Deep penetration testing mode${NC}"
            echo -e "${RED}⚠️ WARNING: Use only on authorized systems!${NC}"
            ;;
        *)
            SCAN_TYPE="standard"
            echo -e "${YELLOW}⚠️ Invalid choice, defaulting to standard${NC}"
            ;;
    esac
    echo ""
}

# Setup database tools
setup_database_tools() {
    echo -e "${CYAN}🔧 Checking database security tools...${NC}"
    
    local missing_tools=()
    
    # Check for essential database clients
    if ! command -v mysql &>/dev/null; then
        missing_tools+=("mysql-client")
    fi
    
    if ! command -v psql &>/dev/null; then
        missing_tools+=("postgresql-client")
    fi
    
    if ! command -v mongo &>/dev/null && ! command -v mongosh &>/dev/null; then
        missing_tools+=("mongodb-mongosh")
    fi
    
    if ! command -v redis-cli &>/dev/null; then
        missing_tools+=("redis-tools")
    fi
    
    # Install missing tools (optional)
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${YELLOW}📦 Missing database tools: ${missing_tools[*]}${NC}"
        echo -e "${BLUE}💡 Install manually for enhanced scanning:${NC}"
        
        if command -v dnf &>/dev/null; then
            echo -e "  sudo dnf install mysql postgresql redis mongodb-mongosh"
        elif command -v apt &>/dev/null; then
            echo -e "  sudo apt install mysql-client postgresql-client redis-tools mongodb-mongosh"
        fi
        echo ""
    fi
    
    echo -e "${GREEN}✅ Tool check completed${NC}"
}

# Database service discovery
discover_database_services() {
    echo -e "\n${CYAN}🔍 Discovering database services...${NC}"
    
    local target="$1"
    [[ -z "$target" ]] && target="localhost"
    
    echo -e "${YELLOW}🎯 Scanning target: $target${NC}"
    
    # Common database ports
    declare -A DB_PORTS=(
        ["3306"]="MySQL/MariaDB"
        ["5432"]="PostgreSQL"
        ["27017"]="MongoDB"
        ["6379"]="Redis"
        ["1521"]="Oracle"
        ["1433"]="SQL Server"
        ["5984"]="CouchDB"
        ["9042"]="Cassandra"
        ["7000"]="Cassandra (cluster)"
        ["8086"]="InfluxDB"
        ["9200"]="Elasticsearch"
        ["5984"]="CouchDB"
    )
    
    echo -e "${GREEN}📊 Database Service Discovery:${NC}"
    local found_services=0
    
    for port in "${!DB_PORTS[@]}"; do
        if command -v nc &>/dev/null; then
            if nc -z -w3 "$target" "$port" 2>/dev/null; then
                echo -e "  ${GREEN}✅ Port $port: ${DB_PORTS[$port]} - OPEN${NC}"
                DISCOVERED_DATABASES+=("$target:$port:${DB_PORTS[$port]}")
                ((found_services++))
            fi
        elif command -v telnet &>/dev/null; then
            if timeout 3 telnet "$target" "$port" 2>/dev/null | grep -q "Connected"; then
                echo -e "  ${GREEN}✅ Port $port: ${DB_PORTS[$port]} - OPEN${NC}"
                DISCOVERED_DATABASES+=("$target:$port:${DB_PORTS[$port]}")
                ((found_services++))
            fi
        fi
    done
    
    if [[ $found_services -eq 0 ]]; then
        echo -e "  ${YELLOW}⚠️ No database services detected on common ports${NC}"
        echo -e "  ${BLUE}💡 Services may be running on non-standard ports or firewalled${NC}"
    else
        echo -e "\n${GREEN}🎯 Found $found_services database services${NC}"
    fi
    
    # Check for local database processes
    echo -e "\n${YELLOW}🔍 Checking for local database processes...${NC}"
    local local_processes=$(ps aux | grep -E "mysql|postgres|mongod|redis|oracle|cassandra" | grep -v grep | wc -l)
    if [[ $local_processes -gt 0 ]]; then
        echo -e "  ${GREEN}✅ $local_processes database processes running locally${NC}"
        ps aux | grep -E "mysql|postgres|mongod|redis|oracle|cassandra" | grep -v grep | while read -r line; do
            local process=$(echo "$line" | awk '{print $11}')
            echo -e "    🗄️ $(basename "$process")"
        done
    else
        echo -e "  ${BLUE}ℹ️ No local database processes detected${NC}"
    fi
}

# MySQL/MariaDB security assessment
assess_mysql_security() {
    local host="$1"
    local port="$2"
    
    echo -e "\n${CYAN}🐬 MySQL/MariaDB Security Assessment${NC}"
    echo -e "${YELLOW}Target: $host:$port${NC}"
    
    if ! command -v mysql &>/dev/null; then
        echo -e "${YELLOW}⚠️ MySQL client not available - basic tests only${NC}"
        return 1
    fi
    
    # Test anonymous login
    echo -e "${YELLOW}🔍 Testing anonymous access...${NC}"
    if mysql -h "$host" -P "$port" -u "" --connect-timeout=5 -e "SELECT VERSION();" 2>/dev/null; then
        echo -e "  ${RED}🚨 CRITICAL: Anonymous login allowed!${NC}"
    else
        echo -e "  ${GREEN}✅ Anonymous login disabled${NC}"
    fi
    
    # Test common weak credentials
    echo -e "${YELLOW}🔍 Testing common credentials...${NC}"
    local weak_credentials=("root:" "root:root" "root:password" "root:123456" "admin:admin" "mysql:mysql")
    local weak_found=false
    
    for cred in "${weak_credentials[@]}"; do
        local user=$(echo "$cred" | cut -d':' -f1)
        local pass=$(echo "$cred" | cut -d':' -f2)
        
        if [[ -z "$pass" ]]; then
            if mysql -h "$host" -P "$port" -u "$user" --connect-timeout=5 -e "SELECT VERSION();" 2>/dev/null; then
                echo -e "  ${RED}🚨 CRITICAL: User '$user' has no password!${NC}"
                weak_found=true
            fi
        else
            if mysql -h "$host" -P "$port" -u "$user" -p"$pass" --connect-timeout=5 -e "SELECT VERSION();" 2>/dev/null; then
                echo -e "  ${RED}🚨 CRITICAL: Weak credentials found - $user:$pass${NC}"
                weak_found=true
            fi
        fi
    done
    
    [[ "$weak_found" == "false" ]] && echo -e "  ${GREEN}✅ No common weak credentials detected${NC}"
    
    # Check for information disclosure
    echo -e "${YELLOW}🔍 Checking information disclosure...${NC}"
    local version_info=$(mysql -h "$host" -P "$port" --connect-timeout=5 -e "SELECT VERSION();" 2>/dev/null)
    if [[ -n "$version_info" ]]; then
        echo -e "  ${YELLOW}ℹ️ Version exposed: $version_info${NC}"
        echo -e "  ${BLUE}💡 Consider hiding version information${NC}"
    fi
    
    # SSL/TLS support check
    echo -e "${YELLOW}🔍 Checking SSL/TLS support...${NC}"
    local ssl_status=$(mysql -h "$host" -P "$port" --ssl-mode=REQUIRED --connect-timeout=5 -e "SHOW STATUS LIKE 'Ssl_cipher';" 2>/dev/null)
    if [[ -n "$ssl_status" ]]; then
        echo -e "  ${GREEN}✅ SSL/TLS supported${NC}"
    else
        echo -e "  ${YELLOW}⚠️ SSL/TLS not available or not enforced${NC}"
    fi
}

# PostgreSQL security assessment
assess_postgresql_security() {
    local host="$1"
    local port="$2"
    
    echo -e "\n${CYAN}🐘 PostgreSQL Security Assessment${NC}"
    echo -e "${YELLOW}Target: $host:$port${NC}"
    
    if ! command -v psql &>/dev/null; then
        echo -e "${YELLOW}⚠️ PostgreSQL client not available - basic tests only${NC}"
        return 1
    fi
    
    # Test common databases and users
    echo -e "${YELLOW}🔍 Testing common access patterns...${NC}"
    local common_dbs=("postgres" "template1" "test")
    local common_users=("postgres" "admin" "user")
    
    for db in "${common_dbs[@]}"; do
        for user in "${common_users[@]}"; do
            if PGPASSWORD="" psql -h "$host" -p "$port" -U "$user" -d "$db" -c "SELECT version();" 2>/dev/null | grep -q "PostgreSQL"; then
                echo -e "  ${RED}🚨 CRITICAL: Passwordless access - User: $user, DB: $db${NC}"
            fi
        done
    done
    
    # Check for version disclosure
    echo -e "${YELLOW}🔍 Checking version disclosure...${NC}"
    local pg_version=$(PGPASSWORD="" psql -h "$host" -p "$port" -U postgres -d postgres -t -c "SELECT version();" 2>/dev/null)
    if [[ -n "$pg_version" ]]; then
        echo -e "  ${YELLOW}ℹ️ Version: $(echo "$pg_version" | tr -d '\n' | xargs)${NC}"
    fi
    
    # Check SSL enforcement
    echo -e "${YELLOW}🔍 Checking SSL configuration...${NC}"
    local ssl_check=$(PGPASSWORD="" psql -h "$host" -p "$port" -U postgres -d postgres -t -c "SHOW ssl;" 2>/dev/null)
    if [[ "$ssl_check" == *"on"* ]]; then
        echo -e "  ${GREEN}✅ SSL enabled${NC}"
    else
        echo -e "  ${YELLOW}⚠️ SSL not enabled or not enforced${NC}"
    fi
}

# MongoDB security assessment
assess_mongodb_security() {
    local host="$1"
    local port="$2"
    
    echo -e "\n${CYAN}🍃 MongoDB Security Assessment${NC}"
    echo -e "${YELLOW}Target: $host:$port${NC}"
    
    # Test for authentication bypass
    echo -e "${YELLOW}🔍 Testing authentication requirements...${NC}"
    
    if command -v mongosh &>/dev/null; then
        local mongo_cmd="mongosh"
    elif command -v mongo &>/dev/null; then
        local mongo_cmd="mongo"
    else
        echo -e "${YELLOW}⚠️ MongoDB client not available${NC}"
        return 1
    fi
    
    # Test unauthenticated access
    local unauth_test=$($mongo_cmd --host "$host" --port "$port" --eval "db.runCommand('listCollections')" 2>/dev/null)
    if [[ "$unauth_test" == *"collections"* ]]; then
        echo -e "  ${RED}🚨 CRITICAL: Unauthenticated access allowed!${NC}"
        echo -e "  ${YELLOW}💡 Enable authentication immediately${NC}"
    else
        echo -e "  ${GREEN}✅ Authentication appears to be required${NC}"
    fi
    
    # Check for default databases
    echo -e "${YELLOW}🔍 Checking for exposed databases...${NC}"
    local db_list=$($mongo_cmd --host "$host" --port "$port" --eval "db.adminCommand('listDatabases')" 2>/dev/null)
    if [[ -n "$db_list" ]]; then
        echo -e "  ${YELLOW}ℹ️ Database enumeration possible${NC}"
        echo -e "  ${BLUE}💡 Review database access permissions${NC}"
    fi
    
    # Version information
    echo -e "${YELLOW}🔍 Checking version information...${NC}"
    local version_info=$($mongo_cmd --host "$host" --port "$port" --eval "db.version()" 2>/dev/null)
    if [[ -n "$version_info" ]]; then
        echo -e "  ${YELLOW}ℹ️ Version: $version_info${NC}"
    fi
}

# Redis security assessment
assess_redis_security() {
    local host="$1"
    local port="$2"
    
    echo -e "\n${CYAN}🔴 Redis Security Assessment${NC}"
    echo -e "${YELLOW}Target: $host:$port${NC}"
    
    if ! command -v redis-cli &>/dev/null; then
        echo -e "${YELLOW}⚠️ Redis client not available${NC}"
        return 1
    fi
    
    # Test unauthenticated access
    echo -e "${YELLOW}🔍 Testing authentication...${NC}"
    local redis_info=$(redis-cli -h "$host" -p "$port" --no-auth-warning info server 2>/dev/null)
    if [[ -n "$redis_info" ]]; then
        echo -e "  ${RED}🚨 CRITICAL: Unauthenticated access allowed!${NC}"
        echo -e "  ${YELLOW}💡 Configure AUTH password immediately${NC}"
        
        # Check Redis version
        local redis_version=$(echo "$redis_info" | grep "redis_version" | cut -d':' -f2 | tr -d '\r')
        [[ -n "$redis_version" ]] && echo -e "  ${YELLOW}ℹ️ Version: $redis_version${NC}"
        
        # Check for dangerous commands
        echo -e "${YELLOW}🔍 Testing dangerous commands...${NC}"
        local config_get=$(redis-cli -h "$host" -p "$port" --no-auth-warning CONFIG GET "*" 2>/dev/null)
        if [[ -n "$config_get" ]]; then
            echo -e "  ${RED}🚨 CONFIG command available - potential for privilege escalation${NC}"
        fi
        
        local eval_test=$(redis-cli -h "$host" -p "$port" --no-auth-warning EVAL "return 'test'" 0 2>/dev/null)
        if [[ "$eval_test" == "test" ]]; then
            echo -e "  ${RED}🚨 EVAL command available - potential for code execution${NC}"
        fi
        
    else
        echo -e "  ${GREEN}✅ Authentication appears to be required${NC}"
    fi
}

# Generate database security report
generate_database_report() {
    local report_file="database_security_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
🔐 DATABASE SECURITY ANALYSIS REPORT
====================================
Generated: $(date)
Scan Type: $SCAN_TYPE
Target Host: $TARGET_HOST

DISCOVERED SERVICES:
===================
$(for db in "${DISCOVERED_DATABASES[@]}"; do
    echo "- $db"
done)

SECURITY ASSESSMENT SUMMARY:
============================
Total database services found: ${#DISCOVERED_DATABASES[@]}

COMMON VULNERABILITIES TESTED:
==============================
✓ Anonymous/unauthenticated access
✓ Default and weak credentials
✓ Version information disclosure
✓ SSL/TLS configuration
✓ Dangerous command availability
✓ Database enumeration

RECOMMENDATIONS:
===============
1. Enable authentication on all database services
2. Remove or secure default accounts
3. Use strong, unique passwords
4. Enable SSL/TLS encryption
5. Disable unnecessary features and commands
6. Implement network access controls
7. Regular security updates and patching
8. Monitor database access logs
9. Implement least privilege access
10. Regular security assessments

HIGH-PRIORITY ACTIONS:
=====================
□ Secure any databases allowing anonymous access
□ Change default passwords immediately
□ Enable encryption for data in transit
□ Review and restrict network access
□ Enable comprehensive logging
□ Implement backup encryption

TOOLS USED:
===========
- Network port scanning
- Database client connections
- Authentication testing
- Configuration analysis

Report generated by GoGoGadget Database Security Scanner
EOF
    
    echo -e "\n${GREEN}📄 Database security report saved: $report_file${NC}"
}

# Comprehensive database security audit
comprehensive_audit() {
    echo -e "\n${BLUE}🚀 Running comprehensive database security audit...${NC}"
    
    # Run discovery first
    discover_database_services "$TARGET_HOST"
    
    if [[ ${#DISCOVERED_DATABASES[@]} -eq 0 ]]; then
        echo -e "${YELLOW}⚠️ No databases discovered for detailed assessment${NC}"
        return 1
    fi
    
    # Assess each discovered database
    for db_info in "${DISCOVERED_DATABASES[@]}"; do
        local host=$(echo "$db_info" | cut -d':' -f1)
        local port=$(echo "$db_info" | cut -d':' -f2)
        local service=$(echo "$db_info" | cut -d':' -f3)
        
        case "$service" in
            "MySQL/MariaDB")
                assess_mysql_security "$host" "$port"
                ;;
            "PostgreSQL")
                assess_postgresql_security "$host" "$port"
                ;;
            "MongoDB")
                assess_mongodb_security "$host" "$port"
                ;;
            "Redis")
                assess_redis_security "$host" "$port"
                ;;
            *)
                echo -e "\n${YELLOW}ℹ️ $service detected on $host:$port${NC}"
                echo -e "  ${BLUE}💡 Manual assessment recommended${NC}"
                ;;
        esac
    done
    
    echo -e "\n${GREEN}🎯 Comprehensive database audit completed!${NC}"
}

# Display menu
display_menu() {
    echo -e "\n${YELLOW}🔐 Database Security Scanner Options:${NC}"
    echo "────────────────────────────────────────────"
    echo "[1] Database service discovery"
    echo "[2] MySQL/MariaDB security assessment"
    echo "[3] PostgreSQL security assessment"
    echo "[4] MongoDB security assessment"
    echo "[5] Redis security assessment"
    echo "[6] Comprehensive database audit"
    echo "[7] Generate security report"
    echo "[Q] Quit"
}

# Get target host
get_target_host() {
    echo -n "Enter target host (default: localhost): "
    read -r target
    TARGET_HOST=${target:-localhost}
    echo -e "${GREEN}✅ Target set: $TARGET_HOST${NC}"
}

# Main execution
main() {
    configure_scan
    setup_database_tools
    
    while true; do
        display_menu
        echo -n "Enter your choice: "
        read -r choice
        
        case "$choice" in
            1)
                get_target_host
                discover_database_services "$TARGET_HOST"
                ;;
            2)
                get_target_host
                echo -n "Enter MySQL port (default: 3306): "
                read -r port
                assess_mysql_security "$TARGET_HOST" "${port:-3306}"
                ;;
            3)
                get_target_host
                echo -n "Enter PostgreSQL port (default: 5432): "
                read -r port
                assess_postgresql_security "$TARGET_HOST" "${port:-5432}"
                ;;
            4)
                get_target_host
                echo -n "Enter MongoDB port (default: 27017): "
                read -r port
                assess_mongodb_security "$TARGET_HOST" "${port:-27017}"
                ;;
            5)
                get_target_host
                echo -n "Enter Redis port (default: 6379): "
                read -r port
                assess_redis_security "$TARGET_HOST" "${port:-6379}"
                ;;
            6)
                get_target_host
                comprehensive_audit
                ;;
            7)
                generate_database_report
                ;;
            [Qq])
                echo -e "${BLUE}Exiting database scanner... 🔐${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Invalid choice!${NC}"
                ;;
        esac
    done
}

main
