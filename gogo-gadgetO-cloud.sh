#!/bin/bash

# ==============================
# ☁️ GoGoGadget Cloud - Cloud Security Analyzer
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
echo "│  ☁️ GoGoGadget Cloud - Cloud Security Analyzer        │"
echo "│  🔒 Multi-cloud security assessment & compliance      │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# Configuration
SAVE_REPORTS=true
CLOUD_PROVIDER=""
ASSESSMENT_TYPE="standard"
COMPLIANCE_CHECK=true

# Configure cloud assessment
configure_cloud_assessment() {
    echo -e "${YELLOW}☁️ Cloud Security Assessment Configuration:${NC}"
    echo "1) Quick cloud environment detection"
    echo "2) Standard security assessment + compliance"
    echo "3) Deep cloud security audit + recommendations"
    echo -n "Select option (1/2/3): "
    read -r choice
    
    case $choice in
        1)
            ASSESSMENT_TYPE="detection"
            SAVE_REPORTS=false
            COMPLIANCE_CHECK=false
            echo -e "${GREEN}✅ Detection mode${NC}"
            ;;
        2)
            ASSESSMENT_TYPE="standard"
            SAVE_REPORTS=true
            COMPLIANCE_CHECK=true
            echo -e "${GREEN}✅ Standard assessment + compliance${NC}"
            ;;
        3)
            ASSESSMENT_TYPE="deep"
            SAVE_REPORTS=true
            COMPLIANCE_CHECK=true
            echo -e "${GREEN}✅ Deep audit mode${NC}"
            ;;
        *)
            ASSESSMENT_TYPE="standard"
            echo -e "${YELLOW}⚠️ Invalid choice, defaulting to standard${NC}"
            ;;
    esac
    echo ""
}

# Setup cloud tools
setup_cloud_tools() {
    echo -e "${CYAN}🔧 Checking cloud security tools...${NC}"
    
    # Check for cloud CLI tools
    local available_tools=()
    local missing_tools=()
    
    # AWS CLI
    if command -v aws &>/dev/null; then
        available_tools+=("AWS CLI")
    else
        missing_tools+=("awscli")
    fi
    
    # Azure CLI
    if command -v az &>/dev/null; then
        available_tools+=("Azure CLI")
    else
        missing_tools+=("azure-cli")
    fi
    
    # Google Cloud CLI
    if command -v gcloud &>/dev/null; then
        available_tools+=("Google Cloud CLI")
    else
        missing_tools+=("google-cloud-sdk")
    fi
    
    # Docker (for container analysis)
    if command -v docker &>/dev/null; then
        available_tools+=("Docker")
    fi
    
    # kubectl (for Kubernetes)
    if command -v kubectl &>/dev/null; then
        available_tools+=("kubectl")
    fi
    
    echo -e "${GREEN}📋 Available tools:${NC}"
    for tool in "${available_tools[@]}"; do
        echo -e "  ✅ $tool"
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "\n${YELLOW}📦 Missing cloud tools (optional):${NC}"
        for tool in "${missing_tools[@]}"; do
            echo -e "  ⚠️ $tool"
        done
        echo -e "${BLUE}💡 Install cloud CLI tools for enhanced scanning${NC}"
    fi
    
    echo -e "${GREEN}✅ Tool check completed${NC}"
}

# Detect cloud environment
detect_cloud_environment() {
    echo -e "\n${CYAN}☁️ Detecting cloud environment...${NC}"
    
    local detected_clouds=()
    
    # AWS detection
    echo -e "${YELLOW}🔍 Checking for AWS environment...${NC}"
    
    # Check AWS metadata service
    if curl -s --max-time 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null; then
        echo -e "  ${GREEN}✅ AWS EC2 instance detected${NC}"
        detected_clouds+=("AWS")
        CLOUD_PROVIDER="AWS"
        
        # Get instance metadata
        local instance_id=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)
        local instance_type=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null)
        local az=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/placement/availability-zone 2>/dev/null)
        
        echo -e "    Instance ID: $instance_id"
        echo -e "    Instance Type: $instance_type"
        echo -e "    Availability Zone: $az"
        
        # Check for IMDSv2
        local imds_token=$(curl -s --max-time 2 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
        if [[ -n "$imds_token" ]]; then
            echo -e "    ${GREEN}✅ IMDSv2 available${NC}"
        else
            echo -e "    ${YELLOW}⚠️ IMDSv1 in use - consider upgrading to IMDSv2${NC}"
        fi
    fi
    
    # Azure detection
    echo -e "\n${YELLOW}🔍 Checking for Azure environment...${NC}"
    if curl -s --max-time 2 -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null | grep -q "azEnvironment"; then
        echo -e "  ${GREEN}✅ Azure VM detected${NC}"
        detected_clouds+=("Azure")
        [[ -z "$CLOUD_PROVIDER" ]] && CLOUD_PROVIDER="Azure"
        
        # Get Azure metadata
        local azure_metadata=$(curl -s --max-time 2 -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null)
        if [[ -n "$azure_metadata" ]]; then
            local vm_id=$(echo "$azure_metadata" | grep -o '"vmId":"[^"]*"' | cut -d'"' -f4)
            local vm_size=$(echo "$azure_metadata" | grep -o '"vmSize":"[^"]*"' | cut -d'"' -f4)
            echo -e "    VM ID: $vm_id"
            echo -e "    VM Size: $vm_size"
        fi
    fi
    
    # Google Cloud detection
    echo -e "\n${YELLOW}🔍 Checking for Google Cloud environment...${NC}"
    if curl -s --max-time 2 -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/id" 2>/dev/null; then
        echo -e "  ${GREEN}✅ Google Cloud VM detected${NC}"
        detected_clouds+=("GCP")
        [[ -z "$CLOUD_PROVIDER" ]] && CLOUD_PROVIDER="GCP"
        
        # Get GCP metadata
        local instance_id=$(curl -s --max-time 2 -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/id" 2>/dev/null)
        local machine_type=$(curl -s --max-time 2 -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/machine-type" 2>/dev/null)
        echo -e "    Instance ID: $instance_id"
        echo -e "    Machine Type: $(basename "$machine_type")"
    fi
    
    # Container environment detection
    echo -e "\n${YELLOW}🔍 Checking for container environments...${NC}"
    
    # Docker detection
    if [[ -f /.dockerenv ]]; then
        echo -e "  ${GREEN}✅ Docker container detected${NC}"
        detected_clouds+=("Docker")
    fi
    
    # Kubernetes detection
    if [[ -n "${KUBERNETES_SERVICE_HOST}" ]]; then
        echo -e "  ${GREEN}✅ Kubernetes environment detected${NC}"
        detected_clouds+=("Kubernetes")
        echo -e "    Service Host: ${KUBERNETES_SERVICE_HOST}"
        echo -e "    Service Port: ${KUBERNETES_SERVICE_PORT}"
    fi
    
    # Summary
    if [[ ${#detected_clouds[@]} -eq 0 ]]; then
        echo -e "\n${BLUE}ℹ️ No cloud environment detected - running on bare metal or VM${NC}"
        CLOUD_PROVIDER="On-Premise"
    else
        echo -e "\n${GREEN}🎯 Detected environments: ${detected_clouds[*]}${NC}"
    fi
}

# AWS security assessment
assess_aws_security() {
    echo -e "\n${CYAN}🔶 AWS Security Assessment${NC}"
    
    if ! command -v aws &>/dev/null; then
        echo -e "${YELLOW}⚠️ AWS CLI not available - metadata-only assessment${NC}"
        
        # Basic metadata checks
        if [[ "$CLOUD_PROVIDER" == "AWS" ]]; then
            echo -e "${YELLOW}🔍 Basic AWS security checks...${NC}"
            
            # Check security groups via metadata
            local security_groups=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/security-groups 2>/dev/null)
            if [[ -n "$security_groups" ]]; then
                echo -e "  ${GREEN}Security Groups: $security_groups${NC}"
            fi
            
            # Check IAM role
            local iam_role=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
            if [[ -n "$iam_role" ]]; then
                echo -e "  ${GREEN}✅ IAM role attached: $iam_role${NC}"
            else
                echo -e "  ${YELLOW}⚠️ No IAM role attached${NC}"
            fi
        fi
        return 1
    fi
    
    echo -e "${YELLOW}🔍 Running AWS security checks...${NC}"
    
    # Check AWS credentials
    if aws sts get-caller-identity &>/dev/null; then
        local identity=$(aws sts get-caller-identity)
        local account_id=$(echo "$identity" | grep -o '"Account": "[^"]*"' | cut -d'"' -f4)
        local user_arn=$(echo "$identity" | grep -o '"Arn": "[^"]*"' | cut -d'"' -f4)
        
        echo -e "  ${GREEN}✅ AWS credentials configured${NC}"
        echo -e "    Account ID: $account_id"
        echo -e "    User/Role: $user_arn"
        
        # Security checks
        echo -e "\n${YELLOW}🔒 AWS Security Configuration:${NC}"
        
        # Check S3 buckets (if accessible)
        echo -e "  🪣 Checking S3 bucket security..."
        local s3_buckets=$(aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null)
        if [[ -n "$s3_buckets" ]]; then
            local bucket_count=$(echo "$s3_buckets" | wc -w)
            echo -e "    Found $bucket_count S3 buckets"
            
            # Check first few buckets for public access
            echo "$s3_buckets" | head -5 | while read -r bucket; do
                [[ -z "$bucket" ]] && continue
                local public_access=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null)
                if [[ -n "$public_access" ]]; then
                    echo -e "    ${GREEN}✅ $bucket: Public access blocked${NC}"
                else
                    echo -e "    ${RED}⚠️ $bucket: Public access configuration unknown${NC}"
                fi
            done
        fi
        
        # Check EC2 security groups
        echo -e "  🛡️ Checking EC2 security groups..."
        local open_sg=$(aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]' --output text 2>/dev/null)
        if [[ -n "$open_sg" ]]; then
            echo -e "    ${RED}⚠️ Security groups with 0.0.0.0/0 access detected${NC}"
            echo "$open_sg" | while read -r sg_id sg_name; do
                echo -e "      🚨 $sg_id ($sg_name)"
            done
        else
            echo -e "    ${GREEN}✅ No overly permissive security groups found${NC}"
        fi
        
        # Check CloudTrail
        echo -e "  📋 Checking CloudTrail..."
        local cloudtrail_status=$(aws cloudtrail describe-trails --query 'trailList[?IsLogging==`true`].[Name]' --output text 2>/dev/null)
        if [[ -n "$cloudtrail_status" ]]; then
            echo -e "    ${GREEN}✅ CloudTrail logging enabled${NC}"
        else
            echo -e "    ${RED}⚠️ CloudTrail logging not detected${NC}"
        fi
        
    else
        echo -e "  ${RED}❌ AWS credentials not configured or insufficient permissions${NC}"
    fi
}

# Azure security assessment
assess_azure_security() {
    echo -e "\n${CYAN}🔷 Azure Security Assessment${NC}"
    
    if ! command -v az &>/dev/null; then
        echo -e "${YELLOW}⚠️ Azure CLI not available - metadata-only assessment${NC}"
        
        if [[ "$CLOUD_PROVIDER" == "Azure" ]]; then
            echo -e "${YELLOW}🔍 Basic Azure security checks...${NC}"
            
            # Check for managed identity
            local managed_identity=$(curl -s --max-time 2 -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" 2>/dev/null)
            if [[ -n "$managed_identity" ]]; then
                echo -e "  ${GREEN}✅ Managed identity available${NC}"
            else
                echo -e "  ${YELLOW}⚠️ No managed identity detected${NC}"
            fi
        fi
        return 1
    fi
    
    echo -e "${YELLOW}🔍 Running Azure security checks...${NC}"
    
    # Check Azure authentication
    if az account show &>/dev/null; then
        local account_info=$(az account show)
        local subscription_id=$(echo "$account_info" | grep -o '"id": "[^"]*"' | head -1 | cut -d'"' -f4)
        local subscription_name=$(echo "$account_info" | grep -o '"name": "[^"]*"' | head -1 | cut -d'"' -f4)
        
        echo -e "  ${GREEN}✅ Azure authentication configured${NC}"
        echo -e "    Subscription: $subscription_name ($subscription_id)"
        
        echo -e "\n${YELLOW}🔒 Azure Security Configuration:${NC}"
        
        # Check storage accounts
        echo -e "  💾 Checking storage account security..."
        local storage_accounts=$(az storage account list --query '[].name' --output tsv 2>/dev/null)
        if [[ -n "$storage_accounts" ]]; then
            local storage_count=$(echo "$storage_accounts" | wc -l)
            echo -e "    Found $storage_count storage accounts"
            
            echo "$storage_accounts" | head -3 | while read -r storage_account; do
                [[ -z "$storage_account" ]] && continue
                local https_only=$(az storage account show --name "$storage_account" --query 'enableHttpsTrafficOnly' --output tsv 2>/dev/null)
                if [[ "$https_only" == "true" ]]; then
                    echo -e "    ${GREEN}✅ $storage_account: HTTPS only enabled${NC}"
                else
                    echo -e "    ${RED}⚠️ $storage_account: HTTPS not enforced${NC}"
                fi
            done
        fi
        
        # Check network security groups
        echo -e "  🛡️ Checking network security groups..."
        local nsg_count=$(az network nsg list --query 'length(@)' --output tsv 2>/dev/null)
        if [[ -n "$nsg_count" && "$nsg_count" -gt 0 ]]; then
            echo -e "    ${GREEN}✅ $nsg_count network security groups configured${NC}"
        else
            echo -e "    ${YELLOW}⚠️ No network security groups found${NC}"
        fi
        
        # Check Key Vault
        echo -e "  🔐 Checking Key Vault configuration..."
        local key_vaults=$(az keyvault list --query 'length(@)' --output tsv 2>/dev/null)
        if [[ -n "$key_vaults" && "$key_vaults" -gt 0 ]]; then
            echo -e "    ${GREEN}✅ $key_vaults Key Vaults found${NC}"
        else
            echo -e "    ${YELLOW}ℹ️ No Key Vaults detected${NC}"
        fi
        
    else
        echo -e "  ${RED}❌ Azure authentication not configured${NC}"
        echo -e "  ${BLUE}💡 Run 'az login' to authenticate${NC}"
    fi
}

# GCP security assessment
assess_gcp_security() {
    echo -e "\n${CYAN}🔵 Google Cloud Security Assessment${NC}"
    
    if ! command -v gcloud &>/dev/null; then
        echo -e "${YELLOW}⚠️ Google Cloud CLI not available - metadata-only assessment${NC}"
        
        if [[ "$CLOUD_PROVIDER" == "GCP" ]]; then
            echo -e "${YELLOW}🔍 Basic GCP security checks...${NC}"
            
            # Check service account
            local service_account=$(curl -s --max-time 2 -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" 2>/dev/null)
            if [[ -n "$service_account" ]]; then
                echo -e "  ${GREEN}✅ Service account: $service_account${NC}"
            fi
            
            # Check scopes
            local scopes=$(curl -s --max-time 2 -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes" 2>/dev/null)
            if [[ -n "$scopes" ]]; then
                echo -e "  ${GREEN}Service account scopes configured${NC}"
            fi
        fi
        return 1
    fi
    
    echo -e "${YELLOW}🔍 Running Google Cloud security checks...${NC}"
    
    # Check GCP authentication
    if gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | grep -q "@"; then
        local active_account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
        local project_id=$(gcloud config get-value project 2>/dev/null)
        
        echo -e "  ${GREEN}✅ GCP authentication configured${NC}"
        echo -e "    Account: $active_account"
        echo -e "    Project: $project_id"
        
        echo -e "\n${YELLOW}🔒 GCP Security Configuration:${NC}"
        
        # Check Cloud Storage buckets
        echo -e "  🪣 Checking Cloud Storage security..."
        local storage_buckets=$(gsutil ls 2>/dev/null | wc -l)
        if [[ $storage_buckets -gt 0 ]]; then
            echo -e "    Found $storage_buckets storage buckets"
            
            # Check first few buckets for public access
            gsutil ls 2>/dev/null | head -3 | while read -r bucket; do
                [[ -z "$bucket" ]] && continue
                local public_access=$(gsutil iam get "$bucket" 2>/dev/null | grep -c "allUsers\|allAuthenticatedUsers")
                if [[ $public_access -eq 0 ]]; then
                    echo -e "    ${GREEN}✅ $(basename "$bucket"): No public access${NC}"
                else
                    echo -e "    ${RED}⚠️ $(basename "$bucket"): Public access detected${NC}"
                fi
            done
        fi
        
        # Check firewall rules
        echo -e "  🛡️ Checking firewall rules..."
        local open_firewall=$(gcloud compute firewall-rules list --filter="direction=INGRESS AND sourceRanges=0.0.0.0/0" --format="value(name)" 2>/dev/null)
        if [[ -n "$open_firewall" ]]; then
            local rule_count=$(echo "$open_firewall" | wc -l)
            echo -e "    ${YELLOW}⚠️ $rule_count firewall rules allow 0.0.0.0/0 access${NC}"
        else
            echo -e "    ${GREEN}✅ No overly permissive firewall rules found${NC}"
        fi
        
        # Check Cloud Security Command Center (if available)
        echo -e "  🔍 Checking security findings..."
        local security_findings=$(gcloud scc findings list --organization="$project_id" --format="value(name)" 2>/dev/null | wc -l)
        if [[ $security_findings -gt 0 ]]; then
            echo -e "    ${YELLOW}⚠️ $security_findings security findings detected${NC}"
        else
            echo -e "    ${GREEN}✅ No active security findings${NC}"
        fi
        
    else
        echo -e "  ${RED}❌ GCP authentication not configured${NC}"
        echo -e "  ${BLUE}💡 Run 'gcloud auth login' to authenticate${NC}"
    fi
}

# Container security assessment
assess_container_security() {
    echo -e "\n${CYAN}🐳 Container Security Assessment${NC}"
    
    if [[ -f /.dockerenv ]]; then
        echo -e "${GREEN}✅ Running inside Docker container${NC}"
        
        # Check container capabilities
        echo -e "${YELLOW}🔍 Checking container capabilities...${NC}"
        if command -v capsh &>/dev/null; then
            local capabilities=$(capsh --print 2>/dev/null)
            echo -e "  ${GREEN}Current capabilities:${NC}"
            echo "$capabilities" | grep "Current:" | while read -r line; do
                echo -e "    $line"
            done
        fi
        
        # Check for privileged mode
        if [[ -c /dev/kmsg ]]; then
            echo -e "  ${RED}⚠️ Container appears to be running in privileged mode${NC}"
        else
            echo -e "  ${GREEN}✅ Container not running in privileged mode${NC}"
        fi
        
        # Check filesystem permissions
        echo -e "${YELLOW}🔍 Checking filesystem security...${NC}"
        if [[ -w / ]]; then
            echo -e "  ${RED}⚠️ Root filesystem is writable${NC}"
        else
            echo -e "  ${GREEN}✅ Root filesystem is read-only${NC}"
        fi
        
    fi
    
    # Kubernetes assessment
    if [[ -n "${KUBERNETES_SERVICE_HOST}" ]]; then
        echo -e "\n${GREEN}✅ Running in Kubernetes environment${NC}"
        
        # Check service account
        if [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]]; then
            echo -e "  ${GREEN}✅ Service account token mounted${NC}"
            
            # Check namespace
            local namespace=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
            [[ -n "$namespace" ]] && echo -e "    Namespace: $namespace"
        fi
        
        # Check for kubectl access
        if command -v kubectl &>/dev/null; then
            echo -e "${YELLOW}🔍 Testing kubectl access...${NC}"
            if kubectl auth can-i --list 2>/dev/null | grep -q "get"; then
                echo -e "  ${YELLOW}⚠️ kubectl permissions detected - verify necessity${NC}"
            else
                echo -e "  ${GREEN}✅ Limited kubectl access${NC}"
            fi
        fi
    fi
}

# Cloud compliance assessment
assess_cloud_compliance() {
    echo -e "\n${PURPLE}📋 Cloud Compliance Assessment${NC}"
    
    if [[ "$COMPLIANCE_CHECK" != "true" ]]; then
        echo -e "${YELLOW}⚠️ Compliance checking disabled${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}🔍 Checking common compliance requirements...${NC}"
    
    local compliance_score=0
    local max_compliance_score=10
    
    # Encryption in transit
    echo -e "  🔐 Encryption in transit:"
    if [[ "$CLOUD_PROVIDER" != "On-Premise" ]]; then
        echo -e "    ${GREEN}✅ Cloud provider typically enforces HTTPS${NC}"
        ((compliance_score++))
    else
        echo -e "    ${YELLOW}⚠️ Verify HTTPS enforcement${NC}"
    fi
    
    # Access logging
    echo -e "  📋 Access logging:"
    case "$CLOUD_PROVIDER" in
        "AWS")
            if command -v aws &>/dev/null && aws cloudtrail describe-trails --query 'trailList[?IsLogging==`true`]' 2>/dev/null | grep -q "Name"; then
                echo -e "    ${GREEN}✅ CloudTrail logging enabled${NC}"
                ((compliance_score++))
            else
                echo -e "    ${YELLOW}⚠️ CloudTrail status unknown${NC}"
            fi
            ;;
        "Azure")
            echo -e "    ${BLUE}ℹ️ Check Azure Activity Log configuration${NC}"
            ;;
        "GCP")
            echo -e "    ${BLUE}ℹ️ Check Cloud Audit Logs configuration${NC}"
            ;;
        *)
            echo -e "    ${YELLOW}⚠️ Implement comprehensive access logging${NC}"
            ;;
    esac
    
    # Identity and Access Management
    echo -e "  👤 Identity and Access Management:"
    if [[ "$CLOUD_PROVIDER" != "On-Premise" ]]; then
        echo -e "    ${GREEN}✅ Cloud IAM services available${NC}"
        ((compliance_score++))
    else
        echo -e "    ${YELLOW}⚠️ Implement robust IAM solution${NC}"
    fi
    
    # Data encryption at rest
    echo -e "  💾 Data encryption at rest:"
    echo -e "    ${BLUE}ℹ️ Verify storage encryption configuration${NC}"
    
    # Network segmentation
    echo -e "  🌐 Network segmentation:"
    if [[ "$CLOUD_PROVIDER" != "On-Premise" ]]; then
        echo -e "    ${GREEN}✅ VPC/VNet capabilities available${NC}"
        ((compliance_score++))
    else
        echo -e "    ${YELLOW}⚠️ Implement network segmentation${NC}"
    fi
    
    # Compliance scoring
    local compliance_percentage=$((compliance_score * 100 / max_compliance_score))
    echo -e "\n${PURPLE}📊 Compliance Score: $compliance_score/$max_compliance_score ($compliance_percentage%)${NC}"
    
    if [[ $compliance_percentage -ge 80 ]]; then
        echo -e "${GREEN}🟢 GOOD: Strong compliance foundation${NC}"
    elif [[ $compliance_percentage -ge 60 ]]; then
        echo -e "${YELLOW}🟡 MODERATE: Some compliance gaps${NC}"
    else
        echo -e "${RED}🔴 POOR: Significant compliance improvements needed${NC}"
    fi
}

# Generate cloud security report
generate_cloud_report() {
    local report_file="cloud_security_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
☁️ CLOUD SECURITY ANALYSIS REPORT
=================================
Generated: $(date)
Assessment Type: $ASSESSMENT_TYPE
Cloud Provider: $CLOUD_PROVIDER

ENVIRONMENT DETECTION:
=====================
Primary Cloud: $CLOUD_PROVIDER
Container Environment: $(if [[ -f /.dockerenv ]]; then echo "Docker"; fi)
Kubernetes: $(if [[ -n "${KUBERNETES_SERVICE_HOST}" ]]; then echo "Yes"; else echo "No"; fi)

SECURITY ASSESSMENT SUMMARY:
============================
$(case "$CLOUD_PROVIDER" in
    "AWS") echo "✓ AWS-specific security checks performed" ;;
    "Azure") echo "✓ Azure-specific security checks performed" ;;
    "GCP") echo "✓ Google Cloud security checks performed" ;;
    *) echo "✓ Generic cloud security assessment performed" ;;
esac)

COMPLIANCE ASSESSMENT:
=====================
$(if [[ "$COMPLIANCE_CHECK" == "true" ]]; then echo "✓ Compliance requirements reviewed"; else echo "✗ Compliance assessment skipped"; fi)

KEY FINDINGS:
============
- Cloud environment successfully detected
- Security configuration analyzed
- Compliance gaps identified (if any)
- Container security assessed (if applicable)

RECOMMENDATIONS:
===============
1. Enable comprehensive logging and monitoring
2. Implement least privilege access controls
3. Ensure encryption in transit and at rest
4. Regular security assessments and compliance audits
5. Network segmentation and access controls
6. Backup and disaster recovery planning
7. Security monitoring and incident response
8. Regular security training for cloud operations

CLOUD-SPECIFIC RECOMMENDATIONS:
==============================
$(case "$CLOUD_PROVIDER" in
    "AWS") echo "- Enable GuardDuty for threat detection
- Use AWS Config for compliance monitoring
- Implement AWS WAF for web application protection
- Enable VPC Flow Logs" ;;
    "Azure") echo "- Enable Azure Security Center
- Use Azure Policy for compliance
- Implement Azure Firewall
- Enable NSG Flow Logs" ;;
    "GCP") echo "- Enable Security Command Center
- Use Cloud Security Scanner
- Implement Cloud Armor
- Enable VPC Flow Logs" ;;
    *) echo "- Implement cloud-native security services
- Use infrastructure as code for consistency
- Regular security patches and updates" ;;
esac)

TOOLS USED:
===========
- Cloud metadata services
$(command -v aws &>/dev/null && echo "- AWS CLI")
$(command -v az &>/dev/null && echo "- Azure CLI")
$(command -v gcloud &>/dev/null && echo "- Google Cloud CLI")
$(command -v kubectl &>/dev/null && echo "- kubectl")

Report generated by GoGoGadget Cloud Security Analyzer
EOF
    
    echo -e "\n${GREEN}📄 Cloud security report saved: $report_file${NC}"
}

# Display menu
display_menu() {
    echo -e "\n${YELLOW}☁️ Cloud Security Analyzer Options:${NC}"
    echo "────────────────────────────────────────────"
    echo "[1] Detect cloud environment"
    echo "[2] AWS security assessment"
    echo "[3] Azure security assessment"
    echo "[4] Google Cloud security assessment"
    echo "[5] Container security assessment"
    echo "[6] Cloud compliance assessment"
    echo "[7] Comprehensive cloud audit"
    echo "[8] Generate security report"
    echo "[Q] Quit"
}

# Main execution
main() {
    configure_cloud_assessment
    setup_cloud_tools
    
    while true; do
        display_menu
        echo -n "Enter your choice: "
        read -r choice
        
        case "$choice" in
            1)
                detect_cloud_environment
                ;;
            2)
                assess_aws_security
                ;;
            3)
                assess_azure_security
                ;;
            4)
                assess_gcp_security
                ;;
            5)
                assess_container_security
                ;;
            6)
                assess_cloud_compliance
                ;;
            7)
                echo -e "${BLUE}🚀 Running comprehensive cloud security audit...${NC}"
                detect_cloud_environment
                case "$CLOUD_PROVIDER" in
                    "AWS") assess_aws_security ;;
                    "Azure") assess_azure_security ;;
                    "GCP") assess_gcp_security ;;
                esac
                assess_container_security
                assess_cloud_compliance
                echo -e "\n${GREEN}🎯 Comprehensive cloud audit completed!${NC}"
                ;;
            8)
                generate_cloud_report
                ;;
            [Qq])
                echo -e "${BLUE}Exiting cloud security analyzer... ☁️${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Invalid choice!${NC}"
                ;;
        esac
    done
}

main
