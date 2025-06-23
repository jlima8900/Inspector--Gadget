# Inspector-Gadget – Advanced Security & Exposure Analysis Tool

Welcome to Inspector-Gadget, your all-in-one cybersecurity Swiss Army knife! 🛡️

This comprehensive security suite investigates firewall rules, container security, network exposure, malware threats, rootkits, SSH attacks, and much more, making sure your setup isn't leaking secrets like a spy with a loud mouth.

If you ever wondered:
- "Are my containers running wild without security?"
- "Is my firewall actually working, or is it just a placebo?"
- "Am I unknowingly hosting a VIP lounge for hackers?"
- "Is my server under attack right now?"
- "Do I have malware or rootkits hiding in my system?"

Then Inspector-Gadget is your personal cyber Inspector and your entire cybersecurity team rolled into one!

It scans, detects, and reports in a way that even your non-techy boss can understand.

## 🚀 Core Security Analysis Features

✔ **Fail2Ban Analysis** – Extracts a list of blocked IPs and the jails they belong to. 🚪🔒  
✔ **Firewall Rules Extraction** – Lists active firewalld rules to ensure your defenses are up. 🛑  
✔ **Iptables Rules Extraction** – Analyzes iptables rules for unexpected openings. 🕵️♂️  
✔ **Docker Container Security Check** – Reviews running containers, restart policies, and mapped ports. 🐳  
✔ **Privileged Container Detection** – Identifies containers running with excessive privileges.  
✔ **Docker Network Exposure Analysis** – Detects whether your containers are unintentionally exposed to the internet. 🌍  
✔ **Security Risk Scoring** – Dynamically calculates a security risk score based on detected issues. 📊

## 🔥 NEW: GoGoGadget Security Suite Extensions

Inspector-Gadget now includes a complete arsenal of specialized security modules that transform it from a single tool into a **comprehensive cybersecurity platform**:

### 🦠 **Malware Detection & System Integrity**
- **🦠 ClamAV Scanner** (`gogo-gadgetO-clamav.sh`) – Professional antivirus scanning with real-time detection
- **🔒 Chkrootkit** (`gogo-gadgetO-chkrootkit.sh`) – Rootkit detection and system integrity verification
- **🛡️ RKHunter** (`gogo-gadgetO-rkhunter.sh`) – Advanced rootkit hunting with deep system analysis

### 🚨 **Threat Intelligence & SSH Security**
- **🚨 Sentinel** (`gogo-gadgetO-sentinel.sh`) – SSH threat intelligence with geolocation and TOR detection
- **📡 SSH Monitor** (`gogo-gadgetO-ssh-monitor.sh`) – Real-time SSH connection tracking and login analysis
- **🕵️ Lynis Auditor** (`gogo-gadgetO-lynis.sh`) – Professional security auditing and compliance checking

### 📊 **Risk Assessment & Secure Storage**
- **📊 Risk Scanner** (`gogo-gadgetO-scan.sh`) – Advanced security risk scoring with detailed breakdown
- **🔐 Vault** (`gogo-gadgetO-vault.sh`) – Secure report encryption and Keeper Vault integration

### 🚀 **Unified Command Center**
- **🚀 Master Suite** (`gogo-gadgetO-suite.sh`) – Unified launcher for the complete security toolkit

## 📊 Professional Security Reports

Inspector-Gadget automatically generates structured reports in CSV format for further analysis:

### **Core Analysis Reports:**
📂 **fail2ban_blocked_ips.csv** – List of blocked IPs with associated jails.  
📂 **firewalld_rules.csv** – Active firewall rules for better policy review.  
📂 **iptables_rules.csv** – Breakdown of iptables security rules.  
📂 **container_analysis.csv** – Overview of running containers, restart policies, and exposed ports.  
📂 **privileged_containers.csv** – Privileged containers that may pose security risks.  
📂 **network_analysis.csv** – Summary of Docker network connections and externally accessible services.

### **Advanced Threat Intelligence Reports:**
📂 **ssh_activity_report.csv** – SSH connection logs and access patterns.  
📂 **gogo-gadgetO-sentinel.csv** – Threat intelligence with geolocation and TOR analysis.  
📂 **firewall_analysis.log** – Detailed firewall security assessment.  
📂 **scan_history.log** – Security scan history and trend tracking.

## ✨ What Makes Inspector-Gadget Special

✔ **Easy-to-Run** – Just execute the script and let it do the work. No config required!  
✔ **Color-Coded Output** – Clear visual feedback with ✅ for success and ❌ for issues  
✔ **Parallel Execution** – Runs security checks simultaneously for faster analysis.  
✔ **Interactive Summaries** – Displays structured ASCII tables for better readability.  
✔ **Security Risk Breakdown** – Final security score provides a quick security assessment.  
✔ **Threat Intelligence** – Real-time geolocation and TOR exit node detection.  
✔ **Enterprise Features** – AES256 encryption and secure vault storage.  
✔ **Cross-Platform** – Works on Ubuntu, Debian, CentOS, RHEL, Fedora, and Arch Linux.

## 🎯 Advanced Security Capabilities

### **🌍 Threat Intelligence Engine**
- **Geolocation Lookup** – Identifies the geographic location of suspicious IP addresses
- **TOR Exit Node Detection** – Automatically detects connections from TOR networks via DNS queries
- **Attack Pattern Analysis** – Time-based filtering to identify coordinated attacks
- **Historical Trend Tracking** – Monitor security improvements over time

### **🔐 Enterprise-Grade Security**
- **AES256 Encryption** – Military-grade encryption for sensitive security reports
- **Keeper Vault Integration** – Secure cloud storage for encrypted reports
- **Dynamic Risk Scoring** – Sophisticated algorithm weighing multiple security factors
- **Compliance Reporting** – Generate reports suitable for security audits

### **🧠 Intelligent Analysis**
- **Dynamic Weight Scaling** – Risk scores adapt based on threat landscape
- **Cross-Reference Detection** – Correlate findings across multiple security domains
- **Automated Dependency Installation** – Self-configuring for different Linux distributions
- **Professional Logging** – Comprehensive audit trails for all security operations

## 🚀 Getting Started

No complicated setup. Just download, run, and enjoy.

### **Quick Start - Core Analysis:**
```bash
git clone https://github.com/jlima8900/Inspector--Gadget.git
cd Inspector--Gadget
chmod +x *.sh
sudo ./inspector-gadget.sh
ls -lah *.csv
```

### **🎮 Complete Security Suite:**
```bash
# Run the unified security command center
sudo ./gogo-gadgetO-suite.sh
```

### **🎯 Individual Module Examples:**
```bash
# SSH threat intelligence with geolocation
sudo ./gogo-gadgetO-sentinel.sh

# Professional malware scan
sudo ./gogo-gadgetO-clamav.sh

# Advanced security audit
sudo ./gogo-gadgetO-lynis.sh

# Rootkit detection
sudo ./gogo-gadgetO-chkrootkit.sh

# Calculate security risk score
sudo ./gogo-gadgetO-scan.sh
```

## 🔍 Use Cases & Benefits

### **For Security Professionals:**
✅ **Threat Hunting** – Identify active attacks and suspicious activities  
✅ **Incident Response** – Rapid security assessment during breaches  
✅ **Compliance Auditing** – Generate reports for regulatory requirements  
✅ **Penetration Testing** – Discover vulnerabilities before attackers do

### **For System Administrators:**
✅ **Identify Weak Firewall Rules** – Tighten policies based on real findings.  
✅ **Detect Unsecured Containers** – Flag dangerous configurations before attackers do.  
✅ **Monitor Attack Sources** – Identify repeated attack sources and proactively block them.  
✅ **Ensure Network Segmentation** – Avoid exposing services unintentionally.  
✅ **Evaluate Security Posture** – Prioritize critical security fixes with risk analysis.

### **For Enterprise Teams:**
✅ **Security Baseline Monitoring** – Track security improvements over time  
✅ **Automated Security Reporting** – Generate executive-level security summaries  
✅ **Multi-Domain Analysis** – Comprehensive view across firewall, containers, and network  
✅ **Secure Data Handling** – Encrypted storage and enterprise vault integration

## 🎭 What's Next?

Now that you have top-secret intelligence, what's next?

✅ **Block sketchy IPs** 🚫  
✅ **Tighten up your firewall** 🔥  
✅ **Remove malware and rootkits** 🦠  
✅ **Expose weak spots before bad actors do** 🔓  
✅ **Monitor SSH attacks in real-time** 🚨  
✅ **Calculate and improve your security score** 📊  
✅ **Encrypt and secure your security reports** 🔐  
✅ **Impress your friends with hacker-level insights** 🕶️

## 📜 License

This project is free software, licensed under the GNU General Public License v3 (GPLv3). That means:

- ✅ You can use, modify, and distribute it freely.
- 🔄 But if you improve it, share it back with the community (no hoarding!).

⚠️ No warranty – if your coffee spills because of a security panic, it's on you! ☕

For the full legal stuff, check out the LICENSE file.

## 👤 About

Created by someone who just wants you to be safe in this wild cyber world.

If this tool helped you, buy yourself a coffee – you deserve it! ☕

✅ If you read this far, you're already more secure than most people.  
🕵️♂️ Run the script and let Inspector-Gadget do the rest! 🔍

---

**Contact:** jlima8900@hotmail.com  
**Repository:** https://github.com/jlima8900/Inspector--Gadget
