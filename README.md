# Inspector-Gadget 🛡️

**Shitty Security & Exposure Analysis Tool**

Inspector-Gadget is a comprehensive cybersecurity Swiss Army knife designed to investigate firewall rules, container security, and network exposure. 
This bash script ensures your infrastructure isn't inadvertently exposing secrets or vulnerabilities to potential attackers.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Bash](https://img.shields.io/badge/Bash-4.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Linux](https://img.shields.io/badge/OS-Linux-orange.svg)](https://www.kernel.org/)

## 🚀 Quick Start

```bash
git clone https://github.com/jlima8900/Inspector--Gadget.git
cd Inspector--Gadget
chmod +x inspector-gadget.sh
sudo ./inspector-gadget.sh
```

## 🔍 What Inspector-Gadget Analyzes

### Core Security Assessments

- **🚪 Fail2Ban Analysis** - Extracts blocked IPs and associated jails
- **🛑 Firewall Rules Extraction** - Reviews active firewalld configurations
- **🕵️ Iptables Rules Analysis** - Identifies unexpected network openings
- **🐳 Docker Container Security** - Evaluates running containers and security policies
- **⚠️ Privileged Container Detection** - Flags containers with excessive privileges
- **🌍 Network Exposure Analysis** - Detects unintentional internet exposure
- **📊 Security Risk Scoring** - Provides dynamic risk assessment

### Key Questions Answered

- Are my containers running without proper security constraints?
- Is my firewall configuration actually protecting my system?
- Am I unknowingly hosting services accessible to attackers?
- Which containers are running with dangerous privileges?
- What network services are exposed to the internet?

## 📂 Generated Reports

Inspector-Gadget automatically generates structured CSV reports for detailed analysis:

| Report File | Description |
|-------------|-------------|
| `fail2ban_blocked_ips.csv` | Blocked IPs with associated jail information |
| `firewalld_rules.csv` | Active firewall rules for policy review |
| `iptables_rules.csv` | Comprehensive iptables security analysis |
| `container_analysis.csv` | Container overview with restart policies and ports |
| `privileged_containers.csv` | High-risk privileged container inventory |
| `network_analysis.csv` | Docker network connections and exposed services |

## ✨ Key Features

### 🎯 **Easy to Use**
- Zero configuration required
- Single command execution
- Automatic report generation

### 🎨 **Clear Visual Feedback**
- Color-coded output (✅ success, ❌ warnings)
- Interactive ASCII tables for better readability
- Structured progress indicators

### ⚡ **High Performance**
- Parallel execution for faster analysis
- Optimized security checks
- Minimal system resource usage

### 📈 **Comprehensive Analysis**
- Multi-layered security assessment
- Risk prioritization scoring
- Actionable insights and recommendations

## 🛠️ System Requirements

- **Operating System**: Linux (Ubuntu, CentOS, RHEL, Debian)
- **Shell**: Bash 4.0 or higher
- **Privileges**: Root/sudo access required
- **Dependencies**: 
  - `iptables` (for firewall analysis)
  - `docker` (for container analysis)
  - `fail2ban` (optional, for IP blocking analysis)
  - `firewalld` (optional, for firewall rule analysis)

## 📋 Usage Examples

### Basic Security Scan
```bash
sudo ./inspector-gadget.sh
```

### Review Generated Reports
```bash
ls -la *.csv
cat container_analysis.csv | column -t -s ','
```

### Monitor Blocked IPs
```bash
cat fail2ban_blocked_ips.csv
```

## 🚨 What to Do After Running Inspector-Gadget

### Immediate Actions
1. **🚫 Block Suspicious IPs** - Review and extend IP blocking rules
2. **🔥 Tighten Firewall Rules** - Close unnecessary ports and services
3. **🔒 Secure Containers** - Remove excessive privileges from containers
4. **🕸️ Review Network Exposure** - Ensure proper network segmentation

### Risk Mitigation Strategy
1. **High Risk Items** - Address critical findings immediately
2. **Medium Risk Items** - Schedule fixes within next maintenance window
3. **Low Risk Items** - Include in next security review cycle
4. **Documentation** - Update security policies based on findings

## 🔧 Advanced Configuration

### Running Specific Modules
```bash
# Analyze only Docker containers
sudo ./inspector-gadget.sh --containers-only

# Focus on firewall analysis
sudo ./inspector-gadget.sh --firewall-only

# Generate detailed report
sudo ./inspector-gadget.sh --verbose --output-dir ./security-reports
```

## 📊 Understanding the Risk Score

Inspector-Gadget calculates a dynamic security risk score based on:

- **Critical**: Privileged containers, open management ports
- **High**: Weak firewall rules, excessive network exposure
- **Medium**: Outdated configurations, non-standard setups
- **Low**: Minor configuration improvements, best practice recommendations

**Score Ranges:**
- 🟢 **0-30**: Excellent security posture
- 🟡 **31-60**: Good with room for improvement
- 🟠 **61-80**: Moderate risk, action recommended
- 🔴 **81-100**: High risk, immediate attention required

## 🤝 Contributing

We welcome contributions! Please feel free to:

1. **Report Issues** - Found a bug? Let us know!
2. **Feature Requests** - Have an idea? We'd love to hear it!
3. **Pull Requests** - Code improvements are always welcome!
4. **Documentation** - Help improve our docs!

### Development Setup
```bash
git clone https://github.com/jlima8900/Inspector--Gadget.git
cd Inspector--Gadget
# Make your changes
chmod +x inspector-gadget.sh
# Test your changes
sudo ./inspector-gadget.sh
```

## 📜 License

This project is licensed under the **GNU General Public License v3.0** (GPLv3).

**This means:**
- ✅ Free to use, modify, and distribute
- 🔄 Share improvements with the community
- 📖 Full license text available in [LICENSE](LICENSE) file

⚠️ **Disclaimer**: This tool is provided as-is without warranty. Always test in a safe environment before production use.

## 🎯 Use Cases

### System Administrators
- Regular security audits
- Compliance reporting
- Infrastructure hardening
- Incident response preparation

### DevOps Teams
- Container security validation
- CI/CD security gates
- Infrastructure as Code verification
- Security policy enforcement

### Security Teams
- Vulnerability assessment
- Risk analysis and reporting
- Security baseline validation
- Penetration testing preparation

## 🆘 Support

Having issues? Here's how to get help:

1. **📚 Check Documentation** - Review this README thoroughly
2. **🔍 Search Issues** - Look for similar problems in GitHub Issues
3. **🐛 Report Bugs** - Create a new issue with detailed information
4. **💬 Community Discussion** - Join our community discussions

## 🔗 Related Tools

- **Lynis** - Security auditing tool for Unix-based systems
- **Docker Bench** - Docker security best practices checker
- **Nmap** - Network discovery and security auditing
- **OpenVAS** - Vulnerability assessment scanner

## 🏆 Acknowledgments

Created with security in mind for the cybersecurity community. Special thanks to all contributors and users who help make our digital infrastructure more secure.

---

**Remember**: Security is a journey, not a destination. Regular monitoring and assessment are key to maintaining a robust security posture.

🕵️‍♂️ **Ready to secure your infrastructure? Run Inspector-Gadget today!** 🔍
