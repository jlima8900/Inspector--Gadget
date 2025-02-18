# 🔍 Inspector-Gadget

**Inspector-Gadget** is an **advanced security and exposure analysis tool** that inspects **firewall rules, Fail2Ban bans, Docker container security, privileged mode usage, and network exposure** to help system administrators **quickly identify security risks and misconfigurations.**

---

## 🚀 Features

✔ **Fail2Ban Analysis** – Extracts currently banned IPs and their corresponding jails.  
✔ **Firewalld & Iptables Rules Extraction** – Lists active firewall rules to assess network exposure.  
✔ **Docker Container Security Audit** – Identifies restart policies, mapped ports, and privileged mode usage.  
✔ **Network Exposure Assessment** – Analyzes Docker networks to detect external access risks.  
✔ **Real-Time Progress Indicators** – Displays status updates using a **spinner animation.**  
✔ **CSV Report Generation** – Automatically stores findings in organized CSV files for review.  

---

## 🛠️ Installation & Usage

1️⃣ **Clone the Repository**  
```bash
git clone https://github.com/your-username/Inspector-Gadget.git
cd Inspector-Gadget
```

2️⃣ **Make the Script Executable**  
```bash
chmod +x inspector-gadget.sh
```

3️⃣ **Run the Script**  
```bash
./inspector-gadget.sh
```

---

## 📊 Output & Reports

Once executed, **Inspector-Gadget** generates multiple CSV reports:  

📂 `fail2ban_blocked_ips.csv` → List of IPs currently banned by Fail2Ban.  
📂 `firewalld_rules.csv` → Extracted active Firewalld rules.  
📂 `iptables_rules.csv` → Extracted active Iptables rules.  
📂 `container_analysis.csv` → List of running Docker containers with security details.  
📂 `privileged_containers.csv` → Identifies containers running in privileged mode.  
📂 `network_analysis.csv` → Overview of Docker networks and exposed services.  

These reports help **identify security vulnerabilities** and **track system-wide exposure risks** with ease.

---

## 🤖 Why Use Inspector-Gadget?

🔹 **Preemptively Detect Security Threats** – Helps sysadmins proactively identify risks before an attack happens.  
🔹 **Quickly Audit Your Environment** – Automates the extraction of key security data, saving hours of manual work.  
🔹 **Improve Network & Container Security** – Ensures only the necessary ports and services are exposed.  
🔹 **Use in Incident Response** – Provides a quick snapshot of your security posture during investigations.  

---

## ⚠️ Disclaimer

**Inspector-Gadget** is a **read-only** tool that does **not** modify your system. However, **always review** the output before making any firewall or container adjustments.

---

## 🎯 Contributing

Want to improve Inspector-Gadget? Feel free to submit **pull requests**, report **issues**, or suggest **new features!** 🚀  

🔗 **GitHub Repository:** [Your Repository Link Here]

---

## 📜 License

This project is licensed under the **MIT License** – feel free to modify and use it as needed! 🎩  
