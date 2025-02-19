# 🔍 Inspector-Gadget: The Security & Exposure Detective 🕵️‍♂️

Welcome to **Inspector-Gadget**, your all-in-one **cybersecurity Swiss Army knife**! 🛡️ This script investigates **firewall rules, container security, and network exposure**, making sure your setup isn’t leaking secrets like a spy with a loud mouth.

If you ever wondered,

- “Are my **containers running wild** without security?”  
- “Is my **firewall actually working**, or is it just a placebo?”  
- “Am I unknowingly hosting **a VIP lounge for hackers**?”  

Then **Inspector-Gadget** is your **cyber bodyguard**. It **scans, detects, and reports** in a way that even your **non-techy boss** can understand.

---

## 🚀 Features

### 🔍 **Security & Exposure Analysis**
✔ **Fail2Ban Analysis** – Extracts a list of blocked IPs and the jails they belong to. 🚪🔒  
✔ **Firewall Rules Extraction** – Lists active `firewalld` rules to ensure your defenses are up. 🛑  
✔ **Iptables Rules Extraction** – Analyzes `iptables` rules for unexpected openings. 🕵️‍♂️  
✔ **Docker Container Security Check** – Reviews running containers, restart policies, and mapped ports. 🐳  
✔ **Privileged Container Detection** – Identifies containers running with excessive privileges. ⚠️  
✔ **Docker Network Exposure Analysis** – Detects whether your containers are unintentionally exposed to the internet. 🌍  

### 📜 **Data Output (CSV Reports)**
Inspector-Gadget **automatically generates structured reports** in CSV format:

📂 `fail2ban_blocked_ips.csv` – List of blocked IPs with associated jails.  
📂 `firewalld_rules.csv` – Active firewall rules for better policy review.  
📂 `iptables_rules.csv` – Breakdown of `iptables` security rules.  
📂 `container_analysis.csv` – Overview of running containers, restart policies, and exposed ports.  
📂 `privileged_containers.csv` – Privileged containers that may pose security risks.  
📂 `network_analysis.csv` – Summary of Docker network connections and externally accessible services.  

### 🏗 **User Experience & Usability**
✔ **Easy-to-Run** – Just execute the script and let it do the work. No config required!  
✔ **Color-Coded Output** – Clear visual feedback with ✅ for success and ⚠️ for warnings.  
✔ **Parallel Execution** – Runs security checks simultaneously for faster analysis.
✔ **Colloquial & Friendly Messaging** – Makes security insights digestible, even for non-experts.  

### 🛠 **Security Improvements & Actionable Insights**
✅ **Identify Weak Firewall Rules** – Tighten policies based on real findings.  
✅ **Detect Unsecured Containers** – Flag dangerous configurations before attackers do.  
✅ **Monitor Banned IPs** – Identify repeated attack sources and proactively block them.  
✅ **Ensure Network Segmentation** – Avoid exposing services unintentionally.  

---

## 📜 How to Use It

No complicated setup. Just **download, run, and enjoy**.

1️⃣ **Clone the repo:**  
```bash
git clone https://github.com/yourusername/Inspector-Gadget.git
cd Inspector-Gadget
chmod +x inspector.sh
```

2️⃣ **Run it like a boss** (with sudo for full insights):  
```bash
sudo ./inspector.sh
```

3️⃣ **Profit!** 🎉 (Check the reports)  
```bash
ls -lah *.csv
```

---

## 🛠️ What Can I Do with This Info?  
Now that you have all this **top-secret** intelligence, what next?  

✅ **Block sketchy IPs**  
✅ **Tighten up your firewall**  
✅ **Expose weak spots before bad actors do**  
✅ **Impress your friends with hacker-level insights**  

---

## 📃 License

This project is **free software**, licensed under the **GNU General Public License v3 (GPLv3)**. That means:  

- You **can use, modify, and distribute** it freely.  
- But if you improve it, **share it back with the community** (no hoarding!).  
- No warranty – **if your coffee spills because of a security panic, it’s on you! ☕**  

For the full legal stuff, check out the [LICENSE](LICENSE) file.  

---

## 🤝 Contributing

Want to add cool features? **Pull requests are welcome!** Open an issue, and let’s geek out together.  

---

## 🎩 Credits

Created by someone who just **wants you to be safe** in this wild cyber world. If this tool helped you, **buy yourself a coffee – you deserve it! ☕**  

---

### ✅ If you read this far, you’re already more secure than most people. Run the script and let **Inspector-Gadget** do the rest! 🕵️‍♂️🔍  

