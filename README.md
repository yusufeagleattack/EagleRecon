# 🦅 EagleRecon

**EagleRecon** is a lightweight reconnaissance tool for bug bounty hunters and penetration testers.  
It is designed to work smoothly on **Termux**, **Kali Linux**, and other Linux systems.

---

## 🚀 Features

- 🔍 Subdomain Enumeration  
- 🌐 Port Scanning (80, 443, 8080)  
- 🧬 Technology Fingerprinting  
- 🧪 Basic Reflected XSS Detection  
- 🎨 Colored Output  
- ⚡ Fast & Simple CLI usage  

---

## 📦 Installation

### 🔹 Termux / Linux
```bash
git clone https://github.com/yusufeagleattack/EagleRecon.git
cd EagleRecon
pip install -r requirements.txt
chmod +x eagle.py
cp eagle.py $PREFIX/bin/eaglerecon
