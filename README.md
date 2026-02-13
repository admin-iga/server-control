# ⚡ ServerControl Pro

**Professional Server Management Suite**  
Desktop application with **Tkinter UI** and **full SSH-based server control**.

![ServerControl Pro](https://img.shields.io/badge/edition-PRO-gold.svg)
![Version](https://img.shields.io/badge/version-1.0.0--pro-purple.svg)
![Python](https://img.shields.io/badge/python-3.9+-green.svg)
![License](https://img.shields.io/badge/license-MIT-red.svg)

---

## 🚀 About ServerControl Pro

**ServerControl Pro** is a professional desktop application for system administrators and DevOps engineers.  
It provides **full remote server management via SSH**, a **native Tkinter interface**, advanced security features, and production-grade reliability.

Unlike the Community edition, Pro is designed for **real infrastructure management**, not demos.

---

## ✨ Key Features (Pro)

- 🔗 **Full SSH Server Control**  
  Start, stop, restart and manage real services on remote servers

- 🖥️ **Native Desktop App (Tkinter)**  
  Fast, lightweight, no browser required

- 📊 **Advanced Monitoring**  
  Real CPU, RAM, disk, uptime, load average

- 🧠 **Persistent SSH Connections**  
  Smart connection pooling for high performance

- 🔐 **Enterprise-Grade Security**  
  - SSH key authentication  
  - Encrypted credential storage  
  - Role-based access (Admin / Operator / Viewer)

- 🐳 **Multi-Service Orchestration**  
  systemd, Docker, PM2, Supervisor, custom commands

- 📁 **Server Groups & Tags**  
  Organize servers by environment (prod, staging, dev)

- 🧾 **Audit Logs & History**  
  Full action history with timestamps and users

- 🧩 **Plugin System (Pro)**  
  Extend with custom scripts and integrations

- 🧠 **Offline Mode (Read-only)**  
  View last known states without connecting

---

## 📁 Project Structure

```text
ServerControl-Pro/
├── main.py                # Application entry point (Tkinter)
├── ssh_manager.py         # Advanced SSH manager
├── ui/
│   ├── __init__.py
│   ├── app.py             # Tkinter UI logic
│   └── widgets.py         # Custom widgets
├── core/
│   ├── __init__.py
│   ├── services.py        # Service control logic
│   ├── metrics.py         # Metrics collection
│   └── security.py        # Encryption & auth
├── config/
│   ├── servers.json       # Server configuration
│   └── roles.json         # User roles & permissions
├── assets/
│   └── icon.png           # Application icon
├── logs/
│   └── audit.log          # Audit logs
├── requirements.txt
└── README.md
```

---

## 🖥️ System Requirements

- Windows 10/11, Linux, macOS  
- Python 3.9+  
- SSH access to target servers  
- Network access to managed servers  

---

## ⚙️ Installation

```bash
git clone https://github.com/admin-iga/server-control/tree/Pro
cd ServerControl-Pro

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt
python main.py
```

---

## 🔐 Security Model

- 🔑 **SSH Key Authentication** (recommended)  
- 🔒 **Encrypted Secrets Storage**  
- 👤 **User Roles**
  - Admin – full control  
  - Operator – manage services  
  - Viewer – read-only  

---

## 🧰 Configuration

### Example `servers.json`

```json
{
  "servers": [
    {
      "id": "prod-web-01",
      "name": "Production Web Server",
      "host": "10.0.0.5",
      "ssh": {
        "port": 22,
        "username": "svc_admin",
        "auth_method": "key_file",
        "key_file": "~/.ssh/id_ed25519"
      },
      "services": [
        { "name": "nginx", "type": "systemd" },
        { "name": "docker", "type": "systemd" }
      ],
      "tags": ["prod", "web"]
    }
  ]
}
```

---

## 🛡️ Best Practices

- Use **SSH keys** instead of passwords  
- Create **dedicated service users** on servers  
- Use **passwordless sudo** for controlled commands  
- Restrict network access (VPN / firewall)  
- Regularly rotate keys  

---

## 📦 Packaging

Create standalone desktop app:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon assets/icon.png main.py
```

---

## 📄 License

**Commercial License**  
This software is proprietary. Redistribution is prohibited without permission.

---
---

## 🗺️ Roadmap

- 🌐 Web-based Pro dashboard  
- 📱 Mobile companion app  
- 🔔 Alerting & notifications (Telegram, Slack, Email)  
- 📈 Historical metrics & charts  
- 🧠 AI-assisted diagnostics  

---

© 2026 ServerControl Pro. All rights reserved.
