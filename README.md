# ⚡ ServerControl

A modern server management dashboard with real SSH support, Flask backend, and glassmorphism UI.

![ServerControl](https://img.shields.io/badge/version-1.1.1-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

---

## ✨ Features

- 🖥️ **Real Server Management** – Control actual servers via SSH  
- 📊 **Live Monitoring** – Real-time CPU and RAM metrics  
- 🔐 **Secure Authentication** – Password-protected dashboard  
- 🌙 **Modern Dark UI** – Glassmorphism/cyberpunk design  
- 🔄 **Auto-refresh** – Updates every 3 seconds  
- 📝 **Action Logging** – All operations are logged  
- 🔔 **Toast Notifications** – Visual feedback for all actions  
- 🖱️ **Desktop App** – Native window with custom icon  
- 🐳 **Multi-Service Support** – systemd, Docker, PM2, Supervisor  

---

## 📁 Project Structure

```text
ServerControl/
├── app.py                 # Flask backend (main application)
├── ssh_manager.py         # SSH connection manager
├── desktop_app.py         # Desktop wrapper (pywebview)
├── desktop_app_qt.py      # Desktop wrapper (Qt alternative)
├── servers.json           # Server configuration
├── requirements.txt       # Python dependencies
├── icon.png               # Application icon
├── README.md              # This file
├── logs/
│   └── server_actions.log
├── templates/
│   ├── index.html
│   └── login.html
└── static/
    ├── style.css
    └── app.js
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+  
- pip  
- SSH access to your servers (for real management)

### 🪟 Windows

```cmd
mkdir ServerControl
cd ServerControl

python -m venv venv
venv\Scripts\activate

pip install flask paramiko pywebview
python app.py
```

### 🐧 Linux / macOS

```bash
mkdir ServerControl
cd ServerControl

python3 -m venv venv
source venv/bin/activate

pip install flask paramiko pywebview
python app.py
```

### 🌐 Access the Dashboard

Open:

```
http://127.0.0.1:5000
```

Login password:

```
admin123
```

---

## 🖥️ Desktop Application

```bash
# Using pywebview (recommended)
python desktop_app.py

# Qt alternative
pip install PyQt6 PyQt6-WebEngine
python desktop_app_qt.py
```


---

## ⚙️ Configuration (servers.json)

```json
{
  "settings": {
    "use_real_ssh": true,
    "default_ssh_port": 22,
    "default_timeout": 10,
    "cache_metrics_seconds": 5
  },
  "servers": [
    {
      "id": "unique-server-id",
      "name": "My Server",
      "ip": "192.168.1.100",
      "type": "Web Server",
      "description": "Server description",
      "initial_status": "online",
      "ssh": {
        "enabled": true,
        "port": 22,
        "username": "admin",
        "auth_method": "password",
        "password": "your-password",
        "key_file": null,
        "key_passphrase": null
      },
      "service": {
        "name": "nginx",
        "type": "systemd"
      }
    }
  ]
}
```

---

## 🔐 Authentication Examples

### Password

```json
{
  "ssh": {
    "enabled": true,
    "username": "admin",
    "auth_method": "password",
    "password": "your-secure-password"
  }
}
```

### SSH Key

```json
{
  "ssh": {
    "enabled": true,
    "username": "admin",
    "auth_method": "key_file",
    "key_file": "~/.ssh/id_rsa"
  }
}
```

---

## 🔌 API Reference

| Method | Endpoint                         | Description              |
|--------|----------------------------------|--------------------------|
| GET    | /api/servers                     | List all servers         |
| GET    | /api/servers/{id}                | Get server details       |
| GET    | /api/servers/{id}/status         | Get server status        |
| POST   | /api/servers/{id}/start          | Start service            |
| POST   | /api/servers/{id}/stop           | Stop service             |
| POST   | /api/servers/{id}/restart        | Restart service          |
| POST   | /api/servers/{id}/test-connection| Test SSH connection      |
| GET    | /api/logs                        | Get recent logs          |

---

## 🛠 Troubleshooting

```bash
# Port in use
lsof -i :5000
kill -9 <PID>

# SSH key permissions
chmod 600 ~/.ssh/id_rsa
```

---

## 🔒 Security Recommendations

- Change default password  
- Change Flask secret key  
- Use HTTPS  
- Prefer SSH keys over passwords  
- Limit SSH permissions  

---

## 📦 Requirements

```text
Flask==3.0.0
paramiko==3.4.0
pywebview==4.4.1
gunicorn==21.2.0
python-dotenv==1.0.0
cryptography>=41.0.0
bcrypt>=4.0.0
pynacl>=1.5.0
```

---

## 📜 License

MIT License

---

Made with ❤️ by ServerControl Team
