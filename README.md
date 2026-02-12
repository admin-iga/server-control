# ⚡ ServerControl

A modern server management dashboard with Flask backend and glassmorphism UI.

![ServerControl Dashboard](icon.png)

## ✨ Features

- 🖥️ **Server Management** – Start, stop, and restart servers  
- 📊 **Real-time Monitoring** – Live CPU and RAM metrics  
- 🔐 **Authentication** – Password-protected access  
- 🌙 **Dark UI** – Modern glassmorphism design  
- 🔄 **Auto-refresh** – Updates every 3 seconds  
- 📝 **Action Logging** – All actions are logged  
- 🔔 **Toast Notifications** – Visual feedback  

---

## 📁 Project Structure

```text
ServerControl/
├── app.py               # Flask backend
├── servers.json         # Server configuration
├── requirements.txt     # Python dependencies
├── README.md            # This file
├── logs/                # Log files (auto-created)
├── templates/
│   ├── index.html       # Dashboard page
│   └── login.html       # Login page
└── static/
    ├── style.css        # Styles
    └── app.js           # Frontend JavaScript
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher  
- pip (Python package manager)

### 🪟 Windows Installation

```cmd
:: 1. Create project directory
mkdir ServerControl
cd ServerControl

:: 2. Create virtual environment
python -m venv venv

:: 3. Activate virtual environment
venv\Scripts\activate

:: 4. Install dependencies
pip install -r requirements.txt

:: 5. Run the application
python app.py
```

### 🐧 Linux/macOS Installation

```bash
# 1. Create project directory
mkdir ServerControl
cd ServerControl

# 2. Create virtual environment
python3 -m venv venv

# 3. Activate virtual environment
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run the application
python app.py
```

---

## 🌐 Access the Dashboard

Open your browser and go to:

```
http://127.0.0.1:5000
```

Default login password:

```
admin123
```

---

## 🔌 API Endpoints

| Method | Endpoint                  | Description        |
|--------|---------------------------|--------------------|
| GET    | /api/servers              | List all servers   |
| GET    | /api/servers/{id}         | Get server details |
| POST   | /api/servers/{id}/start   | Start server       |
| POST   | /api/servers/{id}/stop    | Stop server        |
| POST   | /api/servers/{id}/restart | Restart server     |
| GET    | /api/servers/{id}/status  | Get server status  |
| GET    | /api/logs                 | Get action logs    |

---

## ⚙️ Configuration

### 🔑 Changing the Password

Edit `app.py`:

```python
ADMIN_PASSWORD = "your-new-password"
```

### ➕ Adding Servers

Edit `servers.json`:

```json
{
  "servers": [
    {
      "id": "unique-id",
      "name": "Server Name",
      "ip": "192.168.1.100",
      "type": "Web Server",
      "initial_status": "online"
    }
  ]
}
```

---

## 🧩 Server Types (Icons)

- Web Server 🌐  
- Database 🗄️  
- Gateway 🚪  
- Redis ⚡  
- Storage 💾  
- Email 📧  
- Monitoring 📊  

---

## 🛠 Troubleshooting

### Port already in use

```bash
# Windows:
netstat -ano | findstr :5000

# Linux/macOS:
lsof -i :5000
```

Run on another port:

```bash
python app.py --port 5001
```

### Permission denied (Linux/macOS)

```bash
chmod +x app.py
```

### Module not found

```bash
pip install -r requirements.txt
```

---

## 🔐 Security Notes

⚠️ For production use:

- Change the default password  
- Change the Flask secret key  
- Use HTTPS  
- Use a proper WSGI server (Gunicorn)  
- Implement proper user management  

---

## 🚢 Production Deployment

```bash
# Using Gunicorn (Linux/macOS)
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# With SSL
gunicorn -w 4 -b 0.0.0.0:443 --certfile=cert.pem --keyfile=key.pem app:app
```

---

## 📜 License

MIT License – Feel free to use and modify.

## 📦 Version

**1.0.0**

---

Made with ❤️ by ServerControl Team
