"""
ServerControl - Desktop Application (Qt Version)
=================================================
Alternative desktop wrapper using PyQt/PySide for better icon support.
"""

import sys
import os
import threading

# Try PyQt6 first, fall back to PyQt5, then PySide6
try:
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    from PyQt6.QtCore import QUrl
    from PyQt6.QtGui import QIcon
    QT_VERSION = 'PyQt6'
except ImportError:
    try:
        from PyQt5.QtWidgets import QApplication, QMainWindow
        from PyQt5.QtWebEngineWidgets import QWebEngineView
        from PyQt5.QtCore import QUrl
        from PyQt5.QtGui import QIcon
        QT_VERSION = 'PyQt5'
    except ImportError:
        try:
            from PySide6.QtWidgets import QApplication, QMainWindow
            from PySide6.QtWebEngineWidgets import QWebEngineView
            from PySide6.QtCore import QUrl
            from PySide6.QtGui import QIcon
            QT_VERSION = 'PySide6'
        except ImportError:
            print("Error: No Qt library found. Install PyQt6, PyQt5, or PySide6")
            print("  pip install PyQt6 PyQt6-WebEngine")
            sys.exit(1)

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app as flask_app


class ServerControlWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, url: str, icon_path: str = None):
        super().__init__()
        
        # Window configuration
        self.setWindowTitle("ServerControl")
        self.setMinimumSize(800, 600)
        self.resize(1400, 900)
        
        # Set window icon
        if icon_path and os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
            print(f"✓ Icon loaded: {icon_path}")
        else:
            print("! Icon not found, using default")
        
        # Create web view
        self.browser = QWebEngineView()
        self.browser.setUrl(QUrl(url))
        
        # Set central widget
        self.setCentralWidget(self.browser)
        
        # Dark theme for window (Linux/Windows)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0a0a0f;
            }
        """)


def get_icon_path():
    """Get absolute path to icon.png"""
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    
    # Check multiple possible locations
    possible_paths = [
        os.path.join(base_path, 'icon.png'),
        os.path.join(base_path, 'static', 'icon.png'),
        os.path.join(base_path, 'assets', 'icon.png'),
        os.path.join(base_path, 'resources', 'icon.png'),
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    return None


def start_flask():
    """Start Flask server in background"""
    flask_app.run(
        host='127.0.0.1',
        port=5000,
        debug=False,
        use_reloader=False,
        threaded=True
    )


def main():
    """Main entry point"""
    print("\n" + "=" * 50)
    print(f"  ⚡ ServerControl Desktop ({QT_VERSION})")
    print("=" * 50)
    
    # Start Flask in background thread
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    
    # Wait for server to start
    import time
    time.sleep(1)
    
    # Get icon path
    icon_path = get_icon_path()
    if icon_path:
        print(f"  Icon: {icon_path}")
    
    print(f"  URL: http://127.0.0.1:5000")
    print("=" * 50 + "\n")
    
    # Create Qt application
    qt_app = QApplication(sys.argv)
    qt_app.setApplicationName("ServerControl")
    qt_app.setOrganizationName("ServerControl")
    
    # Set application-wide icon
    if icon_path:
        qt_app.setWindowIcon(QIcon(icon_path))
    
    # Create and show window
    window = ServerControlWindow("http://127.0.0.1:5000", icon_path)
    window.show()
    
    # Run event loop
    sys.exit(qt_app.exec() if hasattr(qt_app, 'exec') else qt_app.exec_())


if __name__ == '__main__':
    main()
