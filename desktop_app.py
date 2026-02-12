"""
ServerControl - Desktop Application Wrapper
============================================
Runs ServerControl as a desktop application using pywebview.
Uses icon.png as the application window icon.
"""

import webview
import threading
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

# ============================================
# CONFIGURATION
# ============================================

CONFIG = {
    'title': 'ServerControl',
    'width': 1400,
    'height': 900,
    'min_size': (800, 600),
    'resizable': True,
    'background_color': '#0a0a0f',
    'text_select': False,
    'on_top': False,

    # Icon configuration
    'icon': 'icon.png',  # Path to icon file

    # Server settings
    'host': '127.0.0.1',
    'port': 5000,
    'debug': False
}


def get_icon_path():
    """
    Get absolute path to icon file.
    Handles both development and PyInstaller frozen states.
    """
    # Check if running as PyInstaller bundle
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    icon_path = os.path.join(base_path, CONFIG['icon'])

    # Check if icon exists
    if os.path.exists(icon_path):
        return icon_path

    # Try alternative locations
    alt_paths = [
        os.path.join(base_path, 'static', CONFIG['icon']),
        os.path.join(base_path, 'assets', CONFIG['icon']),
        os.path.join(base_path, 'resources', CONFIG['icon']),
    ]

    for alt_path in alt_paths:
        if os.path.exists(alt_path):
            return alt_path

    # Return None if not found (will use default icon)
    print(f"Warning: Icon file '{CONFIG['icon']}' not found")
    return None


def start_flask_server():
    """Start Flask server in a separate thread"""
    app.run(
        host=CONFIG['host'],
        port=CONFIG['port'],
        debug=CONFIG['debug'],
        use_reloader=False,  # Disable reloader for threading
        threaded=True
    )


def create_desktop_window():
    """Create and configure the desktop window"""

    # Get icon path
    icon_path = get_icon_path()

    # Start Flask server in background thread
    server_thread = threading.Thread(target=start_flask_server, daemon=True)
    server_thread.start()

    # Wait a moment for server to start
    import time
    time.sleep(1)

    # Create window with icon
    window = webview.create_window(
        title=CONFIG['title'],
        url=f"http://{CONFIG['host']}:{CONFIG['port']}",
        width=CONFIG['width'],
        height=CONFIG['height'],
        min_size=CONFIG['min_size'],
        resizable=CONFIG['resizable'],
        background_color=CONFIG['background_color'],
        text_select=CONFIG['text_select'],
        on_top=CONFIG['on_top']
    )

    # Start webview with icon
    webview_settings = {
        'gui': None,  # Auto-detect: gtk, qt, cef, mshtml
        'debug': CONFIG['debug']
    }

    # Add icon if available (platform-specific handling)
    if icon_path:
        # For Windows
        if sys.platform == 'win32':
            # pywebview on Windows supports icon via window parameter
            try:
                import ctypes
                # Set app user model ID for Windows taskbar
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('ServerControl')
            except:
                pass

        # Icon handling varies by platform and pywebview version
        # We'll use the icon parameter if supported
        webview_settings['icon'] = icon_path

    # Start the application
    webview.start(**webview_settings)


def main():
    """Main entry point"""
    print("\n" + "=" * 50)
    print("  ⚡ ServerControl Desktop Application")
    print("=" * 50)
    print(f"  Starting on http://{CONFIG['host']}:{CONFIG['port']}")

    icon_path = get_icon_path()
    if icon_path:
        print(f"  Icon: {icon_path}")
    else:
        print("  Icon: Using default")

    print("=" * 50 + "\n")

    create_desktop_window()


if __name__ == '__main__':
    main()
