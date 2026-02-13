"""
ServerControl Pro - Main Application
====================================
Tkinter-based desktop application for server management.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
import logging
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime
import os
import paramiko
from .widgets import (
    Colors, Fonts, ModernButton, StatusIndicator,
    MetricBar, ToastManager, ServerCard, ScrollableFrame
)
from ssh_manager import SSHConfig, SSHConnectionPool, get_pool, shutdown_pool
from core.services import ServiceType, ServiceStatus, get_controller
from core.metrics import MetricsCollector, SystemMetrics
from core.security import SecurityManager, Permission, Role

logger = logging.getLogger('ServerControlPro.App')


@dataclass
class ServerConfig:
    """Server configuration data."""
    id: str
    name: str
    ip: str
    port: int
    server_type: str
    group: str
    description: str
    username: str
    auth_method: str
    password: Optional[str]
    key_file: Optional[str]
    key_passphrase: Optional[str]
    service_name: Optional[str]
    service_type: str
    custom_commands: Dict[str, str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ServerConfig':
        """Create from dictionary."""
        ssh = data.get('ssh', {})
        service = data.get('service', {})

        return cls(
            id=data['id'],
            name=data['name'],
            ip=data['ip'],
            port=ssh.get('port', 22),
            server_type=data.get('type', 'Server'),
            group=data.get('group', ''),
            description=data.get('description', ''),
            username=ssh.get('username', 'root'),
            auth_method=ssh.get('auth_method', 'password'),
            password=ssh.get('password'),
            key_file=ssh.get('key_file'),
            key_passphrase=ssh.get('key_passphrase'),
            service_name=service.get('name'),
            service_type=service.get('type', 'systemd'),
            custom_commands=service.get('commands', {})
        )


class LoginDialog(tk.Toplevel):
    """Login dialog window."""

    def __init__(self, parent, security: SecurityManager):
        super().__init__(parent)

        self.security = security
        self.authenticated = False

        # Window configuration
        self.title("ServerControl Pro - Login")
        self.geometry("400x300")
        self.configure(bg=Colors.BG_PRIMARY)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        # Center on screen
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 400) // 2
        y = (self.winfo_screenheight() - 300) // 2
        self.geometry(f"+{x}+{y}")

        self._build_ui()

        # Handle window close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        """Build login UI."""
        # Main container
        container = tk.Frame(self, bg=Colors.BG_PRIMARY, padx=40, pady=30)
        container.pack(fill='both', expand=True)

        # Logo/Title
        title = tk.Label(
            container,
            text="⚡ ServerControl Pro",
            font=Fonts.get(18, bold=True),
            fg=Colors.ACCENT_PRIMARY,
            bg=Colors.BG_PRIMARY
        )
        title.pack(pady=(0, 5))

        subtitle = tk.Label(
            container,
            text="Server Management System",
            font=Fonts.get(10),
            fg=Colors.TEXT_SECONDARY,
            bg=Colors.BG_PRIMARY
        )
        subtitle.pack(pady=(0, 30))

        # Username field
        user_frame = tk.Frame(container, bg=Colors.BG_PRIMARY)
        user_frame.pack(fill='x', pady=(0, 15))

        user_label = tk.Label(
            user_frame,
            text="Username",
            font=Fonts.get(10),
            fg=Colors.TEXT_SECONDARY,
            bg=Colors.BG_PRIMARY,
            anchor='w'
        )
        user_label.pack(fill='x')

        self.username_entry = tk.Entry(
            user_frame,
            font=Fonts.get(11),
            bg=Colors.BG_SECONDARY,
            fg=Colors.TEXT_PRIMARY,
            insertbackground=Colors.TEXT_PRIMARY,
            relief='flat',
            highlightthickness=1,
            highlightcolor=Colors.ACCENT_PRIMARY,
            highlightbackground=Colors.BG_TERTIARY
        )
        self.username_entry.pack(fill='x', ipady=8)
        self.username_entry.insert(0, "admin")

        # Password field
        pass_frame = tk.Frame(container, bg=Colors.BG_PRIMARY)
        pass_frame.pack(fill='x', pady=(0, 25))

        pass_label = tk.Label(
            pass_frame,
            text="Password",
            font=Fonts.get(10),
            fg=Colors.TEXT_SECONDARY,
            bg=Colors.BG_PRIMARY,
            anchor='w'
        )
        pass_label.pack(fill='x')

        self.password_entry = tk.Entry(
            pass_frame,
            font=Fonts.get(11),
            bg=Colors.BG_SECONDARY,
            fg=Colors.TEXT_PRIMARY,
            insertbackground=Colors.TEXT_PRIMARY,
            relief='flat',
            show='●',
            highlightthickness=1,
            highlightcolor=Colors.ACCENT_PRIMARY,
            highlightbackground=Colors.BG_TERTIARY
        )
        self.password_entry.pack(fill='x', ipady=8)

        # Error message
        self.error_label = tk.Label(
            container,
            text="",
            font=Fonts.get(9),
            fg=Colors.ACCENT_DANGER,
            bg=Colors.BG_PRIMARY
        )
        self.error_label.pack()

        # Login button
        login_btn = ModernButton(
            container,
            text="Login",
            command=self._do_login,
            width=150,
            height=36,
            bg_color=Colors.ACCENT_PRIMARY,
            hover_color=Colors.ACCENT_SECONDARY
        )
        login_btn.pack(pady=(10, 0))

        # Bind enter key
        self.password_entry.bind('<Return>', lambda e: self._do_login())
        self.username_entry.bind('<Return>', lambda e: self.password_entry.focus())

        # Focus username
        self.username_entry.focus()

    def _do_login(self):
        """Attempt login."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username or not password:
            self.error_label.config(text="Please enter username and password")
            return

        if self.security.authenticate(username, password):
            self.authenticated = True
            self.destroy()
        else:
            self.error_label.config(text="Invalid username or password")
            self.password_entry.delete(0, 'end')

    def _on_close(self):
        """Handle window close."""
        self.authenticated = False
        self.destroy()


class CredentialsDialog(tk.Toplevel):
    """Dialog for entering server credentials with storage options."""

    # Storage option constants
    STORAGE_NONE = "none"
    STORAGE_ENCRYPTED = "encrypted"
    STORAGE_JSON = "json"

    def __init__(
            self,
            parent,
            server_name: str,
            server_id: str,
            default_username: str = "",
            use_key: bool = False
    ):
        super().__init__(parent)

        self.server_name = server_name
        self.server_id = server_id
        self.use_key = use_key
        self.result = None

        # Window configuration
        self.title(f"Credentials - {server_name}")
        self.geometry("450x380")
        self.configure(bg=Colors.BG_PRIMARY)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        # Center on screen
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 450) // 2
        y = (self.winfo_screenheight() - 380) // 2
        self.geometry(f"+{x}+{y}")

        self._build_ui(default_username)

        # Handle escape key
        self.bind('<Escape>', lambda e: self._cancel())

    def _build_ui(self, default_username: str):
        """Build dialog UI."""
        container = tk.Frame(self, bg=Colors.BG_PRIMARY, padx=30, pady=20)
        container.pack(fill='both', expand=True)

        # Title
        title = tk.Label(
            container,
            text=f"Enter credentials for",
            font=Fonts.get(10),
            fg=Colors.TEXT_SECONDARY,
            bg=Colors.BG_PRIMARY
        )
        title.pack(pady=(0, 2))

        server_label = tk.Label(
            container,
            text=self.server_name,
            font=Fonts.get(12, bold=True),
            fg=Colors.ACCENT_PRIMARY,
            bg=Colors.BG_PRIMARY
        )
        server_label.pack(pady=(0, 20))

        # Username field
        user_frame = tk.Frame(container, bg=Colors.BG_PRIMARY)
        user_frame.pack(fill='x', pady=(0, 10))

        tk.Label(
            user_frame,
            text="Username",
            font=Fonts.get(9),
            fg=Colors.TEXT_SECONDARY,
            bg=Colors.BG_PRIMARY
        ).pack(anchor='w')

        self.username_entry = tk.Entry(
            user_frame,
            font=Fonts.get(10),
            bg=Colors.BG_SECONDARY,
            fg=Colors.TEXT_PRIMARY,
            insertbackground=Colors.TEXT_PRIMARY,
            relief='flat',
            highlightthickness=1,
            highlightcolor=Colors.ACCENT_PRIMARY,
            highlightbackground=Colors.BG_TERTIARY
        )
        self.username_entry.pack(fill='x', ipady=6)
        self.username_entry.insert(0, default_username)

        # Password/Passphrase field
        pass_frame = tk.Frame(container, bg=Colors.BG_PRIMARY)
        pass_frame.pack(fill='x', pady=(0, 15))

        label_text = "Key Passphrase" if self.use_key else "Password"
        tk.Label(
            pass_frame,
            text=label_text,
            font=Fonts.get(9),
            fg=Colors.TEXT_SECONDARY,
            bg=Colors.BG_PRIMARY
        ).pack(anchor='w')

        self.password_entry = tk.Entry(
            pass_frame,
            font=Fonts.get(10),
            show='●',
            bg=Colors.BG_SECONDARY,
            fg=Colors.TEXT_PRIMARY,
            insertbackground=Colors.TEXT_PRIMARY,
            relief='flat',
            highlightthickness=1,
            highlightcolor=Colors.ACCENT_PRIMARY,
            highlightbackground=Colors.BG_TERTIARY
        )
        self.password_entry.pack(fill='x', ipady=6)

        # Storage options section
        storage_frame = tk.LabelFrame(
            container,
            text=" Save Credentials ",
            font=Fonts.get(9, bold=True),
            fg=Colors.TEXT_PRIMARY,
            bg=Colors.BG_PRIMARY,
            bd=1,
            relief='groove'
        )
        storage_frame.pack(fill='x', pady=(5, 15))

        self.storage_var = tk.StringVar(value=self.STORAGE_ENCRYPTED)

        # Option 1: Don't save
        opt1_frame = tk.Frame(storage_frame, bg=Colors.BG_PRIMARY)
        opt1_frame.pack(fill='x', padx=10, pady=(10, 2))

        tk.Radiobutton(
            opt1_frame,
            text="Don't save (session only)",
            value=self.STORAGE_NONE,
            variable=self.storage_var,
            font=Fonts.get(9),
            fg=Colors.TEXT_PRIMARY,
            bg=Colors.BG_PRIMARY,
            selectcolor=Colors.BG_SECONDARY,
            activebackground=Colors.BG_PRIMARY,
            activeforeground=Colors.TEXT_PRIMARY
        ).pack(anchor='w')

        tk.Label(
            opt1_frame,
            text="Password will be cleared when you close the app",
            font=Fonts.get(8),
            fg=Colors.TEXT_MUTED,
            bg=Colors.BG_PRIMARY
        ).pack(anchor='w', padx=(20, 0))

        # Option 2: Save encrypted (recommended)
        opt2_frame = tk.Frame(storage_frame, bg=Colors.BG_PRIMARY)
        opt2_frame.pack(fill='x', padx=10, pady=2)

        tk.Radiobutton(
            opt2_frame,
            text="Save encrypted (recommended)",
            value=self.STORAGE_ENCRYPTED,
            variable=self.storage_var,
            font=Fonts.get(9),
            fg=Colors.ACCENT_SUCCESS,
            bg=Colors.BG_PRIMARY,
            selectcolor=Colors.BG_SECONDARY,
            activebackground=Colors.BG_PRIMARY,
            activeforeground=Colors.ACCENT_SUCCESS
        ).pack(anchor='w')

        tk.Label(
            opt2_frame,
            text="Stored securely with AES-256 encryption",
            font=Fonts.get(8),
            fg=Colors.TEXT_MUTED,
            bg=Colors.BG_PRIMARY
        ).pack(anchor='w', padx=(20, 0))

        # Option 3: Save to JSON
        opt3_frame = tk.Frame(storage_frame, bg=Colors.BG_PRIMARY)
        opt3_frame.pack(fill='x', padx=10, pady=(2, 10))

        tk.Radiobutton(
            opt3_frame,
            text="Save to config file (servers.json)",
            value=self.STORAGE_JSON,
            variable=self.storage_var,
            font=Fonts.get(9),
            fg=Colors.ACCENT_WARNING,
            bg=Colors.BG_PRIMARY,
            selectcolor=Colors.BG_SECONDARY,
            activebackground=Colors.BG_PRIMARY,
            activeforeground=Colors.ACCENT_WARNING
        ).pack(anchor='w')

        tk.Label(
            opt3_frame,
            text="⚠️ Plain text - use only for testing/development",
            font=Fonts.get(8),
            fg=Colors.ACCENT_WARNING,
            bg=Colors.BG_PRIMARY
        ).pack(anchor='w', padx=(20, 0))

        # Buttons
        btn_frame = tk.Frame(container, bg=Colors.BG_PRIMARY)
        btn_frame.pack(fill='x', pady=(10, 0))

        cancel_btn = ModernButton(
            btn_frame,
            text="Cancel",
            command=self._cancel,
            width=100,
            height=34,
            bg_color=Colors.BG_TERTIARY
        )
        cancel_btn.pack(side='left')

        connect_btn = ModernButton(
            btn_frame,
            text="Connect",
            command=self._submit,
            width=120,
            height=34,
            bg_color=Colors.ACCENT_PRIMARY,
            hover_color=Colors.ACCENT_SECONDARY
        )
        connect_btn.pack(side='right')

        # Bind enter key
        self.password_entry.bind('<Return>', lambda e: self._submit())
        self.username_entry.bind('<Return>', lambda e: self.password_entry.focus())

        # Focus username if empty, otherwise password
        if default_username:
            self.password_entry.focus()
        else:
            self.username_entry.focus()

    def _submit(self):
        """Submit credentials."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username:
            messagebox.showwarning("Validation", "Username is required")
            self.username_entry.focus()
            return

        if not password and not self.use_key:
            messagebox.showwarning("Validation", "Password is required")
            self.password_entry.focus()
            return

        self.result = {
            'username': username,
            'password': password,
            'storage_method': self.storage_var.get()
        }
        self.destroy()

    def _cancel(self):
        """Cancel dialog."""
        self.result = None
        self.destroy()


class ServerControlApp:
    """Main application class."""

    def __init__(
            self,
            servers_config: Path,
            roles_config: Path,
            security_manager: SecurityManager,
            icon_path: Path
    ):
        """
        Initialize the application.

        Args:
            servers_config: Path to servers.json
            roles_config: Path to roles.json
            security_manager: Security manager instance
            icon_path: Path to application icon
        """
        self.servers_config_path = servers_config
        self.roles_config_path = roles_config
        self.security = security_manager
        self.icon_path = icon_path

        self.servers: Dict[str, ServerConfig] = {}
        self.server_states: Dict[str, Dict[str, Any]] = {}
        self.selected_server: Optional[str] = None

        self._pool = get_pool()
        self._refresh_thread: Optional[threading.Thread] = None
        self._running = True

        # Load configuration
        self._load_config()

        # Create main window
        self.root = tk.Tk()
        self._setup_window()

        # Build UI
        self._build_ui()

        # Toast manager
        self.toast = ToastManager(self.root)

    def _setup_window(self):
        """Configure main window."""
        self.root.title("ServerControl Pro")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        self.root.configure(bg=Colors.BG_PRIMARY)

        # Set icon
        if self.icon_path.exists():
            try:
                # Try PhotoImage for PNG
                icon = tk.PhotoImage(file=str(self.icon_path))
                self.root.iconphoto(True, icon)
            except tk.TclError:
                logger.warning(f"Could not load icon: {self.icon_path}")

        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('clam')

        # Scrollbar style
        style.configure(
            "Vertical.TScrollbar",
            background=Colors.BG_TERTIARY,
            troughcolor=Colors.BG_SECONDARY,
            arrowcolor=Colors.TEXT_SECONDARY
        )

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _load_config(self):
        """Load server configuration."""
        try:
            with open(self.servers_config_path, 'r') as f:
                data = json.load(f)

            for server_data in data.get('servers', []):
                try:
                    server = ServerConfig.from_dict(server_data)
                    self.servers[server.id] = server
                    self.server_states[server.id] = {
                        'status': 'unknown',
                        'cpu': 0,
                        'ram': 0,
                        'disk': 0,
                        'uptime': '',
                        'last_update': None
                    }
                except Exception as e:
                    logger.error(f"Failed to load server config: {e}")

            logger.info(f"Loaded {len(self.servers)} servers")

        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load config: {e}")

    def _build_ui(self):
        """Build main UI."""
        # Header
        self._build_header()

        # Main content area
        content = tk.Frame(self.root, bg=Colors.BG_PRIMARY)
        content.pack(fill='both', expand=True, padx=20, pady=(10, 20))

        # Left panel - Server list
        self._build_server_list(content)

        # Right panel - Server details
        self._build_details_panel(content)

    def _build_header(self):
        """Build header bar."""
        header = tk.Frame(self.root, bg=Colors.BG_SECONDARY, height=60)
        header.pack(fill='x')
        header.pack_propagate(False)

        # Left - Logo
        left = tk.Frame(header, bg=Colors.BG_SECONDARY)
        left.pack(side='left', padx=20)

        logo = tk.Label(
            left,
            text="⚡ ServerControl Pro",
            font=Fonts.get(14, bold=True),
            fg=Colors.ACCENT_PRIMARY,
            bg=Colors.BG_SECONDARY
        )
        logo.pack(side='left')

        # Center - Connection status
        center = tk.Frame(header, bg=Colors.BG_SECONDARY)
        center.pack(side='left', expand=True)

        self.connection_indicator = StatusIndicator(center)
        self.connection_indicator.pack(side='left', padx=(0, 8))

        self.connection_label = tk.Label(
            center,
            text="Ready",
            font=Fonts.get(10),
            fg=Colors.TEXT_SECONDARY,
            bg=Colors.BG_SECONDARY
        )
        self.connection_label.pack(side='left')

        # Right - User info and actions
        right = tk.Frame(header, bg=Colors.BG_SECONDARY)
        right.pack(side='right', padx=20)

        # User info
        user = self.security.current_user
        if user:
            user_label = tk.Label(
                right,
                text=f"👤 {user.username} ({user.role.value})",
                font=Fonts.get(10),
                fg=Colors.TEXT_SECONDARY,
                bg=Colors.BG_SECONDARY
            )
            user_label.pack(side='left', padx=(0, 20))

        # Refresh button
        refresh_btn = ModernButton(
            right,
            text="🔄 Refresh",
            command=self._refresh_all,
            width=90,
            height=30,
            bg_color=Colors.BG_TERTIARY
        )
        refresh_btn.pack(side='left', padx=(0, 10))

        # Logout button
        logout_btn = ModernButton(
            right,
            text="Logout",
            command=self._logout,
            width=70,
            height=30,
            bg_color=Colors.ACCENT_DANGER
        )
        logout_btn.pack(side='left')

    def _build_server_list(self, parent):
        """Build server list panel."""
        # Container
        list_frame = tk.Frame(parent, bg=Colors.BG_SECONDARY, width=350)
        list_frame.pack(side='left', fill='y', padx=(0, 15))
        list_frame.pack_propagate(False)

        # Header
        list_header = tk.Frame(list_frame, bg=Colors.BG_SECONDARY)
        list_header.pack(fill='x', padx=15, pady=15)

        tk.Label(
            list_header,
            text="Servers",
            font=Fonts.get(13, bold=True),
            fg=Colors.TEXT_PRIMARY,
            bg=Colors.BG_SECONDARY
        ).pack(side='left')

        count_label = tk.Label(
            list_header,
            text=f"({len(self.servers)})",
            font=Fonts.get(11),
            fg=Colors.TEXT_MUTED,
            bg=Colors.BG_SECONDARY
        )
        count_label.pack(side='left', padx=5)

        # Filter/Group tabs
        filter_frame = tk.Frame(list_frame, bg=Colors.BG_SECONDARY)
        filter_frame.pack(fill='x', padx=15, pady=(0, 10))

        groups = ['All'] + list(set(s.group for s in self.servers.values() if s.group))

        self.group_var = tk.StringVar(value='All')
        for group in groups:
            btn = tk.Radiobutton(
                filter_frame,
                text=group,
                value=group,
                variable=self.group_var,
                font=Fonts.get(9),
                fg=Colors.TEXT_SECONDARY,
                bg=Colors.BG_SECONDARY,
                selectcolor=Colors.BG_TERTIARY,
                activebackground=Colors.BG_SECONDARY,
                activeforeground=Colors.TEXT_PRIMARY,
                indicatoron=False,
                padx=10,
                pady=4,
                command=self._filter_servers
            )
            btn.pack(side='left', padx=2)

        # Server list
        self.server_list_frame = ScrollableFrame(list_frame)
        self.server_list_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))

        self.server_cards: Dict[str, ServerCard] = {}
        self._populate_server_list()

    def _populate_server_list(self):
        """Populate server cards."""
        # Clear existing cards
        for widget in self.server_list_frame.inner_frame.winfo_children():
            widget.destroy()
        self.server_cards.clear()

        # Filter by group
        selected_group = self.group_var.get()

        for server_id, server in self.servers.items():
            if selected_group != 'All' and server.group != selected_group:
                continue

            card = ServerCard(
                self.server_list_frame.inner_frame,
                server_id=server_id,
                name=server.name,
                ip=server.ip,
                server_type=server.server_type,
                group=server.group,
                on_select=self._select_server
            )
            card.pack(fill='x', padx=5, pady=5)
            self.server_cards[server_id] = card

            # Update with current state
            state = self.server_states.get(server_id, {})
            card.update_status(
                state.get('status', 'unknown'),
                state.get('cpu', 0),
                state.get('ram', 0)
            )

    def _filter_servers(self):
        """Filter servers by group."""
        self._populate_server_list()

    def _build_details_panel(self, parent):
        """Build server details panel."""
        self.details_frame = tk.Frame(parent, bg=Colors.BG_SECONDARY)
        self.details_frame.pack(side='left', fill='both', expand=True)

        # Placeholder when no server selected
        self.no_selection_label = tk.Label(
            self.details_frame,
            text="Select a server to view details",
            font=Fonts.get(12),
            fg=Colors.TEXT_MUTED,
            bg=Colors.BG_SECONDARY
        )
        self.no_selection_label.place(relx=0.5, rely=0.5, anchor='center')

        # Details content (hidden initially)
        self.details_content = tk.Frame(self.details_frame, bg=Colors.BG_SECONDARY)

        self._build_details_content()

    def _test_connection(self):
        """Test SSH connection to the selected server."""
        if not self.selected_server:
            return

        server = self.servers.get(self.selected_server)
        if not server:
            return

        self.toast.info(f"Testing connection to {server.name}...")
        self.test_conn_btn.set_enabled(False)

        def test_task():
            try:
                # Force get fresh credentials
                ssh_config = self._get_ssh_config(self.selected_server, force_prompt=False)
                if not ssh_config:
                    self.root.after(0, lambda: self._show_test_result(
                        False, "No credentials provided"
                    ))
                    return

                # Create a new connection for testing
                from ssh_manager import SSHConnection
                test_conn = SSHConnection(ssh_config, f"test-{self.selected_server}")

                success, message = test_conn.connect()

                if success:
                    # Try a simple command
                    result = test_conn.execute("echo 'Connection test successful'", timeout=10)
                    test_conn.disconnect()

                    if result.success:
                        self.root.after(0, lambda: self._show_test_result(
                            True, f"Connection successful! Server responded correctly."
                        ))
                    else:
                        self.root.after(0, lambda: self._show_test_result(
                            False, f"Connected but command failed: {result.error}"
                        ))
                else:
                    self.root.after(0, lambda: self._show_test_result(False, message))

            except Exception as e:
                logger.exception(f"Connection test error: {e}")
                error_msg = str(e)
                self.root.after(0, lambda: self._show_test_result(False, error_msg))

        thread = threading.Thread(target=test_task, daemon=True)
        thread.start()

    def _show_test_result(self, success: bool, message: str):
        """Show connection test result."""
        self.test_conn_btn.set_enabled(True)

        if success:
            self.toast.success("Connection test passed!")
            self._hide_error()
            # Update status
            self._update_server_state(self.selected_server, {'status': 'online', 'error': None})
        else:
            self.toast.error(f"Connection failed")
            self._show_error(message)
            self._update_server_state(self.selected_server, {'status': 'offline', 'error': message})

        server = self.servers.get(self.selected_server)
        if not server:
            return

        self.toast.info(f"Testing connection to {server.name}...")
        self.test_conn_btn.set_enabled(False)

        def test_task():
            try:
                # Force get fresh credentials
                ssh_config = self._get_ssh_config(self.selected_server)
                if not ssh_config:
                    self.root.after(0, lambda: self._show_test_result(
                        False, "No credentials provided"
                    ))
                    return

                # Create a new connection for testing
                from ssh_manager import SSHConnection
                test_conn = SSHConnection(ssh_config, f"test-{self.selected_server}")

                success, message = test_conn.connect()

                if success:
                    # Try a simple command
                    result = test_conn.execute("echo 'Connection test successful'", timeout=10)
                    test_conn.disconnect()

                    if result.success:
                        self.root.after(0, lambda: self._show_test_result(
                            True, f"Connection successful!\nServer responded correctly."
                        ))
                    else:
                        self.root.after(0, lambda: self._show_test_result(
                            False, f"Connected but command failed: {result.error}"
                        ))
                else:
                    self.root.after(0, lambda: self._show_test_result(False, message))

            except Exception as e:
                logger.exception(f"Connection test error: {e}")
                self.root.after(0, lambda: self._show_test_result(False, str(e)))

        thread = threading.Thread(target=test_task, daemon=True)
        thread.start()

    def _show_test_result(self, success: bool, message: str):
        """Show connection test result."""
        self.test_conn_btn.set_enabled(True)

        if success:
            self.toast.success("Connection test passed!")
            self._hide_error()
            # Update status
            self._update_server_state(self.selected_server, {'status': 'online'})
        else:
            self.toast.error(f"Connection failed")
            self._show_error(message)
            self._update_server_state(self.selected_server, {'status': 'offline'})

    def _show_error(self, message: str):
        """Show error message in details panel."""
        self.error_label.config(text=f"⚠️ {message}")
        # Only pack if not already packed
        if not self.error_frame.winfo_ismapped():
            self.error_frame.pack(fill='x', padx=20, pady=(10, 0))

    def _hide_error(self):
        """Hide error message."""
        if self.error_frame.winfo_ismapped():
            self.error_frame.pack_forget()

    def _clear_credentials(self):
        """Clear stored credentials and prompt for new ones."""
        if not self.selected_server:
            return

        server = self.servers.get(self.selected_server)
        if not server:
            return

        # Confirm action
        if not messagebox.askyesno(
                "Clear Credentials",
                f"Clear stored credentials for {server.name}?\n\n"
                "You will be prompted to enter new credentials."
        ):
            return

        server_id = self.selected_server

        # Clear from encrypted storage
        try:
            self.security.encryption.remove_server_credentials(server_id)
        except Exception as e:
            logger.error(f"Error removing credentials: {e}")

        # Clear from memory/session
        if server_id in self.server_states:
            self.server_states[server_id].pop('_temp_credentials', None)

        # Clear from in-memory server config
        if hasattr(server, 'password'):
            server.password = None
        if hasattr(server, 'key_passphrase'):
            server.key_passphrase = None

        # Reset connection in pool
        self._pool.remove_connection(server_id)

        self.toast.info("Credentials cleared. Enter new credentials to connect.")

        # Hide any existing error
        self._hide_error()

        # Prompt for new credentials immediately
        self._test_connection()

    def _reconnect_server(self):
        """Force reconnect to the selected server."""
        if not self.selected_server:
            return

        server = self.servers.get(self.selected_server)
        if not server:
            return

        # Remove existing connection from pool
        self._pool.remove_connection(self.selected_server)

        self.toast.info(f"Reconnecting to {server.name}...")

        # Hide any existing error
        self._hide_error()

        # Refresh server (will establish new connection)
        self._refresh_server(self.selected_server)

    def _build_details_content(self):
        """Build details panel content."""
        container = self.details_content

        # Initialize info_labels dictionary
        self.info_labels = {}

        # Header
        header = tk.Frame(container, bg=Colors.BG_SECONDARY)
        header.pack(fill='x', padx=20, pady=20)

        # Server name and status
        name_frame = tk.Frame(header, bg=Colors.BG_SECONDARY)
        name_frame.pack(side='left')

        self.detail_status = StatusIndicator(name_frame, size=16)
        self.detail_status.pack(side='left', padx=(0, 10))

        self.detail_name = tk.Label(
            name_frame,
            text="Server Name",
            font=Fonts.get(16, bold=True),
            fg=Colors.TEXT_PRIMARY,
            bg=Colors.BG_SECONDARY
        )
        self.detail_name.pack(side='left')

        # Action buttons - Service control
        actions_frame = tk.Frame(header, bg=Colors.BG_SECONDARY)
        actions_frame.pack(side='right')

        self.start_btn = ModernButton(
            actions_frame, text="▶ Start", command=self._start_service,
            width=80, height=32, accent_color=Colors.ACCENT_SUCCESS
        )
        self.start_btn.pack(side='left', padx=5)

        self.stop_btn = ModernButton(
            actions_frame, text="■ Stop", command=self._stop_service,
            width=80, height=32, accent_color=Colors.ACCENT_DANGER
        )
        self.stop_btn.pack(side='left', padx=5)

        self.restart_btn = ModernButton(
            actions_frame, text="↻ Restart", command=self._restart_service,
            width=90, height=32, accent_color=Colors.ACCENT_WARNING
        )
        self.restart_btn.pack(side='left', padx=5)

        # Connection management buttons
        conn_frame = tk.Frame(container, bg=Colors.BG_SECONDARY)
        conn_frame.pack(fill='x', padx=20, pady=(0, 10))

        self.test_conn_btn = ModernButton(
            conn_frame, text="🔌 Test Connection", command=self._test_connection,
            width=140, height=28, bg_color=Colors.BG_TERTIARY
        )
        self.test_conn_btn.pack(side='left', padx=(0, 10))

        self.clear_creds_btn = ModernButton(
            conn_frame, text="🔑 Change Credentials", command=self._clear_credentials,
            width=150, height=28, bg_color=Colors.BG_TERTIARY
        )
        self.clear_creds_btn.pack(side='left', padx=(0, 10))

        self.reconnect_btn = ModernButton(
            conn_frame, text="🔄 Reconnect", command=self._reconnect_server,
            width=110, height=28, bg_color=Colors.BG_TERTIARY
        )
        self.reconnect_btn.pack(side='left')

        # Error display frame (hidden by default)
        self.error_frame = tk.Frame(container, bg=Colors.ACCENT_DANGER, padx=10, pady=8)
        self.error_label = tk.Label(
            self.error_frame,
            text="",
            font=Fonts.get(9),
            fg=Colors.TEXT_PRIMARY,
            bg=Colors.ACCENT_DANGER,
            wraplength=500,
            justify='left'
        )
        self.error_label.pack(fill='x')
        # Don't pack error_frame yet - it will be shown when needed

        # Divider
        ttk.Separator(container, orient='horizontal').pack(fill='x', padx=20, pady=(5, 0))

        # Info cards container
        info_frame = tk.Frame(container, bg=Colors.BG_SECONDARY)
        info_frame.pack(fill='x', padx=20, pady=20)

        # Server info card
        info_card = tk.Frame(info_frame, bg=Colors.BG_CARD, padx=15, pady=15)
        info_card.pack(side='left', fill='both', expand=True, padx=(0, 10))

        tk.Label(
            info_card, text="Server Information",
            font=Fonts.get(11, bold=True), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD
        ).pack(anchor='w', pady=(0, 10))

        # Create info labels
        for label in ['IP Address', 'Type', 'Group', 'Service', 'Uptime']:
            row = tk.Frame(info_card, bg=Colors.BG_CARD)
            row.pack(fill='x', pady=3)

            tk.Label(
                row, text=f"{label}:", font=Fonts.get(9),
                fg=Colors.TEXT_MUTED, bg=Colors.BG_CARD, width=12, anchor='w'
            ).pack(side='left')

            value = tk.Label(
                row, text="-", font=Fonts.get(9, mono=True),
                fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD, anchor='w'
            )
            value.pack(side='left', fill='x', expand=True)
            self.info_labels[label] = value

        # Metrics card
        metrics_card = tk.Frame(info_frame, bg=Colors.BG_CARD, padx=15, pady=15)
        metrics_card.pack(side='left', fill='both', expand=True)

        tk.Label(
            metrics_card, text="System Metrics",
            font=Fonts.get(11, bold=True), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD
        ).pack(anchor='w', pady=(0, 15))

        # CPU bar
        cpu_row = tk.Frame(metrics_card, bg=Colors.BG_CARD)
        cpu_row.pack(fill='x', pady=5)
        tk.Label(
            cpu_row, text="CPU", font=Fonts.get(9),
            fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD, width=8, anchor='w'
        ).pack(side='left')
        self.detail_cpu = MetricBar(cpu_row, width=200, height=18)
        self.detail_cpu.pack(side='left', fill='x', expand=True)

        # RAM bar
        ram_row = tk.Frame(metrics_card, bg=Colors.BG_CARD)
        ram_row.pack(fill='x', pady=5)
        tk.Label(
            ram_row, text="RAM", font=Fonts.get(9),
            fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD, width=8, anchor='w'
        ).pack(side='left')
        self.detail_ram = MetricBar(ram_row, width=200, height=18)
        self.detail_ram.pack(side='left', fill='x', expand=True)

        # Disk bar
        disk_row = tk.Frame(metrics_card, bg=Colors.BG_CARD)
        disk_row.pack(fill='x', pady=5)
        tk.Label(
            disk_row, text="Disk", font=Fonts.get(9),
            fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD, width=8, anchor='w'
        ).pack(side='left')
        self.detail_disk = MetricBar(disk_row, width=200, height=18)
        self.detail_disk.pack(side='left', fill='x', expand=True)

        # Load average
        load_row = tk.Frame(metrics_card, bg=Colors.BG_CARD)
        load_row.pack(fill='x', pady=5)
        tk.Label(
            load_row, text="Load", font=Fonts.get(9),
            fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD, width=8, anchor='w'
        ).pack(side='left')
        self.detail_load = tk.Label(
            load_row, text="- / - / -", font=Fonts.get(9, mono=True),
            fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD
        )
        self.detail_load.pack(side='left')

        # Last updated label
        self.last_update_label = tk.Label(
            container, text="Last updated: -",
            font=Fonts.get(8), fg=Colors.TEXT_MUTED, bg=Colors.BG_SECONDARY
        )
        self.last_update_label.pack(pady=10)

    def _select_server(self, server_id: str):
        """Handle server selection."""
        # Update selection
        if self.selected_server:
            if self.selected_server in self.server_cards:
                self.server_cards[self.selected_server].set_selected(False)

        self.selected_server = server_id

        if server_id in self.server_cards:
            self.server_cards[server_id].set_selected(True)

        # Show details panel
        self.no_selection_label.place_forget()
        self.details_content.pack(fill='both', expand=True)

        # Update details
        self._update_details()

        # Refresh metrics
        self._refresh_server(server_id)

    def _update_details(self):
        """Update details panel for selected server."""
        if not self.selected_server:
            return

        server = self.servers.get(self.selected_server)
        state = self.server_states.get(self.selected_server, {})

        if not server:
            return

        # Check if info_labels exists (safety check)
        if not hasattr(self, 'info_labels') or not self.info_labels:
            logger.warning("info_labels not initialized, skipping update")
            return

        # Update header
        self.detail_name.config(text=server.name)
        self.detail_status.set_status(state.get('status', 'unknown'))

        # Update info labels
        self.info_labels['IP Address'].config(text=server.ip)
        self.info_labels['Type'].config(text=server.server_type)
        self.info_labels['Group'].config(text=server.group or 'None')
        self.info_labels['Service'].config(text=server.service_name or 'N/A')
        self.info_labels['Uptime'].config(text=state.get('uptime', '-'))

        # Update metrics
        self.detail_cpu.set_value(state.get('cpu', 0))
        self.detail_ram.set_value(state.get('ram', 0))
        self.detail_disk.set_value(state.get('disk', 0))

        load = state.get('load', [0, 0, 0])
        if isinstance(load, list) and len(load) >= 3:
            self.detail_load.config(text=f"{load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}")
        else:
            self.detail_load.config(text="- / - / -")

        # Update timestamp
        last_update = state.get('last_update')
        if last_update:
            self.last_update_label.config(
                text=f"Last updated: {last_update.strftime('%H:%M:%S')}"
            )

        # Show/hide error based on state
        error = state.get('error')
        if error:
            self._show_error(error)
        else:
            self._hide_error()

        # Update button states based on status
        status = state.get('status', 'unknown')
        is_online = status == 'online'

        self.start_btn.set_enabled(not is_online)
        self.stop_btn.set_enabled(is_online)
        self.restart_btn.set_enabled(True)

        server = self.servers.get(self.selected_server)
        state = self.server_states.get(self.selected_server, {})

        if not server:
            return

        # Update header
        self.detail_name.config(text=server.name)
        self.detail_status.set_status(state.get('status', 'unknown'))

        # Update info labels
        self.info_labels['IP Address'].config(text=server.ip)
        self.info_labels['Type'].config(text=server.server_type)
        self.info_labels['Group'].config(text=server.group or 'None')
        self.info_labels['Service'].config(
            text=server.service_name or 'N/A'
        )
        self.info_labels['Uptime'].config(text=state.get('uptime', '-'))

        # Update metrics
        self.detail_cpu.set_value(state.get('cpu', 0))
        self.detail_ram.set_value(state.get('ram', 0))
        self.detail_disk.set_value(state.get('disk', 0))

        load = state.get('load', [0, 0, 0])
        self.detail_load.config(
            text=f"{load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}"
        )

        # Update timestamp
        last_update = state.get('last_update')
        if last_update:
            self.last_update_label.config(
                text=f"Last updated: {last_update.strftime('%H:%M:%S')}"
            )

        # Update button states based on status
        status = state.get('status', 'unknown')
        is_online = status == 'online'

        self.start_btn.set_enabled(not is_online)
        self.stop_btn.set_enabled(is_online)
        self.restart_btn.set_enabled(True)

    def _get_ssh_config(self, server_id: str, force_prompt: bool = False) -> Optional[SSHConfig]:
        """
        Build SSH config for a server, requesting credentials if needed.

        Args:
            server_id: Server ID
            force_prompt: Force prompting for credentials even if stored

        Returns:
            SSHConfig or None if cancelled
        """
        server = self.servers.get(server_id)
        if not server:
            return None

        username = server.username
        password = None
        key_passphrase = None
        need_prompt = force_prompt

        if not force_prompt:
            # Priority 1: Check temporary (session-only) credentials
            temp_creds = self.server_states.get(server_id, {}).get('_temp_credentials')
            if temp_creds:
                username = temp_creds.get('username') or username
                password = temp_creds.get('password')
                key_passphrase = temp_creds.get('key_passphrase')

            # Priority 2: Check encrypted stored credentials
            if not password and not key_passphrase:
                stored = self.security.get_server_credentials(server_id)
                if stored:
                    username = stored.get('username') or username
                    password = stored.get('password')
                    key_passphrase = stored.get('key_passphrase')

            # Priority 3: Check JSON config
            if not password and not key_passphrase:
                password = getattr(server, 'password', None)
                key_passphrase = getattr(server, 'key_passphrase', None)

            # Check if we need credentials
            if not password and not key_passphrase:
                if server.key_file:
                    # Check if key needs passphrase
                    try:
                        key_path = os.path.expanduser(server.key_file)
                        paramiko.RSAKey.from_private_key_file(key_path)
                        # No passphrase needed, key loaded successfully
                    except paramiko.ssh_exception.PasswordRequiredException:
                        need_prompt = True
                    except FileNotFoundError:
                        self.toast.error(f"Key file not found: {server.key_file}")
                        return None
                    except Exception as e:
                        # Try to continue, might work without passphrase
                        logger.debug(f"Key load attempt: {e}")
                else:
                    need_prompt = True

        # Prompt for credentials if needed
        if need_prompt:
            dialog = CredentialsDialog(
                self.root,
                server.name,
                server_id,
                default_username=username,
                use_key=bool(server.key_file)
            )
            self.root.wait_window(dialog)

            if not dialog.result:
                return None

            username = dialog.result['username']
            password_or_passphrase = dialog.result['password']
            storage_method = dialog.result['storage_method']

            if server.key_file:
                key_passphrase = password_or_passphrase
                password = None
            else:
                password = password_or_passphrase
                key_passphrase = None

            # Store credentials based on user choice
            self._store_credentials(
                server_id,
                username,
                password_or_passphrase,
                storage_method,
                is_key_passphrase=bool(server.key_file)
            )

        # Build and return SSH config
        key_file = None
        if server.key_file:
            key_file = os.path.expanduser(server.key_file)

        return SSHConfig(
            host=server.ip,
            port=server.port,
            username=username,
            password=password,
            key_file=key_file,
            key_passphrase=key_passphrase,
            timeout=15,
            retry_attempts=1
        )

    def _refresh_server(self, server_id: str):
        """Refresh metrics for a single server."""

        def refresh_task():
            try:
                server = self.servers.get(server_id)
                if not server:
                    return

                ssh_config = self._get_ssh_config(server_id)
                if not ssh_config:
                    self._update_server_state(server_id, {
                        'status': 'unknown',
                        'error': 'No credentials'
                    })
                    return

                # Get connection from pool
                conn = self._pool.get_connection(server_id, ssh_config)

                # Check if previous auth failed - need new credentials
                if conn.auth_failed:
                    self._pool.remove_connection(server_id)
                    conn = self._pool.get_connection(server_id, ssh_config)

                # Connect if needed
                if not conn.is_connected():
                    success, msg = conn.connect()
                    if not success:
                        self._update_server_state(server_id, {
                            'status': 'offline',
                            'error': msg
                        })

                        # Show error in UI
                        self.root.after(0, lambda: self._handle_connection_error(
                            server_id, msg, conn.auth_failed
                        ))
                        return

                # Clear any previous errors
                self.root.after(0, self._hide_error)

                # Collect metrics
                collector = MetricsCollector(conn)
                metrics = collector.collect()

                if metrics.is_valid:
                    # Check service status
                    service_status = 'online'
                    if server.service_name:
                        service_type = ServiceType(server.service_type)
                        controller = get_controller(conn, service_type)
                        service_info = controller.get_status(server.service_name)

                        if service_info.status == ServiceStatus.RUNNING:
                            service_status = 'online'
                        elif service_info.status == ServiceStatus.STOPPED:
                            service_status = 'offline'
                        else:
                            service_status = 'warning'

                    self._update_server_state(server_id, {
                        'status': service_status,
                        'cpu': metrics.cpu_percent,
                        'ram': metrics.ram_percent,
                        'disk': metrics.disk_percent,
                        'uptime': metrics.uptime_formatted,
                        'load': [metrics.load_1, metrics.load_5, metrics.load_15],
                        'hostname': metrics.hostname,
                        'last_update': datetime.now(),
                        'error': None
                    })
                else:
                    self._update_server_state(server_id, {
                        'status': 'warning',
                        'error': metrics.error
                    })

            except Exception as e:
                logger.exception(f"Error refreshing {server_id}: {e}")
                self._update_server_state(server_id, {
                    'status': 'offline',
                    'error': str(e)
                })

        thread = threading.Thread(target=refresh_task, daemon=True)
        thread.start()

    def _handle_connection_error(self, server_id: str, error_msg: str, auth_failed: bool):
        """Handle connection error - show message and optionally prompt for new credentials."""
        if self.selected_server == server_id:
            self._show_error(error_msg)

            if auth_failed:
                # Ask if user wants to re-enter credentials
                if messagebox.askyesno(
                        "Authentication Failed",
                        f"Authentication failed for this server.\n\n"
                        f"Error: {error_msg}\n\n"
                        "Would you like to enter different credentials?"
                ):
                    # Clear old credentials and prompt for new ones
                    self.security.encryption.remove_server_credentials(server_id)
                    self._pool.remove_connection(server_id)

                    if server_id in self.server_states:
                        self.server_states[server_id].pop('_temp_credentials', None)

                    # Get new credentials
                    self._test_connection()

    def _update_server_state(self, server_id: str, updates: Dict[str, Any]):
        """Update server state and refresh UI."""
        if server_id in self.server_states:
            self.server_states[server_id].update(updates)

        # Schedule UI update on main thread
        def update_ui():
            # Update server card
            if server_id in self.server_cards:
                state = self.server_states.get(server_id, {})
                self.server_cards[server_id].update_status(
                    state.get('status', 'unknown'),
                    state.get('cpu', 0),
                    state.get('ram', 0)
                )

            # Update details if this server is selected
            if self.selected_server == server_id:
                self._update_details()

        self.root.after(0, update_ui)

    def _refresh_all(self):
        """Refresh all servers."""
        self.connection_label.config(text="Refreshing...")
        self.connection_indicator.set_status('warning')

        def refresh_all_task():
            for server_id in self.servers:
                try:
                    self._refresh_server_sync(server_id)
                except Exception as e:
                    logger.error(f"Error refreshing {server_id}: {e}")

            self.root.after(0, lambda: self._on_refresh_complete())

        thread = threading.Thread(target=refresh_all_task, daemon=True)
        thread.start()

    def _refresh_server_sync(self, server_id: str):
        """Synchronous server refresh (called from background thread)."""
        server = self.servers.get(server_id)
        if not server:
            return

        # Check for stored credentials only (don't prompt)
        stored = self.security.get_server_credentials(server_id)

        if not stored and not server.key_file:
            # No credentials, mark as unknown
            self._update_server_state(server_id, {'status': 'unknown'})
            return

        ssh_config = SSHConfig(
            host=server.ip,
            port=server.port,
            username=stored.get('username', server.username) if stored else server.username,
            password=stored.get('password') if stored else None,
            key_file=server.key_file,
            key_passphrase=stored.get('key_passphrase') if stored else None,
            timeout=10
        )

        try:
            conn = self._pool.get_connection(server_id, ssh_config)

            if not conn.is_connected():
                success, _ = conn.connect()
                if not success:
                    self._update_server_state(server_id, {'status': 'offline'})
                    return

            # Quick metrics check
            collector = MetricsCollector(conn)
            metrics = collector.collect()

            if metrics.is_valid:
                service_status = 'online'
                if server.service_name:
                    service_type = ServiceType(server.service_type)
                    controller = get_controller(conn, service_type)
                    service_info = controller.get_status(server.service_name)

                    if service_info.status != ServiceStatus.RUNNING:
                        service_status = 'offline' if service_info.status == ServiceStatus.STOPPED else 'warning'

                self._update_server_state(server_id, {
                    'status': service_status,
                    'cpu': metrics.cpu_percent,
                    'ram': metrics.ram_percent,
                    'disk': metrics.disk_percent,
                    'uptime': metrics.uptime_formatted,
                    'load': [metrics.load_1, metrics.load_5, metrics.load_15],
                    'last_update': datetime.now()
                })
            else:
                self._update_server_state(server_id, {'status': 'warning'})

        except Exception as e:
            logger.debug(f"Refresh error for {server_id}: {e}")
            self._update_server_state(server_id, {'status': 'offline'})

    def _on_refresh_complete(self):
        """Called when refresh all completes."""
        online = sum(1 for s in self.server_states.values() if s.get('status') == 'online')
        total = len(self.servers)

        self.connection_label.config(text=f"{online}/{total} Online")
        self.connection_indicator.set_status('online' if online > 0 else 'offline')
        self.toast.success(f"Refreshed {total} servers")

    def _start_service(self):
        """Start service on selected server."""
        if not self.selected_server:
            return

        if not self.security.require_permission(Permission.START_SERVICE):
            self.toast.error("Permission denied: Cannot start services")
            return

        server = self.servers.get(self.selected_server)
        if not server or not server.service_name:
            self.toast.warning("No service configured for this server")
            return

        self._execute_service_action('start')

    def _stop_service(self):
        """Stop service on selected server."""
        if not self.selected_server:
            return

        if not self.security.require_permission(Permission.STOP_SERVICE):
            self.toast.error("Permission denied: Cannot stop services")
            return

        server = self.servers.get(self.selected_server)
        if not server or not server.service_name:
            self.toast.warning("No service configured for this server")
            return

        # Confirm stop action
        if not messagebox.askyesno(
                "Confirm Stop",
                f"Are you sure you want to stop {server.service_name} on {server.name}?"
        ):
            return

        self._execute_service_action('stop')

    def _restart_service(self):
        """Restart service on selected server."""
        if not self.selected_server:
            return

        if not self.security.require_permission(Permission.RESTART_SERVICE):
            self.toast.error("Permission denied: Cannot restart services")
            return

        server = self.servers.get(self.selected_server)
        if not server or not server.service_name:
            self.toast.warning("No service configured for this server")
            return

        self._execute_service_action('restart')

    def _store_credentials(
            self,
            server_id: str,
            username: str,
            password: str,
            storage_method: str,
            is_key_passphrase: bool = False
    ):
        """
        Store credentials based on user's chosen method.

        Args:
            server_id: Server ID
            username: Username
            password: Password or key passphrase
            storage_method: 'none', 'encrypted', or 'json'
            is_key_passphrase: True if password is a key passphrase
        """
        if storage_method == CredentialsDialog.STORAGE_NONE:
            # Don't save - store temporarily in memory only
            # We can store in server_states for this session
            self.server_states[server_id]['_temp_credentials'] = {
                'username': username,
                'password': password if not is_key_passphrase else None,
                'key_passphrase': password if is_key_passphrase else None
            }
            self.toast.info("Credentials stored for this session only")

        elif storage_method == CredentialsDialog.STORAGE_ENCRYPTED:
            # Save encrypted (recommended)
            if is_key_passphrase:
                self.security.set_server_credentials(
                    server_id, username, key_passphrase=password
                )
            else:
                self.security.set_server_credentials(
                    server_id, username, password=password
                )
            self.toast.success("Credentials saved (encrypted)")

        elif storage_method == CredentialsDialog.STORAGE_JSON:
            # Save to JSON config file
            self._save_credentials_to_json(
                server_id, username, password, is_key_passphrase
            )
            self.toast.warning("Credentials saved to config file (plain text)")

    def _save_credentials_to_json(
            self,
            server_id: str,
            username: str,
            password: str,
            is_key_passphrase: bool = False
    ):
        """
        Save credentials to servers.json config file.

        Args:
            server_id: Server ID
            username: Username
            password: Password or key passphrase
            is_key_passphrase: True if password is a key passphrase
        """
        try:
            # Load current config
            with open(self.servers_config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # Find and update the server
            for server in config.get('servers', []):
                if server.get('id') == server_id:
                    if 'ssh' not in server:
                        server['ssh'] = {}

                    server['ssh']['username'] = username

                    if is_key_passphrase:
                        server['ssh']['key_passphrase'] = password
                    else:
                        server['ssh']['password'] = password

                    break

            # Write back to file
            with open(self.servers_config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            # Update in-memory config too
            if server_id in self.servers:
                if is_key_passphrase:
                    self.servers[server_id].key_passphrase = password
                else:
                    self.servers[server_id].password = password
                self.servers[server_id].username = username

            logger.info(f"Saved credentials to JSON for {server_id}")

            # Log this action
            self.security.log_action(
                "SAVE_CREDENTIALS_JSON",
                server_id,
                "Credentials saved to config file",
                True
            )

        except Exception as e:
            logger.error(f"Failed to save credentials to JSON: {e}")
            self.toast.error(f"Failed to save: {e}")

    def _execute_service_action(self, action: str):
        """
        Execute a service control action.

        Args:
            action: 'start', 'stop', or 'restart'
        """
        server_id = self.selected_server
        server = self.servers.get(server_id)

        if not server:
            return

        self.toast.info(f"{action.capitalize()}ing {server.service_name}...")

        # Disable buttons during operation
        self.start_btn.set_enabled(False)
        self.stop_btn.set_enabled(False)
        self.restart_btn.set_enabled(False)

        def action_task():
            try:
                ssh_config = self._get_ssh_config(server_id)
                if not ssh_config:
                    self.root.after(0, lambda: self._on_action_complete(
                        False, "Credentials required", action, server.name
                    ))
                    return

                conn = self._pool.get_connection(server_id, ssh_config)

                if not conn.is_connected():
                    success, msg = conn.connect()
                    if not success:
                        self.root.after(0, lambda: self._on_action_complete(
                            False, msg, action, server.name
                        ))
                        return

                # Get service controller
                service_type = ServiceType(server.service_type)
                controller = get_controller(
                    conn, service_type,
                    custom_commands=server.custom_commands
                )

                # Execute action
                if action == 'start':
                    success, message = controller.start(server.service_name)
                elif action == 'stop':
                    success, message = controller.stop(server.service_name)
                else:
                    success, message = controller.restart(server.service_name)

                # Log action
                self.security.log_action(
                    action.upper(),
                    f"{server.name}/{server.service_name}",
                    message,
                    success
                )

                # Update status
                if success:
                    new_status = 'online' if action in ('start', 'restart') else 'offline'
                    self._update_server_state(server_id, {'status': new_status})

                self.root.after(0, lambda: self._on_action_complete(
                    success, message, action, server.name
                ))

            except Exception as e:
                logger.exception(f"Service action error: {e}")
                self.root.after(0, lambda: self._on_action_complete(
                    False, str(e), action, server.name
                ))

        thread = threading.Thread(target=action_task, daemon=True)
        thread.start()

    def _on_action_complete(
            self,
            success: bool,
            message: str,
            action: str,
            server_name: str
    ):
        """Handle service action completion."""
        if success:
            self.toast.success(f"{action.capitalize()} successful: {server_name}")
        else:
            self.toast.error(f"{action.capitalize()} failed: {message}")

        # Re-enable buttons and refresh
        self._update_details()

        # Refresh server metrics after short delay
        if self.selected_server:
            self.root.after(1000, lambda: self._refresh_server(self.selected_server))

    def _start_auto_refresh(self):
        """Start background auto-refresh."""

        def refresh_loop():
            while self._running:
                # Wait for interval
                for _ in range(30):  # 30 second refresh
                    if not self._running:
                        return
                    threading.Event().wait(1)

                # Refresh all servers
                if self._running:
                    for server_id in self.servers:
                        if not self._running:
                            break
                        try:
                            self._refresh_server_sync(server_id)
                        except Exception as e:
                            logger.debug(f"Auto-refresh error: {e}")

        self._refresh_thread = threading.Thread(
            target=refresh_loop,
            name="AutoRefresh",
            daemon=True
        )
        self._refresh_thread.start()

    def _logout(self):
        """Log out current user."""
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
            self.security.logout()
            self._on_close()

    def _on_close(self):
        """Handle application close."""
        self._running = False

        # Close SSH connections
        shutdown_pool()

        # Destroy window
        self.root.destroy()

    def run(self):
        """Start the application."""
        # Show login dialog
        login = LoginDialog(self.root, self.security)
        self.root.wait_window(login)

        if not login.authenticated:
            self.root.destroy()
            return

        # Rebuild header with user info
        for widget in self.root.winfo_children():
            widget.destroy()
        self._build_ui()

        # Initial refresh
        self.root.after(500, self._refresh_all)

        # Start auto-refresh
        self._start_auto_refresh()

        # Start main loop
        self.root.mainloop()