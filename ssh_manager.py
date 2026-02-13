"""
SSH Manager Module
==================
Provides SSH connection pooling, command execution,
and connection lifecycle management.

Features:
- Persistent connection pool with automatic reconnection
- Thread-safe connection access
- Support for password and key-based authentication
- Configurable timeouts and retry logic
"""

import paramiko
import socket
import threading
import time
import logging
import os
from typing import Optional, Dict, Any, Tuple, List, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from queue import Queue, Empty
from contextlib import contextmanager

logger = logging.getLogger('ServerControlPro.SSH')


class AuthMethod(Enum):
    """SSH authentication methods."""
    PASSWORD = "password"
    KEY_FILE = "key_file"
    KEY_DATA = "key_data"


class ConnectionState(Enum):
    """Connection state enumeration."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


@dataclass
class SSHConfig:
    """
    SSH connection configuration.

    Attributes:
        host: Server hostname or IP address
        port: SSH port number
        username: SSH username
        password: Password for authentication (if using password auth)
        key_file: Path to private key file (if using key auth)
        key_passphrase: Passphrase for encrypted private key
        timeout: Connection timeout in seconds
        keepalive_interval: Keepalive packet interval
        retry_attempts: Number of connection retry attempts
        retry_delay: Delay between retry attempts
    """
    host: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None
    key_file: Optional[str] = None
    key_passphrase: Optional[str] = None
    timeout: int = 10
    keepalive_interval: int = 30
    retry_attempts: int = 3
    retry_delay: float = 2.0

    def __post_init__(self):
        """Validate and expand configuration."""
        # Expand ~ in key file path
        if self.key_file:
            self.key_file = os.path.expanduser(self.key_file)

    @property
    def auth_method(self) -> AuthMethod:
        """Determine authentication method based on config."""
        if self.key_file:
            return AuthMethod.KEY_FILE
        return AuthMethod.PASSWORD

    def validate(self) -> Tuple[bool, str]:
        """
        Validate configuration.

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.host:
            return False, "Host is required"

        if not self.username:
            return False, "Username is required"

        if self.key_file:
            key_path = Path(self.key_file)
            if not key_path.exists():
                return False, f"SSH key file not found: {self.key_file}"
            if not os.access(self.key_file, os.R_OK):
                return False, f"SSH key file not readable: {self.key_file}"
        elif not self.password:
            return False, "Password or key file required"

        if not 1 <= self.port <= 65535:
            return False, f"Invalid port: {self.port}"

        return True, "Valid"


@dataclass
class CommandResult:
    """
    Result of a command execution.

    Attributes:
        success: Whether command executed successfully
        exit_code: Command exit code
        stdout: Standard output
        stderr: Standard error
        duration: Execution duration in seconds
        error: Error message if failed
    """
    success: bool
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    error: str = ""


class SSHConnection:
    """
    Manages a single SSH connection with automatic reconnection.

    This class provides thread-safe SSH connection management with
    connection pooling, keepalive, and automatic reconnection.
    """

    def __init__(self, config: SSHConfig, connection_id: str):
        """Initialize SSH connection."""
        self.config = config
        self.connection_id = connection_id
        self.client: Optional[paramiko.SSHClient] = None
        self.state = ConnectionState.DISCONNECTED
        self.last_error: str = ""
        self.last_activity: float = 0
        self.connect_time: Optional[float] = None
        self.auth_failed: bool = False  # Track auth failures

        self._lock = threading.RLock()
        self._state_callbacks: List[Callable] = []

    def add_state_callback(self, callback: Callable[[ConnectionState], None]):
        """Register callback for state changes."""
        self._state_callbacks.append(callback)

    def _notify_state_change(self, new_state: ConnectionState):
        """Notify all callbacks of state change."""
        self.state = new_state
        for callback in self._state_callbacks:
            try:
                callback(new_state)
            except Exception as e:
                logger.error(f"State callback error: {e}")

    def connect(self) -> Tuple[bool, str]:
        """
        Establish SSH connection.

        Returns:
            Tuple of (success, message)
        """
        with self._lock:
            # Reset auth failed flag
            self.auth_failed = False

            # Close any existing connection first
            if self.client:
                try:
                    self.client.close()
                except:
                    pass
                self.client = None

            # Validate configuration first
            is_valid, validation_msg = self.config.validate()
            if not is_valid:
                self.last_error = validation_msg
                self._notify_state_change(ConnectionState.ERROR)
                return False, validation_msg

            self._notify_state_change(ConnectionState.CONNECTING)

            for attempt in range(1, self.config.retry_attempts + 1):
                try:
                    logger.info(
                        f"Connection attempt {attempt}/{self.config.retry_attempts} "
                        f"to {self.config.host}:{self.config.port} as {self.config.username}"
                    )

                    # Create new client for each attempt
                    self.client = paramiko.SSHClient()
                    self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    # Build connection parameters
                    connect_kwargs = {
                        'hostname': self.config.host,
                        'port': self.config.port,
                        'username': self.config.username,
                        'timeout': self.config.timeout,
                        'allow_agent': False,
                        'look_for_keys': False,
                        'banner_timeout': self.config.timeout
                    }

                    # Configure authentication
                    if self.config.key_file:
                        private_key = self._load_private_key()
                        if private_key is None:
                            self.auth_failed = True
                            return False, self.last_error
                        connect_kwargs['pkey'] = private_key
                    elif self.config.password:
                        connect_kwargs['password'] = self.config.password
                    else:
                        self.last_error = "No password or key file provided"
                        self.auth_failed = True
                        return False, self.last_error

                    # Connect
                    self.client.connect(**connect_kwargs)

                    # Configure keepalive
                    transport = self.client.get_transport()
                    if transport:
                        transport.set_keepalive(self.config.keepalive_interval)

                    self.connect_time = time.time()
                    self.last_activity = time.time()
                    self.last_error = ""
                    self._notify_state_change(ConnectionState.CONNECTED)

                    logger.info(
                        f"Successfully connected to {self.config.host}:{self.config.port} "
                        f"as {self.config.username}"
                    )
                    return True, "Connected successfully"

                except paramiko.AuthenticationException as e:
                    self.last_error = f"Authentication failed: Check username and password"
                    self.auth_failed = True
                    logger.error(f"Auth failed for {self.config.host}: {e}")
                    self._notify_state_change(ConnectionState.ERROR)
                    # Don't retry on auth failure - wrong credentials
                    return False, self.last_error

                except paramiko.SSHException as e:
                    self.last_error = f"SSH error: {e}"
                    logger.warning(f"SSH error (attempt {attempt}): {e}")

                except socket.timeout:
                    self.last_error = "Connection timeout - server may be unreachable"
                    logger.warning(f"Timeout (attempt {attempt})")

                except socket.gaierror as e:
                    self.last_error = f"Cannot resolve hostname: {self.config.host}"
                    logger.error(f"DNS error for {self.config.host}: {e}")
                    self._notify_state_change(ConnectionState.ERROR)
                    return False, self.last_error

                except ConnectionRefusedError:
                    self.last_error = f"Connection refused - SSH service may not be running on port {self.config.port}"
                    logger.error(f"Connection refused for {self.config.host}:{self.config.port}")

                except socket.error as e:
                    self.last_error = f"Network error: {e}"
                    logger.warning(f"Socket error (attempt {attempt}): {e}")

                except Exception as e:
                    self.last_error = f"Unexpected error: {e}"
                    logger.exception(f"Unexpected error: {e}")

                # Clean up failed client
                if self.client:
                    try:
                        self.client.close()
                    except:
                        pass
                    self.client = None

                # Wait before retry (except on last attempt)
                if attempt < self.config.retry_attempts:
                    time.sleep(self.config.retry_delay)

            self._notify_state_change(ConnectionState.ERROR)
            return False, self.last_error

    def _load_private_key(self) -> Optional[paramiko.PKey]:
        """
        Load private key from file, trying multiple key types.

        Returns:
            Loaded private key or None on failure
        """
        key_classes = [
            ('RSA', paramiko.RSAKey),
            ('Ed25519', paramiko.Ed25519Key),
            ('ECDSA', paramiko.ECDSAKey),
            ('DSS', paramiko.DSSKey),
        ]

        errors = []
        for key_name, key_class in key_classes:
            try:
                key = key_class.from_private_key_file(
                    self.config.key_file,
                    password=self.config.key_passphrase
                )
                logger.debug(f"Loaded {key_name} key from {self.config.key_file}")
                return key
            except paramiko.PasswordRequiredException:
                self.last_error = "Key file requires passphrase"
                return None
            except Exception as e:
                errors.append(f"{key_name}: {e}")

        self.last_error = f"Failed to load key: {'; '.join(errors)}"
        logger.error(self.last_error)
        return None

    def disconnect(self):
        """Close SSH connection."""
        with self._lock:
            if self.client:
                try:
                    self.client.close()
                except Exception as e:
                    logger.debug(f"Error closing connection: {e}")
                finally:
                    self.client = None

            self._notify_state_change(ConnectionState.DISCONNECTED)
            self.connect_time = None
            logger.info(f"Disconnected from {self.config.host}")

    def is_connected(self) -> bool:
        """
        Check if connection is active and usable.

        Returns:
            True if connection is active
        """
        with self._lock:
            if not self.client:
                return False

            try:
                transport = self.client.get_transport()
                if transport and transport.is_active():
                    # Send keepalive to verify connection
                    transport.send_ignore()
                    return True
            except Exception:
                pass

            self._notify_state_change(ConnectionState.DISCONNECTED)
            return False

    def ensure_connected(self) -> Tuple[bool, str]:
        """
        Ensure connection is established, reconnecting if needed.

        Returns:
            Tuple of (connected, message)
        """
        if self.is_connected():
            return True, "Already connected"
        return self.connect()

    def execute(
            self,
            command: str,
            timeout: int = 30,
            get_pty: bool = False
    ) -> CommandResult:
        """
        Execute command on remote server.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds
            get_pty: Whether to request a pseudo-terminal

        Returns:
            CommandResult with execution results
        """
        start_time = time.time()

        # Ensure connected
        connected, msg = self.ensure_connected()
        if not connected:
            return CommandResult(
                success=False,
                error=f"Not connected: {msg}"
            )

        with self._lock:
            try:
                self.last_activity = time.time()

                # Execute command
                stdin, stdout, stderr = self.client.exec_command(
                    command,
                    timeout=timeout,
                    get_pty=get_pty
                )

                # Read output
                stdout_data = stdout.read().decode('utf-8', errors='replace').strip()
                stderr_data = stderr.read().decode('utf-8', errors='replace').strip()
                exit_code = stdout.channel.recv_exit_status()

                duration = time.time() - start_time

                logger.debug(
                    f"Command on {self.config.host}: '{command[:50]}...' "
                    f"exit={exit_code} duration={duration:.2f}s"
                )

                return CommandResult(
                    success=(exit_code == 0),
                    exit_code=exit_code,
                    stdout=stdout_data,
                    stderr=stderr_data,
                    duration=duration
                )

            except socket.timeout:
                return CommandResult(
                    success=False,
                    error="Command timeout",
                    duration=time.time() - start_time
                )
            except paramiko.SSHException as e:
                logger.error(f"SSH error executing command: {e}")
                return CommandResult(
                    success=False,
                    error=f"SSH error: {e}",
                    duration=time.time() - start_time
                )
            except Exception as e:
                logger.exception(f"Command execution error: {e}")
                return CommandResult(
                    success=False,
                    error=str(e),
                    duration=time.time() - start_time
                )

    def execute_sudo(
            self,
            command: str,
            sudo_password: Optional[str] = None,
            timeout: int = 30
    ) -> CommandResult:
        """
        Execute command with sudo privileges.

        Args:
            command: Command to execute
            sudo_password: Password for sudo (uses SSH password if not provided)
            timeout: Command timeout

        Returns:
            CommandResult
        """
        password = sudo_password or self.config.password

        if password:
            # Use echo to provide password to sudo
            sudo_cmd = f"echo {password} | sudo -S {command}"
        else:
            # Assume passwordless sudo
            sudo_cmd = f"sudo {command}"

        return self.execute(sudo_cmd, timeout=timeout, get_pty=True)

    @property
    def uptime(self) -> Optional[float]:
        """Get connection uptime in seconds."""
        if self.connect_time and self.is_connected():
            return time.time() - self.connect_time
        return None

    def reset(self):
        """Reset connection completely (use when credentials change)."""
        with self._lock:
            self.disconnect()
            self.auth_failed = False
            self.last_error = ""


class SSHConnectionPool:
    """
    Thread-safe SSH connection pool.

    Manages multiple SSH connections with automatic lifecycle management,
    connection reuse, and cleanup.
    """

    def __init__(self, max_connections: int = 50):
        """
        Initialize connection pool.

        Args:
            max_connections: Maximum number of simultaneous connections
        """
        self.max_connections = max_connections
        self._connections: Dict[str, SSHConnection] = {}
        self._lock = threading.RLock()
        self._cleanup_thread: Optional[threading.Thread] = None
        self._running = True

        # Start cleanup thread
        self._start_cleanup_thread()

    def _start_cleanup_thread(self):
        """Start background thread for connection cleanup."""
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="SSHCleanup",
            daemon=True
        )
        self._cleanup_thread.start()

    def _cleanup_loop(self):
        """Background loop to cleanup idle connections."""
        IDLE_TIMEOUT = 300  # 5 minutes
        CHECK_INTERVAL = 60  # 1 minute

        while self._running:
            time.sleep(CHECK_INTERVAL)

            with self._lock:
                now = time.time()
                to_remove = []

                for conn_id, conn in self._connections.items():
                    # Remove disconnected or idle connections
                    if not conn.is_connected():
                        to_remove.append(conn_id)
                    elif now - conn.last_activity > IDLE_TIMEOUT:
                        logger.info(f"Closing idle connection: {conn_id}")
                        conn.disconnect()
                        to_remove.append(conn_id)

                for conn_id in to_remove:
                    del self._connections[conn_id]

    def get_connection(
            self,
            server_id: str,
            config: SSHConfig
    ) -> SSHConnection:
        """
        Get or create SSH connection for a server.

        Args:
            server_id: Unique server identifier
            config: SSH configuration

        Returns:
            SSHConnection instance
        """
        with self._lock:
            if server_id in self._connections:
                conn = self._connections[server_id]
                # Update config if changed
                conn.config = config
                return conn

            # Check pool limit
            if len(self._connections) >= self.max_connections:
                # Remove oldest idle connection
                oldest = min(
                    self._connections.items(),
                    key=lambda x: x[1].last_activity
                )
                oldest[1].disconnect()
                del self._connections[oldest[0]]

            # Create new connection
            conn = SSHConnection(config, server_id)
            self._connections[server_id] = conn
            return conn

    def remove_connection(self, server_id: str):
        """Remove and close a connection."""
        with self._lock:
            if server_id in self._connections:
                self._connections[server_id].disconnect()
                del self._connections[server_id]

    def get_connection_state(self, server_id: str) -> ConnectionState:
        """Get state of a connection."""
        with self._lock:
            if server_id in self._connections:
                return self._connections[server_id].state
            return ConnectionState.DISCONNECTED

    def close_all(self):
        """Close all connections and shutdown pool."""
        self._running = False

        with self._lock:
            for conn in self._connections.values():
                conn.disconnect()
            self._connections.clear()

        logger.info("SSH connection pool closed")

    @property
    def active_connections(self) -> int:
        """Get count of active connections."""
        with self._lock:
            return sum(1 for c in self._connections.values() if c.is_connected())

    @property
    def total_connections(self) -> int:
        """Get total connection count."""
        with self._lock:
            return len(self._connections)


# Global connection pool instance
_pool: Optional[SSHConnectionPool] = None


def get_pool() -> SSHConnectionPool:
    """Get global SSH connection pool instance."""
    global _pool
    if _pool is None:
        _pool = SSHConnectionPool()
    return _pool


def shutdown_pool():
    """Shutdown global connection pool."""
    global _pool
    if _pool:
        _pool.close_all()
        _pool = None
