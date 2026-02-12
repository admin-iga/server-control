"""
SSH Manager Module
==================
Handles real SSH connections to remote servers
for executing commands and gathering metrics.
"""

import paramiko
import socket
import threading
import time
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import re

logger = logging.getLogger('ServerControl.SSH')


class AuthMethod(Enum):
    """SSH authentication methods"""
    PASSWORD = "password"
    KEY_FILE = "key_file"
    KEY_STRING = "key_string"


@dataclass
class SSHConfig:
    """SSH connection configuration"""
    host: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None
    key_file: Optional[str] = None
    key_passphrase: Optional[str] = None
    timeout: int = 10
    service_name: Optional[str] = None
    service_type: str = "systemd"  # systemd, sysvinit, docker, pm2, custom


class SSHConnection:
    """
    Manages SSH connection to a single server.
    Provides methods for command execution and metric collection.
    """

    def __init__(self, config: SSHConfig):
        self.config = config
        self.client: Optional[paramiko.SSHClient] = None
        self._lock = threading.Lock()
        self._connected = False

    def connect(self) -> Tuple[bool, str]:
        """
        Establish SSH connection to the server.

        Returns:
            Tuple of (success: bool, message: str)
        """
        with self._lock:
            try:
                # Create SSH client
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # Prepare connection parameters
                connect_kwargs = {
                    'hostname': self.config.host,
                    'port': self.config.port,
                    'username': self.config.username,
                    'timeout': self.config.timeout,
                    'allow_agent': False,
                    'look_for_keys': False
                }

                # Handle authentication
                if self.config.key_file:
                    # Key-based authentication
                    try:
                        private_key = paramiko.RSAKey.from_private_key_file(
                            self.config.key_file,
                            password=self.config.key_passphrase
                        )
                    except paramiko.ssh_exception.SSHException:
                        # Try other key types
                        try:
                            private_key = paramiko.Ed25519Key.from_private_key_file(
                                self.config.key_file,
                                password=self.config.key_passphrase
                            )
                        except:
                            private_key = paramiko.ECDSAKey.from_private_key_file(
                                self.config.key_file,
                                password=self.config.key_passphrase
                            )
                    connect_kwargs['pkey'] = private_key
                elif self.config.password:
                    # Password authentication
                    connect_kwargs['password'] = self.config.password
                else:
                    return False, "No authentication method provided"

                # Connect
                self.client.connect(**connect_kwargs)
                self._connected = True
                logger.info(f"Connected to {self.config.host}:{self.config.port}")
                return True, "Connected successfully"

            except paramiko.AuthenticationException:
                logger.error(f"Authentication failed for {self.config.host}")
                return False, "Authentication failed"
            except paramiko.SSHException as e:
                logger.error(f"SSH error for {self.config.host}: {e}")
                return False, f"SSH error: {str(e)}"
            except socket.timeout:
                logger.error(f"Connection timeout for {self.config.host}")
                return False, "Connection timeout"
            except socket.error as e:
                logger.error(f"Socket error for {self.config.host}: {e}")
                return False, f"Connection failed: {str(e)}"
            except Exception as e:
                logger.error(f"Unexpected error for {self.config.host}: {e}")
                return False, f"Error: {str(e)}"

    def disconnect(self):
        """Close SSH connection"""
        with self._lock:
            if self.client:
                try:
                    self.client.close()
                except:
                    pass
                self.client = None
            self._connected = False
            logger.info(f"Disconnected from {self.config.host}")

    def is_connected(self) -> bool:
        """Check if connection is active"""
        if not self._connected or not self.client:
            return False

        try:
            transport = self.client.get_transport()
            if transport and transport.is_active():
                # Send keepalive to verify connection
                transport.send_ignore()
                return True
        except:
            pass

        self._connected = False
        return False

    def execute_command(self, command: str, timeout: int = 30) -> Tuple[bool, str, str]:
        """
        Execute command on remote server.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            Tuple of (success: bool, stdout: str, stderr: str)
        """
        if not self.is_connected():
            success, msg = self.connect()
            if not success:
                return False, "", msg

        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)

            # Read output
            stdout_str = stdout.read().decode('utf-8', errors='ignore').strip()
            stderr_str = stderr.read().decode('utf-8', errors='ignore').strip()
            exit_code = stdout.channel.recv_exit_status()

            success = exit_code == 0
            logger.debug(f"Command '{command}' on {self.config.host}: exit={exit_code}")

            return success, stdout_str, stderr_str

        except socket.timeout:
            return False, "", "Command timeout"
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return False, "", str(e)

    def get_system_metrics(self) -> Dict[str, Any]:
        """
        Get CPU and RAM usage from remote server.

        Returns:
            Dict with 'cpu' and 'ram' percentages
        """
        metrics = {'cpu': 0, 'ram': 0, 'online': False}

        # Check if server is reachable
        if not self.is_connected():
            success, msg = self.connect()
            if not success:
                return metrics

        try:
            # Get CPU usage using /proc/stat
            cpu_command = """
            read cpu user nice system idle iowait irq softirq steal guest < /proc/stat
            total1=$((user + nice + system + idle + iowait + irq + softirq + steal))
            idle1=$idle
            sleep 0.5
            read cpu user nice system idle iowait irq softirq steal guest < /proc/stat
            total2=$((user + nice + system + idle + iowait + irq + softirq + steal))
            idle2=$idle
            total_diff=$((total2 - total1))
            idle_diff=$((idle2 - idle1))
            if [ $total_diff -gt 0 ]; then
                cpu_usage=$((100 * (total_diff - idle_diff) / total_diff))
                echo $cpu_usage
            else
                echo 0
            fi
            """

            success, stdout, _ = self.execute_command(cpu_command.strip(), timeout=5)
            if success and stdout:
                try:
                    metrics['cpu'] = min(100, max(0, int(stdout.strip())))
                except ValueError:
                    pass

            # Get RAM usage
            ram_command = "free | awk '/Mem:/ {printf \"%.0f\", ($3/$2) * 100}'"
            success, stdout, _ = self.execute_command(ram_command, timeout=5)
            if success and stdout:
                try:
                    metrics['ram'] = min(100, max(0, int(stdout.strip())))
                except ValueError:
                    pass

            metrics['online'] = True

        except Exception as e:
            logger.error(f"Error getting metrics from {self.config.host}: {e}")

        return metrics

    def check_service_status(self) -> bool:
        """
        Check if the configured service is running.

        Returns:
            True if service is running, False otherwise
        """
        if not self.config.service_name:
            # No specific service, check if server is reachable
            return self.is_connected() or self.connect()[0]

        service_type = self.config.service_type
        service_name = self.config.service_name

        # Build status command based on service type
        if service_type == "systemd":
            command = f"systemctl is-active {service_name}"
        elif service_type == "sysvinit":
            command = f"service {service_name} status"
        elif service_type == "docker":
            command = f"docker inspect -f '{{{{.State.Running}}}}' {service_name}"
        elif service_type == "pm2":
            command = f"pm2 show {service_name} | grep -q 'online'"
        elif service_type == "supervisor":
            command = f"supervisorctl status {service_name} | grep -q RUNNING"
        elif service_type == "custom":
            # Custom command should be set in service_name
            command = service_name
        else:
            command = f"systemctl is-active {service_name}"

        success, stdout, _ = self.execute_command(command, timeout=10)

        # Parse response based on service type
        if service_type == "systemd":
            return stdout.strip() == "active"
        elif service_type == "docker":
            return stdout.strip().lower() == "true"
        else:
            return success

    def start_service(self) -> Tuple[bool, str]:
        """Start the configured service"""
        return self._control_service("start")

    def stop_service(self) -> Tuple[bool, str]:
        """Stop the configured service"""
        return self._control_service("stop")

    def restart_service(self) -> Tuple[bool, str]:
        """Restart the configured service"""
        return self._control_service("restart")

    def _control_service(self, action: str) -> Tuple[bool, str]:
        """
        Execute service control command.

        Args:
            action: 'start', 'stop', or 'restart'

        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.config.service_name:
            return False, "No service configured"

        service_type = self.config.service_type
        service_name = self.config.service_name

        # Build command based on service type
        if service_type == "systemd":
            command = f"sudo systemctl {action} {service_name}"
        elif service_type == "sysvinit":
            command = f"sudo service {service_name} {action}"
        elif service_type == "docker":
            if action == "restart":
                command = f"docker restart {service_name}"
            elif action == "start":
                command = f"docker start {service_name}"
            elif action == "stop":
                command = f"docker stop {service_name}"
            else:
                command = f"docker {action} {service_name}"
        elif service_type == "pm2":
            command = f"pm2 {action} {service_name}"
        elif service_type == "supervisor":
            if action == "restart":
                command = f"supervisorctl restart {service_name}"
            else:
                command = f"supervisorctl {action} {service_name}"
        else:
            command = f"sudo systemctl {action} {service_name}"

        success, stdout, stderr = self.execute_command(command, timeout=30)

        if success:
            message = f"Service {service_name} {action}ed successfully"
            logger.info(message)
            return True, message
        else:
            message = stderr or stdout or f"Failed to {action} service"
            logger.error(f"Failed to {action} {service_name}: {message}")
            return False, message


class SSHManager:
    """
    Manages multiple SSH connections to servers.
    Provides connection pooling and caching.
    """

    def __init__(self):
        self.connections: Dict[str, SSHConnection] = {}
        self._lock = threading.Lock()

    def get_connection(self, server_id: str, config: SSHConfig) -> SSHConnection:
        """
        Get or create SSH connection for a server.

        Args:
            server_id: Unique server identifier
            config: SSH configuration

        Returns:
            SSHConnection instance
        """
        with self._lock:
            if server_id not in self.connections:
                self.connections[server_id] = SSHConnection(config)
            return self.connections[server_id]

    def remove_connection(self, server_id: str):
        """Remove and close a connection"""
        with self._lock:
            if server_id in self.connections:
                self.connections[server_id].disconnect()
                del self.connections[server_id]

    def close_all(self):
        """Close all connections"""
        with self._lock:
            for conn in self.connections.values():
                conn.disconnect()
            self.connections.clear()

    def get_server_status(self, server_id: str, config: SSHConfig) -> Dict[str, Any]:
        """
        Get comprehensive server status.

        Returns:
            Dict with status, cpu, ram, and service_running
        """
        conn = self.get_connection(server_id, config)

        # Get system metrics
        metrics = conn.get_system_metrics()

        # Check service status
        service_running = conn.check_service_status() if config.service_name else metrics['online']

        return {
            'online': metrics['online'],
            'cpu': metrics['cpu'],
            'ram': metrics['ram'],
            'service_running': service_running,
            'status': 'online' if service_running else 'offline'
        }

    def start_server(self, server_id: str, config: SSHConfig) -> Tuple[bool, str]:
        """Start server/service"""
        conn = self.get_connection(server_id, config)

        if not conn.is_connected():
            success, msg = conn.connect()
            if not success:
                return False, f"Cannot connect to server: {msg}"

        return conn.start_service()

    def stop_server(self, server_id: str, config: SSHConfig) -> Tuple[bool, str]:
        """Stop server/service"""
        conn = self.get_connection(server_id, config)

        if not conn.is_connected():
            success, msg = conn.connect()
            if not success:
                return False, f"Cannot connect to server: {msg}"

        return conn.stop_service()

    def restart_server(self, server_id: str, config: SSHConfig) -> Tuple[bool, str]:
        """Restart server/service"""
        conn = self.get_connection(server_id, config)

        if not conn.is_connected():
            success, msg = conn.connect()
            if not success:
                return False, f"Cannot connect to server: {msg}"

        return conn.restart_service()


# Global SSH manager instance
ssh_manager = SSHManager()
