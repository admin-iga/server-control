"""
Service Control Module
======================
Provides abstraction for managing services across different
service managers (systemd, Docker, PM2, Supervisor, custom).
"""

import logging
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod

from ssh_manager import SSHConnection, CommandResult

logger = logging.getLogger('ServerControlPro.Services')


class ServiceType(Enum):
    """Supported service manager types."""
    SYSTEMD = "systemd"
    DOCKER = "docker"
    PM2 = "pm2"
    SUPERVISOR = "supervisor"
    SYSVINIT = "sysvinit"
    CUSTOM = "custom"


class ServiceStatus(Enum):
    """Service status states."""
    RUNNING = "running"
    STOPPED = "stopped"
    RESTARTING = "restarting"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass
class ServiceInfo:
    """
    Service status information.

    Attributes:
        name: Service name
        status: Current status
        pid: Process ID if running
        uptime: Uptime string
        memory: Memory usage
        cpu: CPU usage percentage
        details: Additional details
    """
    name: str
    status: ServiceStatus
    pid: Optional[int] = None
    uptime: Optional[str] = None
    memory: Optional[str] = None
    cpu: Optional[float] = None
    details: str = ""


class ServiceController(ABC):
    """Abstract base class for service controllers."""

    def __init__(self, connection: SSHConnection):
        self.connection = connection

    @abstractmethod
    def get_status(self, service_name: str) -> ServiceInfo:
        """Get service status."""
        pass

    @abstractmethod
    def start(self, service_name: str) -> Tuple[bool, str]:
        """Start service."""
        pass

    @abstractmethod
    def stop(self, service_name: str) -> Tuple[bool, str]:
        """Stop service."""
        pass

    @abstractmethod
    def restart(self, service_name: str) -> Tuple[bool, str]:
        """Restart service."""
        pass

    def execute(self, command: str, use_sudo: bool = False) -> CommandResult:
        """Execute command, optionally with sudo."""
        if use_sudo:
            return self.connection.execute_sudo(command)
        return self.connection.execute(command)


class SystemdController(ServiceController):
    """Controller for systemd services."""

    def get_status(self, service_name: str) -> ServiceInfo:
        """Get systemd service status."""
        # Get active state
        result = self.execute(f"systemctl is-active {service_name}")
        active = result.stdout.strip()

        if active == "active":
            status = ServiceStatus.RUNNING
        elif active in ("inactive", "dead"):
            status = ServiceStatus.STOPPED
        elif active == "failed":
            status = ServiceStatus.FAILED
        elif active == "reloading":
            status = ServiceStatus.RESTARTING
        else:
            status = ServiceStatus.UNKNOWN

        info = ServiceInfo(name=service_name, status=status)

        # Get detailed info if running
        if status == ServiceStatus.RUNNING:
            # Get PID
            pid_result = self.execute(
                f"systemctl show {service_name} --property=MainPID --value"
            )
            if pid_result.success and pid_result.stdout.strip().isdigit():
                info.pid = int(pid_result.stdout.strip())

            # Get uptime
            uptime_result = self.execute(
                f"systemctl show {service_name} --property=ActiveEnterTimestamp --value"
            )
            if uptime_result.success:
                info.uptime = uptime_result.stdout.strip()

            # Get memory usage
            mem_result = self.execute(
                f"systemctl show {service_name} --property=MemoryCurrent --value"
            )
            if mem_result.success and mem_result.stdout.strip() != "[not set]":
                try:
                    mem_bytes = int(mem_result.stdout.strip())
                    info.memory = self._format_bytes(mem_bytes)
                except ValueError:
                    pass

        return info

    def start(self, service_name: str) -> Tuple[bool, str]:
        """Start systemd service."""
        result = self.execute(f"systemctl start {service_name}", use_sudo=True)
        if result.success:
            logger.info(f"Started systemd service: {service_name}")
            return True, f"Service {service_name} started"
        return False, result.stderr or result.error or "Failed to start service"

    def stop(self, service_name: str) -> Tuple[bool, str]:
        """Stop systemd service."""
        result = self.execute(f"systemctl stop {service_name}", use_sudo=True)
        if result.success:
            logger.info(f"Stopped systemd service: {service_name}")
            return True, f"Service {service_name} stopped"
        return False, result.stderr or result.error or "Failed to stop service"

    def restart(self, service_name: str) -> Tuple[bool, str]:
        """Restart systemd service."""
        result = self.execute(f"systemctl restart {service_name}", use_sudo=True)
        if result.success:
            logger.info(f"Restarted systemd service: {service_name}")
            return True, f"Service {service_name} restarted"
        return False, result.stderr or result.error or "Failed to restart service"

    @staticmethod
    def _format_bytes(bytes_value: int) -> str:
        """Format bytes to human readable string."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024
        return f"{bytes_value:.1f} TB"


class DockerController(ServiceController):
    """Controller for Docker containers."""

    def get_status(self, container_name: str) -> ServiceInfo:
        """Get Docker container status."""
        # Get container state
        result = self.execute(
            f"docker inspect -f '{{{{.State.Status}}}}' {container_name}"
        )

        if not result.success:
            return ServiceInfo(
                name=container_name,
                status=ServiceStatus.UNKNOWN,
                details="Container not found"
            )

        state = result.stdout.strip().lower()

        status_map = {
            "running": ServiceStatus.RUNNING,
            "exited": ServiceStatus.STOPPED,
            "paused": ServiceStatus.STOPPED,
            "restarting": ServiceStatus.RESTARTING,
            "dead": ServiceStatus.FAILED,
            "created": ServiceStatus.STOPPED,
        }
        status = status_map.get(state, ServiceStatus.UNKNOWN)

        info = ServiceInfo(name=container_name, status=status)

        if status == ServiceStatus.RUNNING:
            # Get PID
            pid_result = self.execute(
                f"docker inspect -f '{{{{.State.Pid}}}}' {container_name}"
            )
            if pid_result.success:
                try:
                    info.pid = int(pid_result.stdout.strip())
                except ValueError:
                    pass

            # Get stats
            stats_result = self.execute(
                f"docker stats {container_name} --no-stream --format "
                f"'{{{{.CPUPerc}}}}|{{{{.MemUsage}}}}'"
            )
            if stats_result.success:
                parts = stats_result.stdout.strip().split('|')
                if len(parts) >= 2:
                    try:
                        info.cpu = float(parts[0].replace('%', ''))
                    except ValueError:
                        pass
                    info.memory = parts[1]

        return info

    def start(self, container_name: str) -> Tuple[bool, str]:
        """Start Docker container."""
        result = self.execute(f"docker start {container_name}")
        if result.success:
            logger.info(f"Started Docker container: {container_name}")
            return True, f"Container {container_name} started"
        return False, result.stderr or result.error or "Failed to start container"

    def stop(self, container_name: str) -> Tuple[bool, str]:
        """Stop Docker container."""
        result = self.execute(f"docker stop {container_name}")
        if result.success:
            logger.info(f"Stopped Docker container: {container_name}")
            return True, f"Container {container_name} stopped"
        return False, result.stderr or result.error or "Failed to stop container"

    def restart(self, container_name: str) -> Tuple[bool, str]:
        """Restart Docker container."""
        result = self.execute(f"docker restart {container_name}")
        if result.success:
            logger.info(f"Restarted Docker container: {container_name}")
            return True, f"Container {container_name} restarted"
        return False, result.stderr or result.error or "Failed to restart container"


class PM2Controller(ServiceController):
    """Controller for PM2 process manager."""

    def get_status(self, app_name: str) -> ServiceInfo:
        """Get PM2 application status."""
        result = self.execute(f"pm2 jlist")

        if not result.success:
            return ServiceInfo(
                name=app_name,
                status=ServiceStatus.UNKNOWN,
                details="PM2 not available"
            )

        try:
            import json
            processes = json.loads(result.stdout)

            for proc in processes:
                if proc.get('name') == app_name:
                    pm2_status = proc.get('pm2_env', {}).get('status', '')

                    status_map = {
                        'online': ServiceStatus.RUNNING,
                        'stopped': ServiceStatus.STOPPED,
                        'errored': ServiceStatus.FAILED,
                        'launching': ServiceStatus.RESTARTING,
                    }
                    status = status_map.get(pm2_status, ServiceStatus.UNKNOWN)

                    info = ServiceInfo(
                        name=app_name,
                        status=status,
                        pid=proc.get('pid'),
                        memory=self._format_bytes(proc.get('monit', {}).get('memory', 0)),
                        cpu=proc.get('monit', {}).get('cpu', 0)
                    )
                    return info

            return ServiceInfo(
                name=app_name,
                status=ServiceStatus.UNKNOWN,
                details="Application not found in PM2"
            )

        except (json.JSONDecodeError, KeyError) as e:
            return ServiceInfo(
                name=app_name,
                status=ServiceStatus.UNKNOWN,
                details=f"Failed to parse PM2 output: {e}"
            )

    def start(self, app_name: str) -> Tuple[bool, str]:
        """Start PM2 application."""
        result = self.execute(f"pm2 start {app_name}")
        if result.success or "started" in result.stdout.lower():
            logger.info(f"Started PM2 app: {app_name}")
            return True, f"Application {app_name} started"
        return False, result.stderr or result.error or "Failed to start application"

    def stop(self, app_name: str) -> Tuple[bool, str]:
        """Stop PM2 application."""
        result = self.execute(f"pm2 stop {app_name}")
        if result.success or "stopped" in result.stdout.lower():
            logger.info(f"Stopped PM2 app: {app_name}")
            return True, f"Application {app_name} stopped"
        return False, result.stderr or result.error or "Failed to stop application"

    def restart(self, app_name: str) -> Tuple[bool, str]:
        """Restart PM2 application."""
        result = self.execute(f"pm2 restart {app_name}")
        if result.success or "restarted" in result.stdout.lower():
            logger.info(f"Restarted PM2 app: {app_name}")
            return True, f"Application {app_name} restarted"
        return False, result.stderr or result.error or "Failed to restart application"

    @staticmethod
    def _format_bytes(bytes_value: int) -> str:
        """Format bytes to human readable string."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024
        return f"{bytes_value:.1f} TB"


class SupervisorController(ServiceController):
    """Controller for Supervisor process manager."""

    def get_status(self, program_name: str) -> ServiceInfo:
        """Get Supervisor program status."""
        result = self.execute(f"supervisorctl status {program_name}")

        if not result.success and "no such process" in result.stderr.lower():
            return ServiceInfo(
                name=program_name,
                status=ServiceStatus.UNKNOWN,
                details="Program not found"
            )

        output = result.stdout.strip()
        status = ServiceStatus.UNKNOWN
        pid = None
        uptime = None

        if "RUNNING" in output:
            status = ServiceStatus.RUNNING
            # Parse PID and uptime from output like: "name RUNNING pid 1234, uptime 0:01:23"
            parts = output.split()
            for i, part in enumerate(parts):
                if part == "pid" and i + 1 < len(parts):
                    try:
                        pid = int(parts[i + 1].rstrip(','))
                    except ValueError:
                        pass
                if part == "uptime" and i + 1 < len(parts):
                    uptime = parts[i + 1]

        elif "STOPPED" in output:
            status = ServiceStatus.STOPPED
        elif "FATAL" in output or "BACKOFF" in output:
            status = ServiceStatus.FAILED
        elif "STARTING" in output:
            status = ServiceStatus.RESTARTING

        return ServiceInfo(
            name=program_name,
            status=status,
            pid=pid,
            uptime=uptime,
            details=output
        )

    def start(self, program_name: str) -> Tuple[bool, str]:
        """Start Supervisor program."""
        result = self.execute(f"supervisorctl start {program_name}")
        if result.success or "started" in result.stdout.lower():
            logger.info(f"Started Supervisor program: {program_name}")
            return True, f"Program {program_name} started"
        return False, result.stderr or result.stdout or "Failed to start program"

    def stop(self, program_name: str) -> Tuple[bool, str]:
        """Stop Supervisor program."""
        result = self.execute(f"supervisorctl stop {program_name}")
        if result.success or "stopped" in result.stdout.lower():
            logger.info(f"Stopped Supervisor program: {program_name}")
            return True, f"Program {program_name} stopped"
        return False, result.stderr or result.stdout or "Failed to stop program"

    def restart(self, program_name: str) -> Tuple[bool, str]:
        """Restart Supervisor program."""
        result = self.execute(f"supervisorctl restart {program_name}")
        if result.success or "started" in result.stdout.lower():
            logger.info(f"Restarted Supervisor program: {program_name}")
            return True, f"Program {program_name} restarted"
        return False, result.stderr or result.stdout or "Failed to restart program"


class CustomController(ServiceController):
    """Controller for custom commands."""

    def __init__(
            self,
            connection: SSHConnection,
            start_cmd: str = "",
            stop_cmd: str = "",
            restart_cmd: str = "",
            status_cmd: str = ""
    ):
        super().__init__(connection)
        self.start_cmd = start_cmd
        self.stop_cmd = stop_cmd
        self.restart_cmd = restart_cmd
        self.status_cmd = status_cmd

    def get_status(self, service_name: str) -> ServiceInfo:
        """Get status using custom command."""
        if not self.status_cmd:
            return ServiceInfo(
                name=service_name,
                status=ServiceStatus.UNKNOWN,
                details="No status command configured"
            )

        cmd = self.status_cmd.replace("{name}", service_name)
        result = self.execute(cmd)

        # Try to determine status from exit code
        if result.success:
            status = ServiceStatus.RUNNING
        else:
            status = ServiceStatus.STOPPED

        return ServiceInfo(
            name=service_name,
            status=status,
            details=result.stdout or result.stderr
        )

    def start(self, service_name: str) -> Tuple[bool, str]:
        """Start using custom command."""
        if not self.start_cmd:
            return False, "No start command configured"

        cmd = self.start_cmd.replace("{name}", service_name)
        result = self.execute(cmd, use_sudo=True)

        if result.success:
            return True, f"Started: {service_name}"
        return False, result.stderr or result.error or "Start command failed"

    def stop(self, service_name: str) -> Tuple[bool, str]:
        """Stop using custom command."""
        if not self.stop_cmd:
            return False, "No stop command configured"

        cmd = self.stop_cmd.replace("{name}", service_name)
        result = self.execute(cmd, use_sudo=True)

        if result.success:
            return True, f"Stopped: {service_name}"
        return False, result.stderr or result.error or "Stop command failed"

    def restart(self, service_name: str) -> Tuple[bool, str]:
        """Restart using custom command."""
        if not self.restart_cmd:
            # Fall back to stop + start
            success, msg = self.stop(service_name)
            if not success:
                return False, f"Stop failed: {msg}"
            return self.start(service_name)

        cmd = self.restart_cmd.replace("{name}", service_name)
        result = self.execute(cmd, use_sudo=True)

        if result.success:
            return True, f"Restarted: {service_name}"
        return False, result.stderr or result.error or "Restart command failed"


def get_controller(
        connection: SSHConnection,
        service_type: ServiceType,
        custom_commands: Optional[Dict[str, str]] = None
) -> ServiceController:
    """
    Factory function to get appropriate service controller.

    Args:
        connection: SSH connection to use
        service_type: Type of service manager
        custom_commands: Custom commands for CUSTOM type

    Returns:
        ServiceController instance
    """
    controllers = {
        ServiceType.SYSTEMD: SystemdController,
        ServiceType.DOCKER: DockerController,
        ServiceType.PM2: PM2Controller,
        ServiceType.SUPERVISOR: SupervisorController,
        ServiceType.SYSVINIT: SystemdController,  # Similar commands
    }

    if service_type == ServiceType.CUSTOM:
        commands = custom_commands or {}
        return CustomController(
            connection,
            start_cmd=commands.get('start', ''),
            stop_cmd=commands.get('stop', ''),
            restart_cmd=commands.get('restart', ''),
            status_cmd=commands.get('status', '')
        )

    controller_class = controllers.get(service_type, SystemdController)
    return controller_class(connection)