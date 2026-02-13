"""
Metrics Collection Module
=========================
Collects system metrics from remote servers via SSH.

Metrics collected:
- CPU usage
- RAM usage
- Disk usage
- System uptime
- Load average
"""

import logging
import re
import time
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from threading import Thread, Event
from queue import Queue

from ssh_manager import SSHConnection, CommandResult

logger = logging.getLogger('ServerControlPro.Metrics')


@dataclass
class SystemMetrics:
    """
    System metrics data container.

    Attributes:
        cpu_percent: CPU usage percentage (0-100)
        ram_percent: RAM usage percentage (0-100)
        ram_used: RAM used in bytes
        ram_total: Total RAM in bytes
        disk_percent: Root disk usage percentage
        disk_used: Disk used in bytes
        disk_total: Total disk in bytes
        uptime_seconds: System uptime in seconds
        uptime_formatted: Human-readable uptime
        load_1: 1-minute load average
        load_5: 5-minute load average
        load_15: 15-minute load average
        hostname: System hostname
        kernel: Kernel version
        timestamp: When metrics were collected
        error: Error message if collection failed
    """
    cpu_percent: float = 0.0
    ram_percent: float = 0.0
    ram_used: int = 0
    ram_total: int = 0
    disk_percent: float = 0.0
    disk_used: int = 0
    disk_total: int = 0
    uptime_seconds: int = 0
    uptime_formatted: str = ""
    load_1: float = 0.0
    load_5: float = 0.0
    load_15: float = 0.0
    hostname: str = ""
    kernel: str = ""
    timestamp: float = field(default_factory=time.time)
    error: str = ""

    @property
    def is_valid(self) -> bool:
        """Check if metrics were successfully collected."""
        return not self.error and self.timestamp > 0


class MetricsCollector:
    """
    Collects system metrics from a remote server.

    Uses efficient batch commands to minimize SSH round trips.
    """

    # Combined metrics command - executes all metrics gathering in single SSH call
    METRICS_COMMAND = """
    echo "===HOSTNAME==="
    hostname
    echo "===KERNEL==="
    uname -r
    echo "===UPTIME==="
    cat /proc/uptime
    echo "===LOADAVG==="
    cat /proc/loadavg
    echo "===MEMORY==="
    cat /proc/meminfo | grep -E '^(MemTotal|MemAvailable|MemFree|Buffers|Cached):'
    echo "===DISK==="
    df -B1 / | tail -1
    echo "===CPU==="
    head -1 /proc/stat
    sleep 0.2
    head -1 /proc/stat
    """

    def __init__(self, connection: SSHConnection):
        """
        Initialize metrics collector.

        Args:
            connection: SSH connection to use
        """
        self.connection = connection

    def collect(self) -> SystemMetrics:
        """
        Collect all system metrics.

        Returns:
            SystemMetrics object with collected data
        """
        metrics = SystemMetrics()

        # Execute combined metrics command
        result = self.connection.execute(self.METRICS_COMMAND, timeout=15)

        if not result.success:
            metrics.error = result.error or "Failed to collect metrics"
            logger.error(f"Metrics collection failed: {metrics.error}")
            return metrics

        try:
            sections = self._parse_sections(result.stdout)

            # Parse each section
            metrics.hostname = sections.get('HOSTNAME', '').strip()
            metrics.kernel = sections.get('KERNEL', '').strip()

            self._parse_uptime(sections.get('UPTIME', ''), metrics)
            self._parse_loadavg(sections.get('LOADAVG', ''), metrics)
            self._parse_memory(sections.get('MEMORY', ''), metrics)
            self._parse_disk(sections.get('DISK', ''), metrics)
            self._parse_cpu(sections.get('CPU', ''), metrics)

            logger.debug(
                f"Collected metrics from {metrics.hostname}: "
                f"CPU={metrics.cpu_percent:.1f}% RAM={metrics.ram_percent:.1f}%"
            )

        except Exception as e:
            metrics.error = f"Failed to parse metrics: {e}"
            logger.exception(f"Metrics parsing error: {e}")

        return metrics

    def _parse_sections(self, output: str) -> Dict[str, str]:
        """Parse command output into sections."""
        sections = {}
        current_section = None
        current_content = []

        for line in output.split('\n'):
            if line.startswith('===') and line.endswith('==='):
                if current_section:
                    sections[current_section] = '\n'.join(current_content)
                current_section = line[3:-3]
                current_content = []
            elif current_section:
                current_content.append(line)

        if current_section:
            sections[current_section] = '\n'.join(current_content)

        return sections

    def _parse_uptime(self, data: str, metrics: SystemMetrics):
        """Parse /proc/uptime data."""
        try:
            parts = data.strip().split()
            if parts:
                metrics.uptime_seconds = int(float(parts[0]))
                metrics.uptime_formatted = self._format_uptime(metrics.uptime_seconds)
        except (ValueError, IndexError):
            pass

    def _parse_loadavg(self, data: str, metrics: SystemMetrics):
        """Parse /proc/loadavg data."""
        try:
            parts = data.strip().split()
            if len(parts) >= 3:
                metrics.load_1 = float(parts[0])
                metrics.load_5 = float(parts[1])
                metrics.load_15 = float(parts[2])
        except (ValueError, IndexError):
            pass

    def _parse_memory(self, data: str, metrics: SystemMetrics):
        """Parse /proc/meminfo data."""
        mem_info = {}

        for line in data.strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                # Extract numeric value (remove 'kB' suffix)
                match = re.search(r'(\d+)', value)
                if match:
                    mem_info[key.strip()] = int(match.group(1)) * 1024  # Convert to bytes

        try:
            metrics.ram_total = mem_info.get('MemTotal', 0)

            # Calculate available memory
            mem_available = mem_info.get('MemAvailable')
            if mem_available is None:
                # Fallback calculation for older kernels
                mem_free = mem_info.get('MemFree', 0)
                buffers = mem_info.get('Buffers', 0)
                cached = mem_info.get('Cached', 0)
                mem_available = mem_free + buffers + cached

            metrics.ram_used = metrics.ram_total - mem_available

            if metrics.ram_total > 0:
                metrics.ram_percent = (metrics.ram_used / metrics.ram_total) * 100
        except (KeyError, ZeroDivisionError):
            pass

    def _parse_disk(self, data: str, metrics: SystemMetrics):
        """Parse df output."""
        try:
            parts = data.strip().split()
            if len(parts) >= 4:
                metrics.disk_total = int(parts[1])
                metrics.disk_used = int(parts[2])

                if metrics.disk_total > 0:
                    metrics.disk_percent = (metrics.disk_used / metrics.disk_total) * 100
        except (ValueError, IndexError):
            pass

    def _parse_cpu(self, data: str, metrics: SystemMetrics):
        """Parse CPU usage from /proc/stat samples."""
        try:
            lines = [l for l in data.strip().split('\n') if l.startswith('cpu ')]

            if len(lines) >= 2:
                # Parse both CPU samples
                def parse_cpu_line(line):
                    parts = line.split()[1:8]  # user, nice, system, idle, iowait, irq, softirq
                    return [int(p) for p in parts]

                cpu1 = parse_cpu_line(lines[0])
                cpu2 = parse_cpu_line(lines[1])

                # Calculate deltas
                total1 = sum(cpu1)
                total2 = sum(cpu2)
                idle1 = cpu1[3] + cpu1[4]  # idle + iowait
                idle2 = cpu2[3] + cpu2[4]

                total_diff = total2 - total1
                idle_diff = idle2 - idle1

                if total_diff > 0:
                    metrics.cpu_percent = ((total_diff - idle_diff) / total_diff) * 100
                    metrics.cpu_percent = max(0, min(100, metrics.cpu_percent))
        except (ValueError, IndexError):
            pass

    @staticmethod
    def _format_uptime(seconds: int) -> str:
        """Format uptime seconds to human readable string."""
        days, remainder = divmod(seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, _ = divmod(remainder, 60)

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")

        return " ".join(parts) if parts else "< 1m"

    def get_cpu_usage(self) -> float:
        """Get only CPU usage (lighter than full collection)."""
        command = """
        head -1 /proc/stat
        sleep 0.3
        head -1 /proc/stat
        """

        result = self.connection.execute(command, timeout=5)
        if not result.success:
            return 0.0

        metrics = SystemMetrics()
        self._parse_cpu(result.stdout, metrics)
        return metrics.cpu_percent

    def get_memory_usage(self) -> float:
        """Get only RAM usage percentage."""
        result = self.connection.execute(
            "cat /proc/meminfo | grep -E '^(MemTotal|MemAvailable):'",
            timeout=5
        )

        if not result.success:
            return 0.0

        try:
            total = 0
            available = 0

            for line in result.stdout.split('\n'):
                if line.startswith('MemTotal:'):
                    match = re.search(r'(\d+)', line)
                    if match:
                        total = int(match.group(1))
                elif line.startswith('MemAvailable:'):
                    match = re.search(r'(\d+)', line)
                    if match:
                        available = int(match.group(1))

            if total > 0:
                return ((total - available) / total) * 100
        except (ValueError, ZeroDivisionError):
            pass

        return 0.0


class MetricsMonitor:
    """
    Background metrics monitor with periodic collection.

    Runs in a separate thread to avoid blocking UI.
    """

    def __init__(
            self,
            connection: SSHConnection,
            interval: float = 5.0,
            callback=None
    ):
        """
        Initialize metrics monitor.

        Args:
            connection: SSH connection to use
            interval: Collection interval in seconds
            callback: Function to call with new metrics
        """
        self.connection = connection
        self.interval = interval
        self.callback = callback

        self._collector = MetricsCollector(connection)
        self._stop_event = Event()
        self._thread: Optional[Thread] = None
        self._last_metrics: Optional[SystemMetrics] = None

    def start(self):
        """Start background monitoring."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = Thread(
            target=self._monitor_loop,
            name=f"MetricsMonitor-{self.connection.connection_id}",
            daemon=True
        )
        self._thread.start()
        logger.debug(f"Started metrics monitor for {self.connection.connection_id}")

    def stop(self):
        """Stop background monitoring."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
        logger.debug(f"Stopped metrics monitor for {self.connection.connection_id}")

    def _monitor_loop(self):
        """Background monitoring loop."""
        while not self._stop_event.is_set():
            try:
                metrics = self._collector.collect()
                self._last_metrics = metrics

                if self.callback:
                    try:
                        self.callback(metrics)
                    except Exception as e:
                        logger.error(f"Metrics callback error: {e}")

            except Exception as e:
                logger.error(f"Metrics collection error: {e}")

            self._stop_event.wait(self.interval)

    @property
    def last_metrics(self) -> Optional[SystemMetrics]:
        """Get most recently collected metrics."""
        return self._last_metrics

    @property
    def is_running(self) -> bool:
        """Check if monitor is running."""
        return self._thread is not None and self._thread.is_alive()