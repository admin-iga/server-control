"""
Custom Tkinter Widgets
======================
Modern-looking custom widgets for the ServerControl Pro UI.
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional, Callable, Dict, Any, List
from enum import Enum
import time


class Colors:
    """Color scheme constants."""
    # Background colors
    BG_PRIMARY = "#1a1a2e"
    BG_SECONDARY = "#16213e"
    BG_TERTIARY = "#0f3460"
    BG_CARD = "#1f2940"
    BG_HOVER = "#2a3a5a"

    # Accent colors
    ACCENT_PRIMARY = "#00d4ff"
    ACCENT_SECONDARY = "#7c3aed"
    ACCENT_SUCCESS = "#10b981"
    ACCENT_WARNING = "#f59e0b"
    ACCENT_DANGER = "#ef4444"

    # Text colors
    TEXT_PRIMARY = "#ffffff"
    TEXT_SECONDARY = "#a1a1aa"
    TEXT_MUTED = "#71717a"

    # Status colors
    STATUS_ONLINE = "#10b981"
    STATUS_OFFLINE = "#ef4444"
    STATUS_WARNING = "#f59e0b"
    STATUS_UNKNOWN = "#6b7280"


class Fonts:
    """Font configuration."""
    FAMILY = "Segoe UI"
    FAMILY_MONO = "Consolas"

    @classmethod
    def get(cls, size: int = 10, bold: bool = False, mono: bool = False):
        family = cls.FAMILY_MONO if mono else cls.FAMILY
        weight = "bold" if bold else "normal"
        return (family, size, weight)


class ModernButton(tk.Canvas):
    """Modern styled button with hover effects."""

    def __init__(
            self,
            parent,
            text: str,
            command: Optional[Callable] = None,
            width: int = 100,
            height: int = 32,
            bg_color: str = Colors.BG_TERTIARY,
            hover_color: str = Colors.BG_HOVER,
            text_color: str = Colors.TEXT_PRIMARY,
            accent_color: Optional[str] = None,
            **kwargs
    ):
        super().__init__(
            parent,
            width=width,
            height=height,
            bg=parent.cget('bg') if hasattr(parent, 'cget') else Colors.BG_PRIMARY,
            highlightthickness=0,
            **kwargs
        )

        self.text = text
        self.command = command
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.text_color = text_color
        self.accent_color = accent_color or bg_color
        self._enabled = True

        # Draw button
        self._draw()

        # Bind events
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        self.bind('<Button-1>', self._on_click)
        self.bind('<ButtonRelease-1>', self._on_release)

    def _draw(self, hover: bool = False):
        """Draw the button."""
        self.delete('all')

        w = self.winfo_reqwidth()
        h = self.winfo_reqheight()
        radius = 6

        # Background color
        color = self.hover_color if hover else self.bg_color
        if not self._enabled:
            color = Colors.BG_SECONDARY

        # Draw rounded rectangle
        self._create_rounded_rect(2, 2, w - 2, h - 2, radius, fill=color, outline='')

        # Draw accent line at bottom
        if self.accent_color != self.bg_color:
            self.create_line(
                radius, h - 3, w - radius, h - 3,
                fill=self.accent_color, width=2
            )

        # Draw text
        text_color = self.text_color if self._enabled else Colors.TEXT_MUTED
        self.create_text(
            w / 2, h / 2,
            text=self.text,
            fill=text_color,
            font=Fonts.get(10, bold=True)
        )

    def _create_rounded_rect(self, x1, y1, x2, y2, radius, **kwargs):
        """Create a rounded rectangle."""
        points = [
            x1 + radius, y1,
            x2 - radius, y1,
            x2, y1,
            x2, y1 + radius,
            x2, y2 - radius,
            x2, y2,
            x2 - radius, y2,
            x1 + radius, y2,
            x1, y2,
            x1, y2 - radius,
            x1, y1 + radius,
            x1, y1,
            x1 + radius, y1
        ]
        return self.create_polygon(points, smooth=True, **kwargs)

    def _on_enter(self, event):
        if self._enabled:
            self._draw(hover=True)
            self.config(cursor='hand2')

    def _on_leave(self, event):
        self._draw(hover=False)
        self.config(cursor='')

    def _on_click(self, event):
        if self._enabled:
            self._draw(hover=True)

    def _on_release(self, event):
        if self._enabled and self.command:
            self.command()
        self._draw(hover=False)

    def set_enabled(self, enabled: bool):
        """Enable or disable the button."""
        self._enabled = enabled
        self._draw()

    def set_text(self, text: str):
        """Update button text."""
        self.text = text
        self._draw()


class StatusIndicator(tk.Canvas):
    """Animated status indicator dot."""

    def __init__(
            self,
            parent,
            size: int = 12,
            **kwargs
    ):
        super().__init__(
            parent,
            width=size,
            height=size,
            bg=parent.cget('bg') if hasattr(parent, 'cget') else Colors.BG_PRIMARY,
            highlightthickness=0,
            **kwargs
        )

        self.size = size
        self._status = "offline"
        self._pulse_id = None
        self._pulse_state = 0

        self._draw()

    def _draw(self):
        """Draw the status indicator."""
        self.delete('all')

        colors = {
            'online': Colors.STATUS_ONLINE,
            'offline': Colors.STATUS_OFFLINE,
            'warning': Colors.STATUS_WARNING,
            'unknown': Colors.STATUS_UNKNOWN,
        }

        color = colors.get(self._status, Colors.STATUS_UNKNOWN)

        # Draw glow effect for online status
        if self._status == 'online':
            glow_alpha = 0.3 + (self._pulse_state * 0.2)
            # Simplified glow using larger circle
            self.create_oval(
                0, 0, self.size, self.size,
                fill=color,
                outline=''
            )
        else:
            self.create_oval(
                2, 2, self.size - 2, self.size - 2,
                fill=color,
                outline=''
            )

    def set_status(self, status: str):
        """Set the status (online, offline, warning, unknown)."""
        self._status = status
        self._draw()

        # Start or stop pulse animation
        if status == 'online':
            self._start_pulse()
        else:
            self._stop_pulse()

    def _start_pulse(self):
        """Start pulse animation."""
        if self._pulse_id:
            return

        def pulse():
            self._pulse_state = (self._pulse_state + 1) % 10
            self._draw()
            self._pulse_id = self.after(100, pulse)

        pulse()

    def _stop_pulse(self):
        """Stop pulse animation."""
        if self._pulse_id:
            self.after_cancel(self._pulse_id)
            self._pulse_id = None


class MetricBar(tk.Canvas):
    """Horizontal progress bar for metrics."""

    def __init__(
            self,
            parent,
            width: int = 200,
            height: int = 20,
            label: str = "",
            unit: str = "%",
            **kwargs
    ):
        super().__init__(
            parent,
            width=width,
            height=height,
            bg=parent.cget('bg') if hasattr(parent, 'cget') else Colors.BG_PRIMARY,
            highlightthickness=0,
            **kwargs
        )

        self.bar_width = width
        self.bar_height = height
        self.label = label
        self.unit = unit
        self._value = 0

        self._draw()

    def _draw(self):
        """Draw the metric bar."""
        self.delete('all')

        # Background bar
        self.create_rectangle(
            0, 8, self.bar_width, self.bar_height,
            fill=Colors.BG_SECONDARY,
            outline=''
        )

        # Value bar with gradient color based on value
        if self._value < 50:
            color = Colors.ACCENT_SUCCESS
        elif self._value < 80:
            color = Colors.ACCENT_WARNING
        else:
            color = Colors.ACCENT_DANGER

        bar_fill = (self._value / 100) * self.bar_width
        self.create_rectangle(
            0, 8, bar_fill, self.bar_height,
            fill=color,
            outline=''
        )

        # Label
        if self.label:
            self.create_text(
                4, 0,
                text=self.label,
                anchor='nw',
                fill=Colors.TEXT_SECONDARY,
                font=Fonts.get(8)
            )

        # Value text
        self.create_text(
            self.bar_width - 4, 0,
            text=f"{self._value:.1f}{self.unit}",
            anchor='ne',
            fill=Colors.TEXT_PRIMARY,
            font=Fonts.get(8, mono=True)
        )

    def set_value(self, value: float):
        """Set the bar value (0-100)."""
        self._value = max(0, min(100, value))
        self._draw()


class Toast(tk.Toplevel):
    """Toast notification popup."""

    def __init__(
            self,
            parent,
            message: str,
            toast_type: str = "info",
            duration: int = 3000
    ):
        super().__init__(parent)

        # Configure window
        self.overrideredirect(True)
        self.attributes('-topmost', True)
        self.configure(bg=Colors.BG_CARD)

        # Toast colors
        colors = {
            'success': Colors.ACCENT_SUCCESS,
            'error': Colors.ACCENT_DANGER,
            'warning': Colors.ACCENT_WARNING,
            'info': Colors.ACCENT_PRIMARY,
        }
        accent = colors.get(toast_type, Colors.ACCENT_PRIMARY)

        # Icons
        icons = {
            'success': '✓',
            'error': '✕',
            'warning': '⚠',
            'info': 'ℹ',
        }
        icon = icons.get(toast_type, 'ℹ')

        # Main frame
        frame = tk.Frame(self, bg=Colors.BG_CARD)
        frame.pack(fill='both', expand=True, padx=2, pady=2)

        # Accent bar
        accent_bar = tk.Frame(frame, bg=accent, width=4)
        accent_bar.pack(side='left', fill='y')

        # Content
        content = tk.Frame(frame, bg=Colors.BG_CARD)
        content.pack(side='left', fill='both', expand=True, padx=10, pady=8)

        # Icon
        icon_label = tk.Label(
            content,
            text=icon,
            font=Fonts.get(14),
            fg=accent,
            bg=Colors.BG_CARD
        )
        icon_label.pack(side='left', padx=(0, 10))

        # Message
        msg_label = tk.Label(
            content,
            text=message,
            font=Fonts.get(10),
            fg=Colors.TEXT_PRIMARY,
            bg=Colors.BG_CARD,
            wraplength=300,
            justify='left'
        )
        msg_label.pack(side='left', fill='x', expand=True)

        # Position toast
        self.update_idletasks()
        width = self.winfo_reqwidth()
        height = self.winfo_reqheight()

        screen_width = self.winfo_screenwidth()
        x = screen_width - width - 20
        y = 60

        self.geometry(f"+{x}+{y}")

        # Auto-close after duration
        self.after(duration, self.destroy)

        # Click to close
        self.bind('<Button-1>', lambda e: self.destroy())


class ToastManager:
    """Manages toast notifications."""

    def __init__(self, parent):
        self.parent = parent
        self._toasts: List[Toast] = []
        self._y_offset = 60

    def show(
            self,
            message: str,
            toast_type: str = "info",
            duration: int = 3000
    ):
        """Show a toast notification."""
        # Remove old toasts
        self._cleanup()

        toast = Toast(self.parent, message, toast_type, duration)

        # Offset for multiple toasts
        if self._toasts:
            last_toast = self._toasts[-1]
            try:
                y = last_toast.winfo_y() + last_toast.winfo_height() + 10
                x = last_toast.winfo_x()
                toast.geometry(f"+{x}+{y}")
            except tk.TclError:
                pass

        self._toasts.append(toast)

    def _cleanup(self):
        """Remove destroyed toasts."""
        self._toasts = [t for t in self._toasts if t.winfo_exists()]

    def success(self, message: str):
        self.show(message, "success")

    def error(self, message: str):
        self.show(message, "error", duration=5000)

    def warning(self, message: str):
        self.show(message, "warning")

    def info(self, message: str):
        self.show(message, "info")


class ServerCard(tk.Frame):
    """Server information card widget."""

    def __init__(
            self,
            parent,
            server_id: str,
            name: str,
            ip: str,
            server_type: str,
            group: str = "",
            on_select: Optional[Callable] = None,
            **kwargs
    ):
        super().__init__(parent, bg=Colors.BG_CARD, **kwargs)

        self.server_id = server_id
        self.name = name
        self.ip = ip
        self.server_type = server_type
        self.group = group
        self.on_select = on_select
        self._selected = False

        self._build_ui()

        # Bind click events
        self.bind('<Button-1>', self._on_click)
        for child in self.winfo_children():
            child.bind('<Button-1>', self._on_click)

    def _build_ui(self):
        """Build card UI."""
        self.configure(padx=12, pady=10)

        # Header row
        header = tk.Frame(self, bg=Colors.BG_CARD)
        header.pack(fill='x')

        # Status indicator
        self.status_indicator = StatusIndicator(header)
        self.status_indicator.pack(side='left', padx=(0, 8))

        # Server name
        self.name_label = tk.Label(
            header,
            text=self.name,
            font=Fonts.get(11, bold=True),
            fg=Colors.TEXT_PRIMARY,
            bg=Colors.BG_CARD,
            anchor='w'
        )
        self.name_label.pack(side='left', fill='x', expand=True)

        # Group tag
        if self.group:
            tag_colors = {
                'prod': Colors.ACCENT_DANGER,
                'production': Colors.ACCENT_DANGER,
                'staging': Colors.ACCENT_WARNING,
                'dev': Colors.ACCENT_SUCCESS,
                'development': Colors.ACCENT_SUCCESS,
            }
            tag_color = tag_colors.get(self.group.lower(), Colors.ACCENT_PRIMARY)

            tag_label = tk.Label(
                header,
                text=self.group.upper(),
                font=Fonts.get(8, bold=True),
                fg=tag_color,
                bg=Colors.BG_SECONDARY,
                padx=6,
                pady=2
            )
            tag_label.pack(side='right')

        # Info row
        info = tk.Frame(self, bg=Colors.BG_CARD)
        info.pack(fill='x', pady=(6, 0))

        # Type
        type_label = tk.Label(
            info,
            text=self.server_type,
            font=Fonts.get(9),
            fg=Colors.TEXT_SECONDARY,
            bg=Colors.BG_CARD
        )
        type_label.pack(side='left')

        # IP
        ip_label = tk.Label(
            info,
            text=self.ip,
            font=Fonts.get(9, mono=True),
            fg=Colors.TEXT_MUTED,
            bg=Colors.BG_CARD
        )
        ip_label.pack(side='right')

        # Metrics row
        metrics = tk.Frame(self, bg=Colors.BG_CARD)
        metrics.pack(fill='x', pady=(8, 0))

        # CPU bar
        cpu_frame = tk.Frame(metrics, bg=Colors.BG_CARD)
        cpu_frame.pack(side='left', fill='x', expand=True, padx=(0, 5))

        self.cpu_bar = MetricBar(cpu_frame, width=100, height=16, label="CPU")
        self.cpu_bar.pack(fill='x', expand=True)

        # RAM bar
        ram_frame = tk.Frame(metrics, bg=Colors.BG_CARD)
        ram_frame.pack(side='left', fill='x', expand=True, padx=(5, 0))

        self.ram_bar = MetricBar(ram_frame, width=100, height=16, label="RAM")
        self.ram_bar.pack(fill='x', expand=True)

    def _on_click(self, event):
        """Handle click event."""
        if self.on_select:
            self.on_select(self.server_id)

    def set_selected(self, selected: bool):
        """Set selection state."""
        self._selected = selected
        color = Colors.BG_TERTIARY if selected else Colors.BG_CARD
        self.configure(bg=color)
        for widget in self.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.configure(bg=color)
                for child in widget.winfo_children():
                    if hasattr(child, 'configure'):
                        try:
                            child.configure(bg=color)
                        except tk.TclError:
                            pass

    def update_status(self, status: str, cpu: float = 0, ram: float = 0):
        """Update server status and metrics."""
        self.status_indicator.set_status(status)
        self.cpu_bar.set_value(cpu)
        self.ram_bar.set_value(ram)


class ScrollableFrame(tk.Frame):
    """Scrollable frame container."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)

        # Canvas for scrolling
        self.canvas = tk.Canvas(
            self,
            bg=Colors.BG_PRIMARY,
            highlightthickness=0
        )

        # Scrollbar
        self.scrollbar = ttk.Scrollbar(
            self,
            orient='vertical',
            command=self.canvas.yview
        )

        # Inner frame
        self.inner_frame = tk.Frame(self.canvas, bg=Colors.BG_PRIMARY)

        # Configure canvas
        self.canvas_window = self.canvas.create_window(
            (0, 0),
            window=self.inner_frame,
            anchor='nw'
        )

        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Layout
        self.canvas.pack(side='left', fill='both', expand=True)
        self.scrollbar.pack(side='right', fill='y')

        # Bind events
        self.inner_frame.bind('<Configure>', self._on_frame_configure)
        self.canvas.bind('<Configure>', self._on_canvas_configure)

        # Mouse wheel scrolling
        self.canvas.bind_all('<MouseWheel>', self._on_mousewheel)
        self.canvas.bind_all('<Button-4>', self._on_mousewheel)
        self.canvas.bind_all('<Button-5>', self._on_mousewheel)

    def _on_frame_configure(self, event):
        """Update scroll region."""
        self.canvas.configure(scrollregion=self.canvas.bbox('all'))

    def _on_canvas_configure(self, event):
        """Update inner frame width."""
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling."""
        if event.num == 4 or event.delta > 0:
            self.canvas.yview_scroll(-1, 'units')
        elif event.num == 5 or event.delta < 0:
            self.canvas.yview_scroll(1, 'units')