"""
PacketSniffer by LunaEMG
Aplicación de captura de paquetes de red con interfaz gráfica PySide6.
"""

import sys
import ctypes
import os
import math
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from scapy.all import (
    sniff, wrpcap, get_if_list, conf,
    IP, IPv6, TCP, UDP, ICMP, ARP, DNS
)

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QComboBox, QFrame, QTableView,
    QHeaderView, QDialog, QMessageBox, QFileDialog, QSizePolicy,
    QAbstractItemView, QStyleFactory
)
from PySide6.QtCore import (
    Qt, QThread, Signal, QAbstractTableModel, QModelIndex, QTimer, QSize
)
from PySide6.QtGui import (
    QFont, QColor, QPainter, QPen, QBrush, QFontDatabase, QPalette, QIcon
)


# ============ COLORES Y ESTILOS ============
COLORS = {
    "bg_dark": "#0d0d1a",
    "bg_card": "#1a1a2e",
    "bg_card_alt": "#16162a",
    "bg_input": "#252540",
    "border": "#2d2d4a",
    "accent_purple": "#7c3aed",
    "accent_violet": "#8b5cf6",
    "success": "#22c55e",
    "danger": "#ef4444",
    "text_primary": "#f1f5f9",
    "text_secondary": "#d1d5db",
    "text_muted": "#6b7280",
    "tcp": "#22c55e",
    "udp": "#3b82f6",
    "icmp": "#f59e0b",
    "arp": "#a855f7",
    "dns": "#06b6d4",
    "ipv6": "#ec4899",
    "other": "#6b7280",
}

FONT_FAMILY = "Segoe UI"  # Fallback default

def load_application_font():
    """Carga Plus Jakarta Sans desde archivo local o usa fallback."""
    global FONT_FAMILY
    script_dir = os.path.dirname(os.path.abspath(__file__))
    font_path = os.path.join(script_dir, "fonts", "PlusJakartaSans-Regular.ttf")
    
    if os.path.exists(font_path):
        font_id = QFontDatabase.addApplicationFont(font_path)
        if font_id >= 0:
            families = QFontDatabase.applicationFontFamilies(font_id)
            if families:
                FONT_FAMILY = families[0]
                return True
    
    # Si no se encuentra, verificar si está instalada en el sistema
    available_fonts = QFontDatabase.families()
    if "Plus Jakarta Sans" in available_fonts:
        FONT_FAMILY = "Plus Jakarta Sans"
        return True
    
    # Fallback a Segoe UI (Windows) o fuente del sistema
    FONT_FAMILY = "Segoe UI"
    return False

# Descripciones de protocolos
PROTOCOL_DESCRIPTIONS = {
    "TCP": "Transmission Control Protocol\nProtocolo orientado a conexión.\nUso: HTTP, HTTPS, SSH, FTP",
    "UDP": "User Datagram Protocol\nProtocolo sin conexión, más rápido.\nUso: DNS, streaming, juegos online",
    "ICMP": "Internet Control Message Protocol\nMensajes de control y diagnóstico.\nUso: ping, traceroute",
    "ARP": "Address Resolution Protocol\nResolución de direcciones IP a MAC.\nUso: comunicación en red local",
    "DNS": "Domain Name System\nResolución de nombres de dominio.\nUso: convertir URLs a direcciones IP",
}


@dataclass
class PacketStats:
    """Estadísticas de paquetes capturados."""
    total: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    arp: int = 0
    dns: int = 0
    other: int = 0


def check_admin_privileges() -> bool:
    """Verifica si se ejecuta con permisos de administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def get_friendly_interface_name(iface: str) -> str:
    """Obtiene nombre amigable de la interfaz."""
    try:
        from scapy.arch.windows import get_windows_if_list
        for i in get_windows_if_list():
            if i.get('guid') == iface or i.get('name') == iface:
                return i.get('description', iface)[:50]
    except:
        pass
    return iface[:50] if len(iface) > 50 else iface


# ============ MODELO DE TABLA ============
class PacketTableModel(QAbstractTableModel):
    """Modelo de datos para la tabla de paquetes."""
    
    def __init__(self):
        super().__init__()
        self.packets: List[Tuple[int, str, str, str, str, str]] = []
        self.headers = ["#", "Tiempo", "Origen", "Destino", "Protocolo", "Info"]
        self.max_packets = 5000  # Límite de paquetes en memoria
    
    def rowCount(self, parent=QModelIndex()):
        return len(self.packets)
    
    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)
    
    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        
        row, col = index.row(), index.column()
        if row >= len(self.packets):
            return None
        
        packet = self.packets[row]
        
        if role == Qt.DisplayRole:
            return str(packet[col])
        
        elif role == Qt.ForegroundRole:
            proto = packet[4]
            if col == 4:  # Columna de protocolo
                color_map = {
                    "TCP": COLORS["tcp"],
                    "UDP": COLORS["udp"],
                    "ICMP": COLORS["icmp"],
                    "ARP": COLORS["arp"],
                    "DNS": COLORS["dns"],
                    "IPv6": COLORS["ipv6"],
                }
                return QColor(color_map.get(proto, COLORS["other"]))
            return QColor(COLORS["text_secondary"])
        
        elif role == Qt.TextAlignmentRole:
            return Qt.AlignLeft | Qt.AlignVCenter
        
        return None
    
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None
    
    def add_packet(self, num: int, ts: str, src: str, dst: str, proto: str, info: str):
        """Añade un paquete al modelo."""
        if len(self.packets) >= self.max_packets:
            # Eliminar los primeros 500 paquetes cuando llegamos al límite
            self.beginRemoveRows(QModelIndex(), 0, 499)
            self.packets = self.packets[500:]
            self.endRemoveRows()
        
        row = len(self.packets)
        self.beginInsertRows(QModelIndex(), row, row)
        self.packets.append((num, ts, src, dst, proto, info))
        self.endInsertRows()
    
    def clear(self):
        """Limpia todos los paquetes."""
        self.beginResetModel()
        self.packets.clear()
        self.endResetModel()


# ============ WORKER THREAD ============
class CaptureWorker(QThread):
    """Thread de captura de paquetes."""
    
    packet_captured = Signal(str, str, str, str, str)  # ts, src, dst, proto, info
    error_occurred = Signal(str)
    
    def __init__(self, interface: Optional[str], bpf_filter: Optional[str]):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.is_running = True
        self.captured_packets = []
    
    def run(self):
        """Ejecuta la captura de paquetes."""
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self.is_running
            )
        except PermissionError:
            self.error_occurred.emit(
                "Permiso denegado. Ejecuta como Administrador."
            )
        except OSError as e:
            if "Npcap" in str(e) or "winpcap" in str(e).lower():
                self.error_occurred.emit(
                    "Npcap no encontrado. Instálalo desde npcap.com"
                )
            else:
                self.error_occurred.emit(f"Error de red: {e}")
        except Exception as e:
            self.error_occurred.emit(str(e))
    
    def _process_packet(self, pkt):
        """Procesa un paquete capturado."""
        if not self.is_running:
            return
        
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        src, dst, proto, extra_info = "N/A", "N/A", "OTHER", ""
        
        # Determinar protocolo y extraer info
        if pkt.haslayer(DNS):
            proto = "DNS"
            if pkt.haslayer(IP):
                src, dst = pkt[IP].src, pkt[IP].dst
            qname = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else "N/A"
            extra_info = f"Query: {qname}"
        elif pkt.haslayer(TCP):
            proto = "TCP"
            if pkt.haslayer(IP):
                src, dst = pkt[IP].src, pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            extra_info = f":{pkt[TCP].sport} → :{pkt[TCP].dport}"
        elif pkt.haslayer(UDP):
            proto = "UDP"
            if pkt.haslayer(IP):
                src, dst = pkt[IP].src, pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            extra_info = f":{pkt[UDP].sport} → :{pkt[UDP].dport}"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            if pkt.haslayer(IP):
                src, dst = pkt[IP].src, pkt[IP].dst
            icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
            extra_info = icmp_types.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")
        elif pkt.haslayer(ARP):
            proto = "ARP"
            op = "Request" if pkt[ARP].op == 1 else "Reply"
            src, dst = pkt[ARP].psrc, pkt[ARP].pdst
            extra_info = op
        elif pkt.haslayer(IPv6):
            proto = "IPv6"
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        elif pkt.haslayer(IP):
            proto = "IP"
            src, dst = pkt[IP].src, pkt[IP].dst
        
        self.captured_packets.append(pkt)
        self.packet_captured.emit(ts, src, dst, proto, extra_info)
    
    def stop(self):
        """Detiene la captura."""
        self.is_running = False


# ============ DIÁLOGO DE RESULTADOS ============
class ResultsDialog(QDialog):
    """Diálogo con resultados del análisis."""
    
    def __init__(self, parent, stats: PacketStats):
        super().__init__(parent)
        self.stats = stats
        self.setWindowTitle("Resultados del Análisis")
        self.setFixedSize(560, 760)
        self.setStyleSheet(f"background-color: {COLORS['bg_dark']};")
        
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Título
        title = QLabel("Resultados del Análisis")
        title.setFont(QFont(FONT_FAMILY, 22, QFont.Bold))
        title.setStyleSheet(f"color: {COLORS['text_primary']};")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Subtítulo
        subtitle = QLabel(f"Total de paquetes capturados: {self.stats.total}")
        subtitle.setFont(QFont(FONT_FAMILY, 13))
        subtitle.setStyleSheet(f"color: {COLORS['text_secondary']};")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)
        
        layout.addSpacing(5)
        
        # Widget para la gráfica
        self.chart_widget = PieChartWidget(self.stats)
        self.chart_widget.setFixedSize(320, 320)
        
        chart_container = QWidget()
        chart_layout = QHBoxLayout(chart_container)
        chart_layout.setContentsMargins(10, 10, 10, 10)
        chart_layout.addStretch()
        chart_layout.addWidget(self.chart_widget)
        chart_layout.addStretch()
        layout.addWidget(chart_container)
        
        layout.addSpacing(10)
        
        # Leyenda
        legend_frame = QFrame()
        legend_frame.setStyleSheet(f"""
            background-color: {COLORS['bg_card']};
            border-radius: 12px;
        """)
        legend_layout = QVBoxLayout(legend_frame)
        legend_layout.setContentsMargins(20, 15, 20, 15)
        legend_layout.setSpacing(10)
        
        protocol_data = [
            ("TCP", self.stats.tcp, COLORS["tcp"]),
            ("UDP", self.stats.udp, COLORS["udp"]),
            ("ICMP", self.stats.icmp, COLORS["icmp"]),
            ("ARP", self.stats.arp, COLORS["arp"]),
            ("DNS", self.stats.dns, COLORS["dns"]),
        ]
        
        total = sum(p[1] for p in protocol_data)
        
        for name, count, color in protocol_data:
            row = QHBoxLayout()
            
            # Indicador de color
            dot = QFrame()
            dot.setFixedSize(14, 14)
            dot.setStyleSheet(f"background-color: {color}; border-radius: 7px;")
            row.addWidget(dot)
            
            row.addSpacing(12)
            
            # Nombre
            name_label = QLabel(name)
            name_label.setFont(QFont(FONT_FAMILY, 13, QFont.Bold))
            name_label.setStyleSheet(f"color: {COLORS['text_primary']};")
            name_label.setFixedWidth(60)
            row.addWidget(name_label)
            
            # Cantidad
            count_label = QLabel(str(count))
            count_label.setFont(QFont(FONT_FAMILY, 13, QFont.Bold))
            count_label.setStyleSheet(f"color: {color};")
            count_label.setFixedWidth(70)
            row.addWidget(count_label)
            
            row.addStretch()
            
            # Porcentaje
            pct = (count / total * 100) if total > 0 else 0
            pct_label = QLabel(f"{pct:.1f}%")
            pct_label.setFont(QFont(FONT_FAMILY, 13))
            pct_label.setStyleSheet(f"color: {COLORS['text_muted']};")
            row.addWidget(pct_label)
            
            legend_layout.addLayout(row)
        
        layout.addWidget(legend_frame)
        
        layout.addStretch()
        
        # Botón cerrar
        close_btn = QPushButton("Cerrar")
        close_btn.setFont(QFont(FONT_FAMILY, 14, QFont.Bold))
        close_btn.setFixedSize(140, 45)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent_purple']};
                color: white;
                border: none;
                border-radius: 22px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_violet']};
            }}
        """)
        close_btn.clicked.connect(self.accept)
        
        btn_container = QWidget()
        btn_layout = QHBoxLayout(btn_container)
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        btn_layout.addStretch()
        layout.addWidget(btn_container)


class PieChartWidget(QWidget):
    """Widget para dibujar la gráfica de pastel con alta calidad (supersampling)."""
    
    def __init__(self, stats: PacketStats):
        super().__init__()
        self.stats = stats
        self.cached_pixmap = None
    
    def paintEvent(self, event):
        painter = QPainter(self)
        
        # Crear imagen en alta resolución (4x) para supersampling
        if self.cached_pixmap is None:
            self._render_chart()
        
        if self.cached_pixmap:
            # Dibujar la imagen escalada
            x = (self.width() - self.cached_pixmap.width()) // 2
            y = (self.height() - self.cached_pixmap.height()) // 2
            painter.drawPixmap(x, y, self.cached_pixmap)
    
    def _render_chart(self):
        """Renderiza la gráfica en alta resolución y escala hacia abajo."""
        from PySide6.QtGui import QImage, QPixmap
        
        # Supersampling: renderizar a 4x el tamaño
        scale = 4
        size = min(self.width(), self.height())
        hq_size = size * scale
        
        if hq_size <= 0:
            return
        
        # Crear imagen de alta resolución
        image = QImage(hq_size, hq_size, QImage.Format_ARGB32)
        image.fill(Qt.transparent)
        
        painter = QPainter(image)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
        
        cx, cy = hq_size // 2, hq_size // 2
        r = int(hq_size * 0.42)
        inner_r = int(r * 0.55)
        
        # Datos
        data = [
            (self.stats.tcp, QColor(COLORS["tcp"])),
            (self.stats.udp, QColor(COLORS["udp"])),
            (self.stats.icmp, QColor(COLORS["icmp"])),
            (self.stats.arp, QColor(COLORS["arp"])),
            (self.stats.dns, QColor(COLORS["dns"])),
        ]
        
        total = sum(d[0] for d in data)
        
        bg_color = QColor(COLORS["bg_card"])
        
        if total == 0:
            # Círculo vacío
            painter.setPen(QPen(QColor(COLORS["border"]), 3 * scale))
            painter.setBrush(QColor(COLORS["bg_card_alt"]))
            painter.drawEllipse(cx - r, cy - r, r * 2, r * 2)
        else:
            # Dibujar segmentos
            start_angle = 90 * 16
            rect_tuple = (cx - r, cy - r, r * 2, r * 2)
            
            for value, color in data:
                if value > 0:
                    extent = int((value / total) * 360 * 16)
                    painter.setPen(QPen(bg_color, 2 * scale))
                    painter.setBrush(color)
                    painter.drawPie(*rect_tuple, start_angle, -extent)
                    start_angle -= extent
            
            # Círculo interior (efecto donut)
            painter.setPen(Qt.NoPen)
            painter.setBrush(bg_color)
            painter.drawEllipse(cx - inner_r, cy - inner_r, inner_r * 2, inner_r * 2)
        
        # Texto central
        painter.setPen(QColor(COLORS["text_primary"]))
        font_large = QFont(FONT_FAMILY, 26 * scale, QFont.Bold)
        painter.setFont(font_large)
        
        from PySide6.QtCore import QRect
        text_rect = QRect(0, 0, hq_size, hq_size)
        text_rect.setTop(text_rect.top() - 15 * scale)
        painter.drawText(text_rect, Qt.AlignCenter, str(total))
        
        painter.setPen(QColor(COLORS["text_muted"]))
        font_small = QFont(FONT_FAMILY, 11 * scale)
        painter.setFont(font_small)
        text_rect2 = QRect(0, 0, hq_size, hq_size)
        text_rect2.setTop(text_rect2.top() + 35 * scale)
        painter.drawText(text_rect2, Qt.AlignCenter, "paquetes")
        
        painter.end()
        
        # Escalar hacia abajo con alta calidad
        scaled_image = image.scaled(
            size, size,
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation
        )
        self.cached_pixmap = QPixmap.fromImage(scaled_image)


# ============ VENTANA PRINCIPAL ============
class MainWindow(QMainWindow):
    """Ventana principal de PacketSniffer."""
    
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("PacketSniffer - Sniffer de Red")
        self.setMinimumSize(1100, 750)
        self.resize(1150, 800)
        
        # Estado
        self.capture_worker: Optional[CaptureWorker] = None
        self.stats = PacketStats()
        self.is_capturing = False
        self.packet_count = 0
        
        # Mapeo de interfaces
        self.interface_map = {}
        
        self._setup_ui()
        self._apply_styles()
        self._start_pulse_animation()
        
        # Verificar admin
        if not check_admin_privileges():
            QTimer.singleShot(500, self._show_admin_warning)
    
    def _setup_ui(self):
        """Configura la interfaz de usuario."""
        central = QWidget()
        self.setCentralWidget(central)
        
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(18)
        main_layout.setContentsMargins(28, 28, 28, 28)
        
        # ============ BARRA SUPERIOR ============
        top_bar = QFrame()
        top_bar.setObjectName("topBar")
        top_bar_layout = QHBoxLayout(top_bar)
        top_bar_layout.setContentsMargins(0, 0, 0, 0)
        
        # Logo y título
        title_frame = QWidget()
        title_layout = QHBoxLayout(title_frame)
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(8)
        
        title_label = QLabel("PacketSniffer")
        title_label.setFont(QFont(FONT_FAMILY, 22, QFont.Bold))
        title_label.setStyleSheet(f"color: {COLORS['accent_purple']};")
        title_layout.addWidget(title_label)
        
        subtitle_label = QLabel("by LunaEMG")
        subtitle_label.setFont(QFont(FONT_FAMILY, 12))
        subtitle_label.setStyleSheet(f"color: {COLORS['text_muted']};")
        title_layout.addWidget(subtitle_label)
        
        top_bar_layout.addWidget(title_frame)
        top_bar_layout.addStretch()
        
        # Botón ayuda
        help_btn = QPushButton("?")
        help_btn.setFixedSize(40, 40)
        help_btn.setCursor(Qt.PointingHandCursor)
        help_btn.setFont(QFont(FONT_FAMILY, 16, QFont.Bold))
        help_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_input']};
                color: {COLORS['text_secondary']};
                border: none;
                border-radius: 20px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['border']};
            }}
        """)
        help_btn.clicked.connect(self._show_help)
        top_bar_layout.addWidget(help_btn)
        
        top_bar_layout.addSpacing(15)
        
        # Indicador de estado
        self.status_dot = QLabel("●")
        self.status_dot.setFont(QFont(FONT_FAMILY, 12))
        self.status_dot.setStyleSheet(f"color: {COLORS['text_muted']};")
        top_bar_layout.addWidget(self.status_dot)
        
        self.status_label = QLabel("Detenido")
        self.status_label.setFont(QFont(FONT_FAMILY, 13))
        self.status_label.setStyleSheet(f"color: {COLORS['text_muted']};")
        top_bar_layout.addWidget(self.status_label)
        
        main_layout.addWidget(top_bar)
        
        # ============ CONTROLES ============
        controls_card = QFrame()
        controls_card.setObjectName("controlsCard")
        controls_layout = QHBoxLayout(controls_card)
        controls_layout.setContentsMargins(20, 15, 20, 15)
        controls_layout.setSpacing(15)
        
        # Interfaz de red
        iface_frame = QWidget()
        iface_layout = QVBoxLayout(iface_frame)
        iface_layout.setContentsMargins(0, 0, 0, 0)
        iface_layout.setSpacing(5)
        
        iface_label = QLabel("Interfaz de Red")
        iface_label.setFont(QFont(FONT_FAMILY, 11))
        iface_label.setStyleSheet(f"color: {COLORS['text_muted']};")
        iface_layout.addWidget(iface_label)
        
        iface_row = QHBoxLayout()
        
        self.interface_combo = QComboBox()
        self.interface_combo.setFixedSize(200, 38)
        self._populate_interfaces()
        iface_row.addWidget(self.interface_combo)
        
        refresh_btn = QPushButton("↻")
        refresh_btn.setFixedSize(38, 38)
        refresh_btn.setCursor(Qt.PointingHandCursor)
        refresh_btn.setFont(QFont(FONT_FAMILY, 16))
        refresh_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent_purple']};
                color: white;
                border: none;
                border-radius: 8px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_violet']};
            }}
        """)
        refresh_btn.clicked.connect(self._populate_interfaces)
        iface_row.addWidget(refresh_btn)
        
        iface_layout.addLayout(iface_row)
        controls_layout.addWidget(iface_frame)
        
        controls_layout.addSpacing(20)
        
        # Filtro BPF
        filter_frame = QWidget()
        filter_layout = QVBoxLayout(filter_frame)
        filter_layout.setContentsMargins(0, 0, 0, 0)
        filter_layout.setSpacing(5)
        
        filter_label = QLabel("Filtro BPF")
        filter_label.setFont(QFont(FONT_FAMILY, 11))
        filter_label.setStyleSheet(f"color: {COLORS['text_muted']};")
        filter_layout.addWidget(filter_label)
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("ej: tcp port 80")
        self.filter_input.setFixedSize(200, 38)
        filter_layout.addWidget(self.filter_input)
        
        controls_layout.addWidget(filter_frame)
        
        controls_layout.addStretch()
        
        # Botones de acción
        self.start_btn = self._create_action_button("Iniciar", COLORS["success"], "#16a34a")
        self.start_btn.clicked.connect(self.start_capture)
        controls_layout.addWidget(self.start_btn)
        
        self.stop_btn = self._create_action_button("Detener", COLORS["danger"], "#dc2626")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_capture)
        controls_layout.addWidget(self.stop_btn)
        
        self.export_btn = self._create_action_button("Exportar", COLORS["accent_purple"], COLORS["accent_violet"])
        self.export_btn.clicked.connect(self.export_pcap)
        controls_layout.addWidget(self.export_btn)
        
        self.clear_btn = self._create_action_button("Limpiar", COLORS["bg_input"], COLORS["border"])
        self.clear_btn.clicked.connect(self.clear_packets)
        controls_layout.addWidget(self.clear_btn)
        
        main_layout.addWidget(controls_card)
        
        # ============ TABLA DE PAQUETES ============
        table_card = QFrame()
        table_card.setObjectName("tableCard")
        table_layout = QVBoxLayout(table_card)
        table_layout.setContentsMargins(0, 0, 0, 0)
        
        self.packet_model = PacketTableModel()
        self.packet_table = QTableView()
        self.packet_table.setModel(self.packet_model)
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packet_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.setShowGrid(False)
        
        # Configurar columnas
        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        
        self.packet_table.setColumnWidth(0, 70)
        self.packet_table.setColumnWidth(1, 100)
        self.packet_table.setColumnWidth(4, 80)
        
        table_layout.addWidget(self.packet_table)
        main_layout.addWidget(table_card, stretch=1)
        
        # ============ BARRA DE ESTADÍSTICAS ============
        stats_card = QFrame()
        stats_card.setObjectName("statsCard")
        stats_card.setFixedHeight(90)
        stats_layout = QHBoxLayout(stats_card)
        stats_layout.setContentsMargins(25, 15, 25, 15)
        
        self.stat_labels = {}
        
        # Estadísticas por protocolo
        protocol_stats = [
            ("TCP", "tcp", COLORS["tcp"]),
            ("UDP", "udp", COLORS["udp"]),
            ("ICMP", "icmp", COLORS["icmp"]),
            ("ARP", "arp", COLORS["arp"]),
            ("DNS", "dns", COLORS["dns"]),
        ]
        
        for name, key, color in protocol_stats:
            proto_widget = self._create_stat_widget(name, key, color)
            stats_layout.addWidget(proto_widget, stretch=1)
        
        stats_layout.addSpacing(30)
        
        # Total
        total_frame = QFrame()
        total_frame.setFixedWidth(130)
        total_frame.setStyleSheet(f"""
            background-color: {COLORS['bg_input']};
            border-radius: 12px;
        """)
        total_layout = QVBoxLayout(total_frame)
        total_layout.setAlignment(Qt.AlignCenter)
        
        total_label = QLabel("TOTAL")
        total_label.setFont(QFont(FONT_FAMILY, 10, QFont.Bold))
        total_label.setStyleSheet(f"color: {COLORS['text_muted']};")
        total_label.setAlignment(Qt.AlignCenter)
        total_layout.addWidget(total_label)
        
        self.stat_labels["total"] = QLabel("0")
        self.stat_labels["total"].setFont(QFont(FONT_FAMILY, 16, QFont.Bold))
        self.stat_labels["total"].setStyleSheet(f"color: {COLORS['text_primary']};")
        self.stat_labels["total"].setAlignment(Qt.AlignCenter)
        total_layout.addWidget(self.stat_labels["total"])
        
        stats_layout.addWidget(total_frame)
        
        main_layout.addWidget(stats_card)
    
    def _create_action_button(self, text: str, bg: str, hover: str) -> QPushButton:
        """Crea un botón de acción estilizado."""
        btn = QPushButton(text)
        btn.setFixedSize(110, 44)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setFont(QFont(FONT_FAMILY, 13, QFont.Bold))
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg};
                color: white;
                border: none;
                border-radius: 22px;
            }}
            QPushButton:hover {{
                background-color: {hover};
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_input']};
                color: {COLORS['text_muted']};
            }}
        """)
        return btn
    
    def _create_stat_widget(self, name: str, key: str, color: str) -> QWidget:
        """Crea un widget de estadística de protocolo."""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setAlignment(Qt.AlignCenter)
        
        # Indicador de color
        dot = QFrame()
        dot.setFixedSize(10, 10)
        dot.setStyleSheet(f"background-color: {color}; border-radius: 5px;")
        layout.addWidget(dot)
        
        layout.addSpacing(8)
        
        # Textos
        text_widget = QWidget()
        text_layout = QVBoxLayout(text_widget)
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(0)
        
        name_label = QLabel(name)
        name_label.setFont(QFont(FONT_FAMILY, 10, QFont.Bold))
        name_label.setStyleSheet(f"color: {COLORS['text_muted']};")
        name_label.setToolTip(PROTOCOL_DESCRIPTIONS.get(name, ""))
        text_layout.addWidget(name_label)
        
        self.stat_labels[key] = QLabel("0")
        self.stat_labels[key].setFont(QFont(FONT_FAMILY, 18, QFont.Bold))
        self.stat_labels[key].setStyleSheet(f"color: {color};")
        text_layout.addWidget(self.stat_labels[key])
        
        layout.addWidget(text_widget)
        
        return widget
    
    def _apply_styles(self):
        """Aplica estilos globales."""
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {COLORS['bg_dark']};
            }}
            
            QFrame#controlsCard, QFrame#tableCard, QFrame#statsCard {{
                background-color: {COLORS['bg_card']};
                border-radius: 16px;
            }}
            
            QComboBox {{
                background-color: {COLORS['bg_input']};
                color: {COLORS['text_secondary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 5px 10px;
                font-family: "{FONT_FAMILY}";
                font-size: 12px;
            }}
            QComboBox::drop-down {{
                border: none;
                width: 30px;
            }}
            QComboBox::down-arrow {{
                image: none;
            }}
            QComboBox QAbstractItemView {{
                background-color: {COLORS['bg_input']};
                color: {COLORS['text_secondary']};
                selection-background-color: {COLORS['accent_purple']};
                border: 1px solid {COLORS['border']};
            }}
            
            QLineEdit {{
                background-color: {COLORS['bg_input']};
                color: {COLORS['text_secondary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 5px 10px;
                font-family: "{FONT_FAMILY}";
                font-size: 12px;
            }}
            QLineEdit:focus {{
                border-color: {COLORS['accent_purple']};
            }}
            
            QTableView {{
                background-color: {COLORS['bg_dark']};
                alternate-background-color: {COLORS['bg_card_alt']};
                color: {COLORS['text_secondary']};
                border: none;
                font-family: "{FONT_FAMILY}";
                font-size: 12px;
                gridline-color: transparent;
            }}
            QTableView::item {{
                padding: 8px 10px;
                border: none;
            }}
            QTableView::item:selected {{
                background-color: {COLORS['accent_purple']};
                color: white;
            }}
            QHeaderView::section {{
                background-color: {COLORS['bg_card_alt']};
                color: {COLORS['text_muted']};
                font-family: "{FONT_FAMILY}";
                font-size: 12px;
                font-weight: bold;
                padding: 10px 10px;
                border: none;
            }}
            
            QScrollBar:vertical {{
                background-color: {COLORS['bg_dark']};
                width: 10px;
                margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background-color: {COLORS['accent_purple']};
                min-height: 30px;
                border-radius: 5px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
        """)
    
    def _populate_interfaces(self):
        """Llena el combo de interfaces."""
        self.interface_combo.clear()
        self.interface_map.clear()
        
        self.interface_combo.addItem("Todas las interfaces")
        self.interface_map["Todas las interfaces"] = None
        
        interfaces = get_if_list()
        for iface in interfaces:
            friendly = get_friendly_interface_name(iface)
            self.interface_combo.addItem(friendly)
            self.interface_map[friendly] = iface
    
    def _start_pulse_animation(self):
        """Inicia la animación de pulso del indicador."""
        self.pulse_timer = QTimer(self)
        self.pulse_timer.timeout.connect(self._pulse_status)
        self.pulse_timer.start(800)
    
    def _pulse_status(self):
        """Alterna el color del indicador durante captura."""
        if self.is_capturing:
            current = self.status_dot.styleSheet()
            if COLORS["success"] in current:
                self.status_dot.setStyleSheet(f"color: #16a34a;")
            else:
                self.status_dot.setStyleSheet(f"color: {COLORS['success']};")
    
    def _show_admin_warning(self):
        """Muestra advertencia de privilegios."""
        QMessageBox.warning(
            self,
            "Se Requiere Administrador",
            "Esta aplicación necesita privilegios de administrador para capturar paquetes.\n\n"
            "Por favor, reinicia como Administrador:\n"
            "Click derecho → Ejecutar como administrador"
        )
    
    def _show_help(self):
        """Muestra diálogo de ayuda."""
        QMessageBox.information(
            self,
            "Ayuda - PacketSniffer",
            "PacketSniffer by LunaEMG\n\n"
            "¿Qué es un Packet Sniffer?\n"
            "Es una herramienta que captura el tráfico de red en tiempo real.\n\n"
            "Filtros BPF:\n"
            "• tcp port 80 - Solo tráfico HTTP\n"
            "• udp - Solo paquetes UDP\n"
            "• host 192.168.1.1 - Tráfico de una IP específica\n\n"
            "Protocolos:\n"
            "• TCP - Conexiones web, SSH, etc.\n"
            "• UDP - DNS, streaming, juegos\n"
            "• ICMP - Ping, diagnósticos\n"
            "• ARP - Resolución de direcciones\n"
            "• DNS - Resolución de nombres"
        )
    
    def start_capture(self):
        """Inicia la captura de paquetes."""
        if self.is_capturing:
            return
        
        # Obtener interfaz seleccionada
        friendly_name = self.interface_combo.currentText()
        real_iface = self.interface_map.get(friendly_name)
        
        # Obtener filtro
        bpf_filter = self.filter_input.text().strip() or None
        
        self.is_capturing = True
        self.packet_count = 0
        
        # Actualizar UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.interface_combo.setEnabled(False)
        self.filter_input.setEnabled(False)
        
        self.status_dot.setStyleSheet(f"color: {COLORS['success']};")
        self.status_label.setText("Capturando...")
        self.status_label.setStyleSheet(f"color: {COLORS['success']};")
        
        # Iniciar worker
        self.capture_worker = CaptureWorker(real_iface, bpf_filter)
        self.capture_worker.packet_captured.connect(self._on_packet_captured)
        self.capture_worker.error_occurred.connect(self._on_capture_error)
        self.capture_worker.start()
    
    def stop_capture(self):
        """Detiene la captura de paquetes."""
        if not self.is_capturing:
            return
        
        self.is_capturing = False
        
        if self.capture_worker:
            self.capture_worker.stop()
            self.capture_worker.wait(2000)
        
        # Actualizar UI
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.interface_combo.setEnabled(True)
        self.filter_input.setEnabled(True)
        
        self.status_dot.setStyleSheet(f"color: {COLORS['text_muted']};")
        self.status_label.setText("Detenido")
        self.status_label.setStyleSheet(f"color: {COLORS['text_muted']};")
        
        # Mostrar resultados si hay paquetes
        if self.stats.total > 0:
            dialog = ResultsDialog(self, self.stats)
            dialog.exec()
    
    def _on_packet_captured(self, ts: str, src: str, dst: str, proto: str, info: str):
        """Maneja un paquete capturado."""
        self.packet_count += 1
        self.stats.total += 1
        
        # Actualizar estadísticas
        proto_lower = proto.lower()
        if hasattr(self.stats, proto_lower):
            setattr(self.stats, proto_lower, getattr(self.stats, proto_lower) + 1)
        else:
            self.stats.other += 1
        
        # Añadir a la tabla
        self.packet_model.add_packet(self.packet_count, ts, src, dst, proto, info)
        
        # Auto-scroll
        self.packet_table.scrollToBottom()
        
        # Actualizar stats display
        self._update_stats_display()
    
    def _on_capture_error(self, error: str):
        """Maneja errores de captura."""
        self.stop_capture()
        QMessageBox.critical(self, "Error de Captura", error)
    
    def _update_stats_display(self):
        """Actualiza los labels de estadísticas."""
        self.stat_labels["total"].setText(str(self.stats.total))
        self.stat_labels["tcp"].setText(str(self.stats.tcp))
        self.stat_labels["udp"].setText(str(self.stats.udp))
        self.stat_labels["icmp"].setText(str(self.stats.icmp))
        self.stat_labels["arp"].setText(str(self.stats.arp))
        self.stat_labels["dns"].setText(str(self.stats.dns))
    
    def clear_packets(self):
        """Limpia la tabla de paquetes."""
        self.packet_model.clear()
        self.stats = PacketStats()
        self.packet_count = 0
        self._update_stats_display()
        
        if self.capture_worker:
            self.capture_worker.captured_packets.clear()
    
    def export_pcap(self):
        """Exporta los paquetes capturados a PCAP."""
        if not self.capture_worker or not self.capture_worker.captured_packets:
            QMessageBox.information(self, "Sin Datos", "No hay paquetes capturados para exportar.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Guardar archivo PCAP",
            f"captura_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap",
            "Archivos PCAP (*.pcap)"
        )
        
        if filename:
            try:
                wrpcap(filename, self.capture_worker.captured_packets)
                QMessageBox.information(
                    self,
                    "Exportación Exitosa",
                    f"Se exportaron {len(self.capture_worker.captured_packets)} paquetes a:\n{filename}"
                )
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error al exportar: {e}")
    
    def closeEvent(self, event):
        """Maneja el cierre de la ventana."""
        if self.is_capturing:
            self.stop_capture()
        event.accept()


def main():
    """Punto de entrada principal."""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Cargar fuente personalizada
    load_application_font()
    
    # Aplicar fuente por defecto a la aplicación
    default_font = QFont(FONT_FAMILY, 10)
    app.setFont(default_font)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
