
#!/usr/bin/env python3
"""
LUNA___EMG - Advanced Network Packet Sniffer

Herramienta de diagnóstico de red robusta con:
- Validación de privilegios de administrador
- Soporte para IPv4, IPv6, TCP, UDP, ICMP, ARP y DNS
- Salida colorizada por protocolo
- Guardado opcional en pcap con límite de tamaño
- Estadísticas detalladas al finalizar
"""

import argparse
import ctypes
import logging
import os
import platform
import signal
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    ICMP,
    IP,
    TCP,
    UDP,
    IPv6,
    Packet,
    PcapWriter,
    conf,
    get_if_list,
    sniff,
)

LOG = logging.getLogger("sniffer")
console = Console()


@dataclass
class PacketStats:
    """Estadísticas de paquetes capturados por protocolo."""
    
    total: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    arp: int = 0
    dns: int = 0
    ipv6: int = 0
    other: int = 0
    bytes_written: int = 0


# Instancia global de estadísticas
stats = PacketStats()


def check_admin_privileges() -> bool:
    """
    Verifica si el script se ejecuta con privilegios de administrador.
    
    Returns:
        True si tiene privilegios de admin/root, False en caso contrario.
    """
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except AttributeError:
        # Fallback para sistemas no soportados
        return False


def list_interfaces() -> None:
    """
    Lista todas las interfaces de red disponibles y termina el programa.
    """
    interfaces = get_if_list()
    
    table = Table(title="Interfaces de Red Disponibles")
    table.add_column("Interfaz", style="cyan", no_wrap=True)
    table.add_column("Estado", style="green")
    
    for iface in interfaces:
        table.add_row(iface, "Disponible")
    
    console.print(table)
    console.print(f"\n[dim]Total: {len(interfaces)} interfaces encontradas[/dim]")


def get_protocol_style(proto: str) -> str:
    """
    Retorna el estilo de color para cada protocolo.
    
    Args:
        proto: Nombre del protocolo.
        
    Returns:
        String con el estilo de rich para el protocolo.
    """
    styles = {
        "TCP": "bold green",
        "UDP": "bold blue",
        "ICMP": "bold red",
        "ARP": "bold yellow",
        "DNS": "bold magenta",
        "IPv6": "bold cyan",
    }
    return styles.get(proto, "white")


def format_packet_info(pkt: Packet) -> tuple[str, str, str, str, str, str]:
    """
    Extrae información formateada del paquete.
    
    Args:
        pkt: Paquete Scapy a analizar.
        
    Returns:
        Tupla con (protocolo, src, dst, sport, dport, info_extra).
    """
    global stats
    
    src = dst = "-"
    sport = dport = "-"
    proto = "OTHER"
    extra_info = ""
    
    # IPv6
    if IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
        proto = "IPv6"
        stats.ipv6 += 1
    # IPv4
    elif IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
    
    # DNS (antes de TCP/UDP para identificarlo correctamente)
    if DNS in pkt:
        proto = "DNS"
        stats.dns += 1
        if DNSQR in pkt and pkt[DNSQR].qname:
            qname = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else pkt[DNSQR].qname
            qtype = pkt[DNSQR].qtype
            extra_info = f"Query: {qname} (Type: {qtype})"
    # TCP
    elif TCP in pkt:
        proto = "TCP"
        sport = str(pkt[TCP].sport)
        dport = str(pkt[TCP].dport)
        flags = pkt[TCP].flags
        extra_info = f"Flags: {flags}"
        stats.tcp += 1
    # UDP
    elif UDP in pkt:
        proto = "UDP"
        sport = str(pkt[UDP].sport)
        dport = str(pkt[UDP].dport)
        stats.udp += 1
    # ICMP
    elif ICMP in pkt:
        proto = "ICMP"
        icmp_type = pkt[ICMP].type
        icmp_code = pkt[ICMP].code
        extra_info = f"Type: {icmp_type}, Code: {icmp_code}"
        stats.icmp += 1
    # ARP
    elif ARP in pkt:
        proto = "ARP"
        op = "who-has" if pkt[ARP].op == 1 else "is-at"
        src = pkt[ARP].psrc
        dst = pkt[ARP].pdst
        hwsrc = pkt[ARP].hwsrc
        hwdst = pkt[ARP].hwdst
        extra_info = f"{op} | {hwsrc} -> {hwdst}"
        stats.arp += 1
    else:
        stats.other += 1
    
    stats.total += 1
    
    return proto, src, dst, sport, dport, extra_info


def procesar_paquete(
    pkt: Packet,
    pcap_writer: Optional[PcapWriter],
    max_size_bytes: int
) -> None:
    """
    Procesa y muestra información de cada paquete capturado.
    
    Args:
        pkt: Paquete Scapy capturado.
        pcap_writer: Writer para guardar en pcap (o None).
        max_size_bytes: Límite máximo de bytes para el archivo pcap (0 = ilimitado).
    """
    global stats
    
    try:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        proto, src, dst, sport, dport, extra_info = format_packet_info(pkt)
        
        style = get_protocol_style(proto)
        
        # Construir línea de salida
        port_info = f":{sport} -> :{dport}" if sport != "-" else ""
        line = f"[dim]{ts}[/dim] [{style}]{proto:5}[/{style}] {src} -> {dst} {port_info}"
        
        if extra_info:
            line += f" [dim]| {extra_info}[/dim]"
        
        console.print(line)
        
        # Guardar en pcap si aplica
        if pcap_writer:
            pkt_len = len(bytes(pkt))
            
            # Verificar límite de tamaño
            if max_size_bytes > 0 and (stats.bytes_written + pkt_len) > max_size_bytes:
                console.print("[yellow] Límite de tamaño de pcap alcanzado. Deteniendo guardado.[/yellow]")
                return
            
            try:
                pcap_writer.write(pkt)
                stats.bytes_written += pkt_len
            except PermissionError:
                console.print("[red]✗ Error: Sin permisos de escritura en disco[/red]")
            except OSError as e:
                console.print(f"[red]✗ Error de disco: {e}[/red]")
    
    except Exception as e:
        LOG.exception("Error procesando paquete: %s", e)


def show_statistics() -> None:
    """
    Muestra un resumen estadístico de la captura.
    """
    global stats
    
    if stats.total == 0:
        console.print("\n[yellow]No se capturaron paquetes.[/yellow]")
        return
    
    def pct(count: int) -> str:
        return f"{(count / stats.total * 100):.1f}%"
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Protocol", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Percentage", justify="right")
    
    table.add_row("[green]TCP[/green]", str(stats.tcp), pct(stats.tcp))
    table.add_row("[blue]UDP[/blue]", str(stats.udp), pct(stats.udp))
    table.add_row("[red]ICMP[/red]", str(stats.icmp), pct(stats.icmp))
    table.add_row("[yellow]ARP[/yellow]", str(stats.arp), pct(stats.arp))
    table.add_row("[magenta]DNS[/magenta]", str(stats.dns), pct(stats.dns))
    table.add_row("[cyan]IPv6[/cyan]", str(stats.ipv6), pct(stats.ipv6))
    table.add_row("[white]Otros[/white]", str(stats.other), pct(stats.other))
    
    panel = Panel(
        table,
        title=f"📊 Resumen de Captura | Total: {stats.total:,} paquetes",
        border_style="blue"
    )
    
    console.print("\n")
    console.print(panel)
    
    if stats.bytes_written > 0:
        size_mb = stats.bytes_written / (1024 * 1024)
        console.print(f"[dim]Archivo pcap: {size_mb:.2f} MB escritos[/dim]")


def signal_handler(sig: int, frame) -> None:
    """
    Manejador de señales para Ctrl+C.
    """
    console.print("\n[yellow]⚠ Captura interrumpida por el usuario[/yellow]")
    show_statistics()
    sys.exit(0)


def main() -> None:
    """
    Función principal del sniffer.
    """
    parser = argparse.ArgumentParser(
        description="🔍 Sniffer de Red Avanzado con Scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python sniffer.py --list-ifaces           # Listar interfaces
  python sniffer.py --iface eth0            # Capturar en eth0
  python sniffer.py --filter "tcp port 80"  # Solo tráfico HTTP
  python sniffer.py --outfile cap.pcap      # Guardar a archivo
        """
    )
    
    parser.add_argument(
        "--iface",
        help="Interfaz a escuchar (ej. eth0, Wi-Fi)",
        default=None
    )
    parser.add_argument(
        "--filter",
        help="Filtro BPF (ej. 'tcp port 80', 'icmp')",
        default=None
    )
    parser.add_argument(
        "--count",
        type=int,
        help="Número de paquetes a capturar (0 = infinito)",
        default=0
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Timeout en segundos (0 = infinito)",
        default=0
    )
    parser.add_argument(
        "--outfile",
        help="Archivo pcap de salida (opcional)",
        default=None
    )
    parser.add_argument(
        "--max-size",
        type=int,
        help="Tamaño máximo del pcap en MB (0 = ilimitado)",
        default=0
    )
    parser.add_argument(
        "--list-ifaces",
        action="store_true",
        help="Lista interfaces de red disponibles y termina"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Salida más verbosa"
    )
    
    args = parser.parse_args()
    
    # Listar interfaces si se solicita
    if args.list_ifaces:
        list_interfaces()
        sys.exit(0)
    
    # Verificar privilegios de administrador
    if not check_admin_privileges():
        console.print(Panel(
            "[bold red]✗ Error: Se requieren privilegios de administrador[/bold red]\n\n"
            "[white]Este sniffer necesita acceso de bajo nivel a la red.\n"
            "Por favor, ejecuta el script como:[/white]\n\n"
            "[cyan]• Windows:[/cyan] Ejecutar como Administrador\n"
            "[cyan]• Linux/macOS:[/cyan] sudo python sniffer.py",
            title="⚠ Permisos Insuficientes",
            border_style="red"
        ))
        sys.exit(1)
    
    # Configurar logging
    lvl = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=lvl, format="%(asctime)s %(levelname)s: %(message)s")
    
    # Configurar manejador de señales
    signal.signal(signal.SIGINT, signal_handler)
    
    # Mostrar banner de inicio
    console.print(Panel(
        f"[bold cyan]Interfaz:[/bold cyan] {args.iface or 'Todas'}\n"
        f"[bold cyan]Filtro:[/bold cyan] {args.filter or 'Ninguno'}\n"
        f"[bold cyan]Salida:[/bold cyan] {args.outfile or 'Sin guardar'}",
        title="🔍 Iniciando Captura",
        border_style="green"
    ))
    
    # Configurar writer de pcap (opcional)
    pcap_writer: Optional[PcapWriter] = None
    max_size_bytes = args.max_size * 1024 * 1024  # Convertir MB a bytes
    
    if args.outfile:
        try:
            pcap_writer = PcapWriter(args.outfile, append=True, sync=True)
            console.print(f"[green]✓ Archivo pcap: {args.outfile}[/green]")
            if args.max_size > 0:
                console.print(f"[dim]  Límite de tamaño: {args.max_size} MB[/dim]")
        except PermissionError:
            console.print(f"[red]✗ Error: Sin permisos para escribir en '{args.outfile}'[/red]")
            sys.exit(1)
        except OSError as e:
            console.print(f"[red]✗ Error al crear archivo: {e}[/red]")
            sys.exit(1)
    
    console.print("[dim]Presiona Ctrl+C para detener y ver estadísticas...[/dim]\n")
    
    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=lambda pkt: procesar_paquete(pkt, pcap_writer, max_size_bytes),
            store=False,
            count=args.count if args.count > 0 else 0,
            timeout=args.timeout if args.timeout > 0 else None
        )
    except PermissionError:
        console.print("[red]✗ Error: Permisos insuficientes para capturar en esta interfaz[/red]")
        sys.exit(1)
    except OSError as e:
        if "No such device" in str(e) or "doesn't exist" in str(e):
            console.print(f"[red]✗ Error: Interfaz '{args.iface}' no encontrada[/red]")
            console.print("[dim]Usa --list-ifaces para ver interfaces disponibles[/dim]")
        else:
            console.print(f"[red]✗ Error de red: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        LOG.exception("Error durante la captura: %s", e)
        console.print(f"[red]✗ Error inesperado: {e}[/red]")
    finally:
        # Cerrar writer de pcap
        if pcap_writer:
            try:
                pcap_writer.close()
                console.print(f"\n[green] Captura guardada en: {args.outfile}[/green]")
            except Exception:
                pass
        
        # Mostrar estadísticas finales
        show_statistics()


if __name__ == "__main__":
    main()
