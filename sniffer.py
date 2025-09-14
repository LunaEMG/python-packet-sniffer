#!/usr/bin/env python3
"""
Sniffer con Scapy:
- argumentos CLI (iface, filter, count, timeout, outfile)
- store=False para no retener en memoria
- PcapWriter para persistencia en tiempo real
- logging y manejo de excepciones
"""

import argparse
import logging
from datetime import datetime
from scapy.all import sniff, PcapWriter, IP, TCP, UDP

LOG = logging.getLogger("sniffer")

def procesar_paquete(pkt, pcap_writer=None):
    """
    Procesa cada paquete capturado.
    - pkt: objeto Scapy
    - pcap_writer: instancia de PcapWriter para persistir
    """
    try:
        ts = datetime.now().isoformat(sep=' ', timespec='milliseconds')
        summary = pkt.summary()
        # Extraer campos comunes de interés (si existen)
        src = pkt[IP].src if IP in pkt else "-"
        dst = pkt[IP].dst if IP in pkt else "-"
        proto = "?"
        sport = dport = "-"
        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        LOG.info("%s | %s -> %s | %s %s->%s | %s",
                 ts, src, dst, proto, sport, dport, summary)

        # Guardar en pcap si nos dieron un writer
        if pcap_writer:
            pcap_writer.write(pkt)

    except Exception as e:
        LOG.exception("Error procesando paquete: %s", e)
        # no re-levantar excepción para no detener sniffing

def main():
    parser = argparse.ArgumentParser(description="Sniffer con Scapy")
    parser.add_argument("--iface", help="Interfaz a escuchar (ej. eth0)", default=None)
    parser.add_argument("--filter", help="Filtro BPF (ej. 'tcp port 80')", default=None)
    parser.add_argument("--count", type=int, help="Número de paquetes a capturar (0 = infinito)", default=0)
    parser.add_argument("--timeout", type=int, help="Timeout en segundos (0 = infinito)", default=0)
    parser.add_argument("--outfile", help="Archivo pcap de salida (append)", default="capture.pcap")
    parser.add_argument("--verbose", action="store_true", help="Salida más verbosa")
    args = parser.parse_args()

    # Configurar logging
    lvl = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=lvl, format="%(asctime)s %(levelname)s: %(message)s")

    LOG.info("Iniciando sniffer. Interfaz=%s Filter=%s Count=%d Timeout=%d Out=%s",
             args.iface, args.filter, args.count, args.timeout, args.outfile)

    pcap_writer = PcapWriter(args.outfile, append=True, sync=True)

    try:
        sniff(
        iface=args.iface,
        filter=args.filter,
        prn=lambda pkt: procesar_paquete(pkt, pcap_writer),
        store=False,
        count=args.count if args.count > 0 else 0,
        timeout=args.timeout if args.timeout > 0 else None
        )
    except KeyboardInterrupt:
        LOG.info("Interrumpido por el usuario (KeyboardInterrupt). Cerrando.")
    except Exception as e:
        LOG.exception("sniff falló: %s", e)
    finally:
        # cerrar writer (asegura flushing)
        try:
            pcap_writer.close()
            LOG.info("Pcap guardado en %s", args.outfile)
        except Exception:
            pass

if __name__ == "__main__":
    main()
