# 🐍 Python Packet Sniffer 🐍
Un sniffer de paquetes ligero y extensible para análisis de tráfico en tiempo real, construido con Python y Scapy.  

Permite capturar, analizar y guardar el tráfico de red directamente desde la línea de comandos en Linux, macOS y Windows (con Npcap).

---

## Características Principales
* Captura en Tiempo Real: Visualiza el tráfico de red al instante.
* Argumentos CLI: Personaliza la captura usando interfaz, filtros, número de paquetes, y más.
* Filtros Potentes: Compatible con filtros BPF (ej. `tcp port 443`).
* Guardado en Vivo: Almacena la sesión en `.pcap` de forma inmediata para análisis forense.
* Bajo Consumo de Memoria: Usa `store=False`, ideal para sesiones largas.
* Logging Configurable: Salida clara, con soporte para niveles INFO/DEBUG.

---

## Requisitos Previos
* Python 3.8+
* Scapy (`pip install scapy`)
* Npcap (Windows): Descárgalo en https://npcap.com/#download con la opción *WinPcap API-compatible* habilitada.
* libpcap (Linux/macOS): Suele venir instalado de forma nativa.

---

## Instalación
```bash
git clone https://github.com/LunaEMG/python-packet-sniffer.git
cd python-packet-sniffer
pip install -r requirements.txt
```

> (Opcional) Crear y activar un entorno virtual con:
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate
```

---

## Modo de Uso
> El script debe ejecutarse con privilegios de administrador.

#### Captura básica
```bash
sudo python3 sniffer.py   # Linux/macOS
python sniffer.py         # Windows (desde terminal Administrador)
```

#### Capturar 10 paquetes
```bash
python sniffer.py --count 10
```

#### Filtrar HTTP/HTTPS
```bash
python sniffer.py --filter "tcp port 80 or tcp port 443"
```

#### Capturar DNS
```bash
python sniffer.py --filter "udp port 53"
```

#### Usar interfaz específica
```bash
python sniffer.py --iface eth0 --filter "tcp port 22"
```

#### Guardar en archivo personalizado
```bash
python sniffer.py --filter "icmp" --outfile ping_capture.pcap
```

---

## Licencia
Este proyecto está bajo la Licencia MIT. Consulta el archivo LICENSE.

Aviso Legal: Este software debe utilizarse únicamente en redes propias o con autorización explícita.
EL AUTOR NO SE HACE RESPONSABLE DEL USO INDEBIDO. ⚠️⚠️⚠️
