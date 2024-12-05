import sys
import socket
import subprocess
import platform
from datetime import datetime, timezone
import time

try:
    import requests
    import nmap
except ImportError:
    print("Instalando librería dependientes para escaneo... ")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-nmap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import nmap
    import requests

def discover_os(target):
    """Intenta identificar el sistema operativo del objetivo."""
    try:
        if platform.system().lower() == "windows":
            command = ["ping", "-n", "1", target]
        else:
            command = ["ping", "-c", "1", target]
        result = subprocess.run(command, capture_output=True, text=True)
        if "ttl=64" or "ttl=63" in result.stdout.lower():
            return "Linux/Unix-based OS"
        elif "ttl=128" or "ttl=127" in result.stdout.lower():
            return "Windows OS"
        elif "ttl=255" or "ttl=254" in result.stdout.lower():
            return "Cisco OS/Router"
        else:
            return "No se pudo identificar el SO"
    except Exception:
        return "No se pudo identificar el SO"

def get_service_version(target, port):
    """Obtiene la versión del servicio de forma genérica"""
    nm = nmap.PortScanner()
    try:
        # Escanear el puerto de forma estándar
        nm.scan(target, str(port))
        if nm.all_hosts():
            host_info = nm[target]
            if 'tcp' in host_info and port in host_info['tcp']:
                service = host_info['tcp'][port]
                if 'name' in service and 'product' in service:
                    return f"{service['name']} {service['product']} {service.get('version', 'Desconocido')}"
                return "Servicio desconocido"
        return "No se pudo determinar la versión"
    except Exception as e:
        print(f"Error al obtener la versión del servicio en el puerto {port}: {e}")
        return "No se pudo determinar la versión del servicio"

def scan_target(target):
    """Escanea el objetivo para encontrar puertos abiertos y servicios."""
    open_ports = []
    port_info = []
    start_time = time.time()

    # Detectar sistema operativo
    os_info = discover_os(target)

    # Escanear puertos comunes (1-1024)
    for port in range(1, 9999):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
        except Exception:
            pass

    # Obtener servicios y versiones para puertos abiertos
    for port in open_ports:
        service_version = get_service_version(target, port)
        port_info.append((port, service_version))  # Ahora guardamos la información como tupla (Puerto, Servicio)

    end_time = time.time()
    duration = f"{int(end_time - start_time)}s"

    # Construir el informe formateado con columnas
    report = "\U0001F4E1 **Escaneo de Puertos Completado** \U0001F680\n\n"
    report += f"**Target:** {target}\n"
    report += f"**Sistema Operativo:** {os_info}\n"
    report += f"**Fecha/Hora:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n"
    report += "**Puertos y Servicios Abiertos:**\n"
   
    # Crear la tabla con solo dos columnas: Puerto y Servicio/Versión
    report += "+-----------+----------------------------------------------+\n"
    report += "  Puerto       Servicio y Versión                           \n"
    report += "+-----------+----------------------------------------------+\n"

    # Imprimir cada puerto con su servicio y versión
    for port, service in port_info:
        # Limitar los caracteres para que quede alineado adecuadamente
        service_name_version = service[:50] if len(service) > 50 else service
        report += f" {port:<9} \t {service_name_version:<46}\n"

    report += "+-----------+----------------------------------------------+\n"
    report += "\n**Duración del escaneo:** " + duration + "\n\n"
    report += "\U0001F50E *Revisar posibles vulnerabilidades según servicios detectados.*"

    # Comprobación de codificación del informe
    try:
        report_text = report.encode('utf-8').decode('utf-8')
    except UnicodeDecodeError as e:
        print(f"Error en la codificación del texto: {e}")
        report_text = "El reporte contiene caracteres no válidos"

    return report_text

def send_report_via_telegram(report, bot_token, chat_id):
    """Envía el informe a través de la API de Telegram."""
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": report,
        "parse_mode": "Markdown",
    }
    try:
        response = requests.post(api_url, data=payload)
        if response.status_code == 200:
            print("Informe enviado a Telegram exitosamente.")
        else:
            print(f"Error al enviar el informe a Telegram. Código de respuesta: {response.status_code}")
    except Exception as e:
        print(f"Error al conectar con Telegram: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 script.py <target.ip>")
        sys.exit(1)

    target_ip = sys.argv[1]

    # Token de bot de Telegram y chat ID
    telegram_bot_token = "7708506325:AAGZKPZklYU2mja2a9t2g1RNq9_8ZCYMAts"
    telegram_chat_id = "1371241712"

    print(f"Iniciando escaneo para {target_ip}...")
    scan_report = scan_target(target_ip)
    print(scan_report)

    print("Enviando informe a Telegram...")
    send_report_via_telegram(scan_report, telegram_bot_token, telegram_chat_id)