#!/usr/bin/env python3
"""
ua_server.py - Servidor HTTP que captura la cabecera User-Agent de cada peticion.

QUE: levanta un servidor HTTP minimo que registra, por cada peticion entrante,
     la IP de origen, el metodo, la ruta y la cabecera User-Agent.
POR QUE: en un ejercicio de recoleccion, un "beacon" propio permite ver quien/
         que accede (navegador, bot, scanner). Util para entender fingerprinting
         del lado servidor: el User-Agent identifica navegador/SO/version.
COMO: python3 ua_server.py --puerto 8080
      luego visita http://TU_IP:8080/ desde distintos clientes.
QUE BUSCAR: User-Agents de bots/scanners (curl, nmap, python-requests...) vs
            navegadores reales; patrones de version que delatan el cliente.

Uso en tu propia maquina / laboratorio. No es un servicio de produccion.
"""

import argparse
import datetime
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = "user_agents.log"


def analizar_ua(ua):
    """
    Interpreta un User-Agent "a grandes rasgos" y devuelve un dict con lo que
    se puede DEDUCIR de el. El UA es una cadena que el cliente envia y que el
    servidor puede usar para:
      - fingerprinting: SO, navegador y version -> superficie de ataque.
      - deteccion de bots/scanners (curl, nmap, sqlmap, python-requests...).
      - content negotiation / cloaking: servir contenido distinto por cliente.
    OJO: el UA lo controla el cliente -> es FALSIFICABLE. No sirve como control
    de seguridad, solo como senal.
    """
    low = ua.lower()
    info = {"so": "desconocido", "navegador": "desconocido",
            "tipo": "navegador", "notas": []}

    # Sistema operativo.
    if "windows nt 10" in low:
        info["so"] = "Windows 10/11"
    elif "windows" in low:
        info["so"] = "Windows"
    elif "android" in low:
        info["so"] = "Android"
    elif "iphone" in low or "ios" in low:
        info["so"] = "iOS"
    elif "mac os x" in low or "macintosh" in low:
        info["so"] = "macOS"
    elif "linux" in low:
        info["so"] = "Linux"

    # Herramientas / bots (orden importa: mas especifico primero).
    herramientas = ["sqlmap", "nikto", "nmap", "masscan", "nuclei", "ffuf",
                    "gobuster", "wpscan", "curl", "wget", "python-requests",
                    "go-http-client", "httpx", "zgrab", "bot", "spider",
                    "crawler", "scanner"]
    for h in herramientas:
        if h in low:
            info["tipo"] = "bot/herramienta"
            info["navegador"] = h
            info["notas"].append(
                f"UA tipico de herramienta/scanner: '{h}'. En un sitio real, "
                "candidato a bloqueo/rate-limit.")
            return info

    # Navegadores reales.
    if "edg/" in low:
        info["navegador"] = "Edge"
    elif "chrome/" in low and "chromium" not in low:
        info["navegador"] = "Chrome"
    elif "firefox/" in low:
        info["navegador"] = "Firefox"
    elif "safari/" in low and "chrome/" not in low:
        info["navegador"] = "Safari"

    if not ua.strip() or ua == "(sin User-Agent)":
        info["tipo"] = "sospechoso"
        info["notas"].append(
            "Sin User-Agent: navegadores siempre lo envian -> cliente scriptado.")
    return info


class Handler(BaseHTTPRequestHandler):
    # Silenciamos el log por defecto (lo gestionamos nosotros).
    def log_message(self, formato, *args):  # noqa: A003
        return

    def _registrar(self):
        ahora = datetime.datetime.now().isoformat(timespec="seconds")
        ua = self.headers.get("User-Agent", "(sin User-Agent)")
        ip = self.client_address[0]
        analisis = analizar_ua(ua)
        registro = {
            "ts": ahora,
            "ip": ip,
            "metodo": self.command,
            "ruta": self.path,
            "user_agent": ua,
            "analisis_ua": analisis,
            # Guardamos todas las cabeceras por si interesan (Accept-Language,
            # X-Forwarded-For para detectar proxies, etc.).
            "cabeceras": {k: v for k, v in self.headers.items()},
        }
        # Consola legible: enseñamos lo deducido del UA.
        print(f"[{ahora}] {ip} {self.command} {self.path}")
        print(f"    User-Agent: {ua}")
        print(f"    -> SO: {analisis['so']} | Cliente: {analisis['navegador']} "
              f"| Tipo: {analisis['tipo']}")
        for n in analisis["notas"]:
            print(f"    [!] {n}")
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            print(f"    X-Forwarded-For: {xff}  <- posible proxy/balanceador")
        # Fichero JSON-lines (una linea por peticion, facil de parsear luego).
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(registro, ensure_ascii=False) + "\n")

    def _responder(self):
        self._registrar()
        cuerpo = (
            "<html><head><title>UA capture</title></head><body>"
            "<h1>Peticion registrada</h1>"
            f"<p>Tu User-Agent: <code>{self.headers.get('User-Agent','')}</code></p>"
            f"<p>Tu IP (vista por el servidor): <code>{self.client_address[0]}</code></p>"
            "</body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        # No exponemos la version real del servidor.
        self.send_header("Server", "ua-capture")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(cuerpo)

    # Capturamos los metodos mas comunes.
    def do_GET(self):   # noqa: N802
        self._responder()

    def do_POST(self):  # noqa: N802
        self._responder()

    def do_HEAD(self):  # noqa: N802
        self._responder()

    # Oculta la version de BaseHTTPRequestHandler en el banner.
    def version_string(self):
        return "ua-capture"


def main():
    global LOG_PATH
    p = argparse.ArgumentParser(
        description="Servidor HTTP que captura User-Agents de las peticiones.")
    p.add_argument("--host", default="0.0.0.0",
                   help="interfaz de escucha (por defecto 0.0.0.0)")
    p.add_argument("--puerto", type=int, default=8080,
                   help="puerto (por defecto 8080)")
    p.add_argument("--log", default=LOG_PATH,
                   help=f"fichero de log JSON-lines (por defecto {LOG_PATH})")
    args = p.parse_args()

    LOG_PATH = args.log

    servidor = ThreadingHTTPServer((args.host, args.puerto), Handler)
    print(f"[*] Escuchando en http://{args.host}:{args.puerto}/")
    print(f"[*] Registrando User-Agents en: {os.path.abspath(LOG_PATH)}")
    print("[*] Ctrl+C para parar.\n")
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Parando servidor.")
    finally:
        servidor.server_close()


if __name__ == "__main__":
    main()
