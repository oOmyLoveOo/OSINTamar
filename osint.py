#!/usr/bin/env python3
"""
osint.py - Herramienta unica de OSINT / recon para el ejercicio de clase (CPTS).

Reune en una sola CLI con subcomandos:
  recon    -> enumeracion pasiva y activa de un dominio
  headers  -> auditoria de cabeceras de seguridad de una URL
  serve    -> servidor HTTP que captura y clasifica User-Agents

Ejemplos:
  python3 osint.py recon   tajamar.es
  python3 osint.py recon   tajamar.es --activo --nmap -o salida/
  python3 osint.py headers https://tajamar.es otro.com -o cabeceras.json
  python3 osint.py serve   --puerto 8080

USO ETICO: la fase 'activa' (y nmap/whatweb) genera trafico directo contra el
objetivo y es RUIDOSA. Usala solo contra dominios propios o con autorizacion
explicita (p. ej. alcance de un programa de YesWeHack / bug bounty). La fase
pasiva no toca al objetivo: consulta bases de datos de terceros.
"""

import argparse
import datetime
import json
import os
import socket
import ssl
import subprocess
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from shutil import which

try:
    import requests
    # Silenciamos el aviso de "InsecureRequestWarning" (usamos verify=False a
    # proposito: muchos objetivos tienen TLS invalido y no queremos que el
    # recon reviente por eso).
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:  # noqa: BLE001
        pass
except ImportError:
    requests = None


# ==========================================================================
# Utilidades comunes
# ==========================================================================
def banner(titulo):
    linea = "=" * 70
    print(f"\n{linea}\n[*] {titulo}\n{linea}")


def nota(texto):
    print(f"    -> {texto}")


def tiene(binario):
    return which(binario) is not None


def run_cmd(cmd, timeout=120):
    """Ejecuta un comando externo. Devuelve (ok, salida). No lanza excepciones."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode == 0, ((res.stdout or "") + (res.stderr or "")).strip()
    except FileNotFoundError:
        return False, f"[!] Herramienta no instalada: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, f"[!] Timeout ({timeout}s): {' '.join(cmd)}"
    except Exception as e:  # noqa: BLE001
        return False, f"[!] Error ejecutando {cmd[0]}: {e}"


def http_get(url, timeout=20, headers=None):
    """GET tolerante a TLS invalido. Devuelve (status, dict_cabeceras_lower, texto, url_final)."""
    headers = headers or {"User-Agent": "osint-clase/1.0"}
    if requests:
        r = requests.get(url, timeout=timeout, verify=False, headers=headers,
                         allow_redirects=True)
        cab = {k.lower(): v for k, v in r.headers.items()}
        return r.status_code, cab, r.text, r.url
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        cab = {k.lower(): v for k, v in resp.headers.items()}
        cuerpo = resp.read().decode(errors="ignore")
        return resp.status, cab, cuerpo, resp.url


def limpiar_dominio(valor):
    return (valor.strip().lower()
            .replace("https://", "").replace("http://", "").strip("/"))


# ==========================================================================
# SUBCOMANDO: recon
# ==========================================================================
def whois_lookup(dominio, resultados):
    """WHOIS: registrador, fechas, nameservers. QUE BUSCAR: NS (hosting/CDN), fechas."""
    banner("WHOIS (pasivo)")
    if not tiene("whois"):
        nota("binario 'whois' no encontrado; omitiendo.")
        resultados["whois"] = None
        return
    ok, out = run_cmd(["whois", dominio], timeout=30)
    print(out or "(sin salida)")
    nota("Fijate en nameservers y fechas: delatan hosting/CDN y antiguedad.")
    resultados["whois"] = out[:2000]


def dns_registros(dominio, resultados):
    """DNS A/AAAA/MX/NS/TXT/SOA/CNAME + DMARC. QUE BUSCAR: SPF/DMARC, IPs, proveedores."""
    banner("Registros DNS (pasivo/semi-activo)")
    reg = {}
    for t in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
        if tiene("dig"):
            ok, out = run_cmd(["dig", "+short", dominio, t], timeout=20)
        else:
            ok, out = run_cmd(["host", "-t", t, dominio], timeout=20)
        out = out.strip()
        reg[t] = out.splitlines() if out else []
        print(f"[{t}]\n    " + (out.replace("\n", "\n    ") if out else "(vacio)"))

    # DMARC vive en _dmarc.<dominio> como TXT. Su ausencia = spoofing de correo.
    if tiene("dig"):
        ok, dmarc = run_cmd(["dig", "+short", "TXT", f"_dmarc.{dominio}"], timeout=20)
    else:
        ok, dmarc = run_cmd(["host", "-t", "TXT", f"_dmarc.{dominio}"], timeout=20)
    dmarc = dmarc.strip()
    reg["DMARC"] = dmarc.splitlines() if dmarc else []
    print(f"[DMARC]\n    " + (dmarc or "(vacio) <- sin DMARC: correo mas facil de falsificar"))

    nota("TXT suele llevar SPF y verificaciones de SaaS -> lista proveedores (Salesforce, etc.).")
    nota("MX revela el proveedor de correo; sin DMARC el dominio es spoofeable.")
    resultados["dns"] = reg


def crtsh(dominio, resultados):
    """crt.sh (Certificate Transparency): subdominios sin tocar el objetivo. Con reintento."""
    banner("crt.sh - Certificate Transparency (pasivo)")
    url = f"https://crt.sh/?q=%25.{dominio}&output=json"
    data = None
    for intento in range(1, 4):  # reintento: crt.sh a veces responde vacio/lento
        try:
            status, _, texto, _ = http_get(url, timeout=40)
            if status == 200 and texto.strip():
                data = json.loads(texto)
                break
            nota(f"intento {intento}: crt.sh devolvio vacio/{status}, reintentando...")
        except Exception as e:  # noqa: BLE001
            nota(f"intento {intento} fallo: {e}")
    if data is None:
        nota("No se pudo obtener datos de crt.sh tras 3 intentos.")
        resultados["crtsh"] = None
        return

    subs = set()
    for entrada in data:
        for s in entrada.get("name_value", "").splitlines():
            s = s.strip().lstrip("*.").lower()
            if s.endswith(dominio):
                subs.add(s)
    subs = sorted(subs)
    for s in subs:
        print(f"    {s}")
    nota(f"{len(subs)} subdominios unicos en CT logs. Los que resuelven = superficie viva.")
    resultados["crtsh"] = subs


def wayback(dominio, resultados):
    """Wayback Machine: URLs historicas. QUE BUSCAR: rutas/endpoints ya no enlazados."""
    banner("Wayback Machine - URLs historicas (pasivo)")
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{dominio}/*"
           f"&output=text&fl=original&collapse=urlkey&limit=200")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "osint-clase/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            urls = resp.read().decode(errors="ignore").splitlines()
    except Exception as e:  # noqa: BLE001
        nota(f"No se pudo consultar Wayback: {e}")
        resultados["wayback"] = None
        return
    for u in urls[:200]:
        print(f"    {u}")
    nota(f"{len(urls)} URLs (limite 200). OJO: rutas /Chrome/ /Firefox/ suelen ser basura de scripts, no reales.")
    resultados["wayback"] = urls[:200]


def google_dorks(dominio, resultados):
    """Genera dorks listos para pegar (pasivo: consultan al buscador, no al objetivo)."""
    banner("Google Dorks sugeridos (pasivo - pegar en el navegador)")
    dorks = [
        f'site:{dominio} filetype:pdf',
        f'site:{dominio} inurl:admin',
        f'site:{dominio} intitle:"index of"',
        f'site:{dominio} intext:"password" | intext:"contrasena"',
        f'site:{dominio} inurl:login',
        f'site:{dominio} ext:sql | ext:env | ext:log | ext:bak',
        f'site:{dominio} inurl:wp-admin',
        f'(site:github.com | site:pastebin.com) "{dominio}"',
    ]
    for d in dorks:
        print(f"    {d}")
    nota("Dorking en GitHub/Pastebin suele filtrar API keys y config.")
    resultados["google_dorks"] = dorks


def resolver_subs(subs):
    vivos = {}
    for s in subs:
        try:
            vivos[s] = socket.gethostbyname(s)
        except (socket.gaierror, UnicodeError):
            continue
    return vivos


def activa_dns(dominio, resultados):
    """Enumeracion DNS activa (dnsrecon) + resuelve los subdominios de crt.sh."""
    banner("Enumeracion DNS activa (RUIDOSO)")
    if tiene("dnsrecon"):
        nota("Ejecutando dnsrecon -t std ...")
        ok, out = run_cmd(["dnsrecon", "-d", dominio, "-t", "std"], timeout=120)
        print(out[:4000])
    else:
        nota("dnsrecon no instalado; omitiendo.")
    subs = resultados.get("crtsh") or []
    if subs:
        nota(f"Resolviendo {len(subs)} subdominios de crt.sh...")
        vivos = resolver_subs(subs)
        for s, ip in sorted(vivos.items()):
            print(f"    {s:45s} -> {ip}")
        nota(f"{len(vivos)} subdominios vivos = objetivos reales.")
        resultados["subdominios_vivos"] = vivos


def fingerprint_tech(dominio, resultados):
    """whatweb + heuristica propia (WordPress / Plesk / PHP EOL) sobre las cabeceras."""
    banner("Fingerprinting de tecnologias (RUIDOSO)")
    pistas = []
    # Heuristica propia a partir de una peticion normal.
    try:
        status, cab, cuerpo, _ = http_get(f"https://{dominio}", timeout=20)
        powered = cab.get("x-powered-by", "")
        if "php/8.0" in powered.lower() or "php/7" in powered.lower() or "php/5" in powered.lower():
            pistas.append(f"PHP posiblemente EOL detectado ({powered}) -> sin parches de seguridad.")
        if "plesk" in powered.lower():
            pistas.append("Panel Plesk (X-Powered-By) -> revisa el panel de gestion en :8443.")
        low = cuerpo.lower()
        if "wp-content" in low or "wp-json" in low or "/wp-includes" in low:
            pistas.append("WordPress detectado -> prueba wp-login.php, wp-json/wp/v2/users, enum de plugins.")
    except Exception as e:  # noqa: BLE001
        nota(f"No se pudo hacer la peticion de fingerprint: {e}")

    for p in pistas:
        print(f"  [tech] {p}")
    resultados["tech_pistas"] = pistas

    if tiene("whatweb"):
        # -a 1 (stealthy): mas rapido y evita el timeout que daba -a 3 (agresivo).
        ok, out = run_cmd(["whatweb", "-a", "1", f"https://{dominio}"], timeout=90)
        if out:
            print(out)
        resultados["whatweb"] = out
    else:
        nota("whatweb no instalado; me quedo con la heuristica propia.")


def ficheros_conocidos(dominio, resultados):
    """robots.txt / sitemap.xml: rutas que el dueno (a veces) no quiere indexadas."""
    banner("Ficheros conocidos: robots.txt / sitemap.xml (semi-activo)")
    hallados = {}
    for fich in ("robots.txt", "sitemap.xml"):
        for esquema in ("https://", "http://"):
            try:
                status, _, cuerpo, _ = http_get(f"{esquema}{dominio}/{fich}", timeout=15)
                print(f"\n[{esquema}{dominio}/{fich}] (HTTP {status})")
                print("    " + cuerpo[:1500].replace("\n", "\n    "))
                hallados[fich] = cuerpo[:5000]
                break
            except Exception:  # noqa: BLE001
                continue
        if fich not in hallados:
            nota(f"{fich} no accesible.")
    nota("Las lineas 'Disallow:' de robots.txt son pistas de rutas sensibles.")
    resultados["ficheros_conocidos"] = hallados


def activa_nmap(dominio, resultados):
    """nmap top-ports con -sV -oA (metodologia dual: completar con -p- en otra terminal)."""
    banner("Escaneo de puertos nmap (MUY RUIDOSO)")
    if not tiene("nmap"):
        nota("nmap no instalado; omitiendo.")
        return
    outbase = os.path.join(resultados["_outdir"], "nmap_top")
    nota("Escaneo rapido top-ports con -sV -oA (guarda todos los formatos).")
    ok, out = run_cmd(
        ["nmap", "-sV", "-T4", "--top-ports", "1000", "-oA", outbase, dominio],
        timeout=300)
    print(out)
    nota("Lanza el completo en OTRA terminal:")
    print(f"      nmap -p- -sV -T4 -oA {resultados['_outdir']}/nmap_full {dominio}")
    nota("Nunca te fies solo de top-ports: WSUS 8530/8531 se pierde. Plesk suele estar en 8443.")
    resultados["nmap_top"] = out


def cmd_recon(args):
    dominio = limpiar_dominio(args.dominio)
    os.makedirs(args.outdir, exist_ok=True)
    resultados = {
        "_dominio": dominio,
        "_fecha": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "_outdir": args.outdir,
    }
    print(f"\n### Recon de {dominio} ###\n### {resultados['_fecha']} ###")
    if args.activo:
        print("### MODO ACTIVO: trafico directo al objetivo. Asegura autorizacion. ###")

    whois_lookup(dominio, resultados)
    dns_registros(dominio, resultados)
    crtsh(dominio, resultados)
    wayback(dominio, resultados)
    google_dorks(dominio, resultados)

    if args.activo:
        activa_dns(dominio, resultados)
        fingerprint_tech(dominio, resultados)
        ficheros_conocidos(dominio, resultados)
        if args.nmap:
            activa_nmap(dominio, resultados)

    salida = os.path.join(args.outdir, f"{dominio}_recon.json")
    dump = {k: v for k, v in resultados.items() if k != "_outdir"}
    with open(salida, "w") as f:
        json.dump(dump, f, indent=2, ensure_ascii=False)
    banner("Resumen")
    nota(f"Resultados guardados en: {salida}")
    nota("Recon no es lineal: un subdominio tardio puede reabrir fases anteriores.")


# ==========================================================================
# SUBCOMANDO: headers
# ==========================================================================
ESPERADAS = {
    "strict-transport-security": ("Fuerza HTTPS; sin ella, posible downgrade a HTTP (MITM).",
                                  "max-age>=15768000; includeSubDomains"),
    "content-security-policy": ("Mitiga XSS e inyeccion de recursos; su ausencia facilita XSS.",
                                "default-src 'self' (restrictiva)"),
    "x-frame-options": ("Previene clickjacking (embeber el sitio en un iframe).",
                        "DENY o SAMEORIGIN"),
    "x-content-type-options": ("Impide MIME-sniffing del navegador.", "nosniff"),
    "referrer-policy": ("Controla cuanta URL se filtra en el header Referer.",
                        "no-referrer o strict-origin-when-cross-origin"),
    "permissions-policy": ("Restringe APIs del navegador (camara, micro, geoloc).",
                           "deshabilitar lo no usado"),
    "cross-origin-opener-policy": ("Aisla el contexto de navegacion (Spectre / XS-Leaks).",
                                   "same-origin"),
}
FILTRADORAS = ["server", "x-powered-by", "x-aspnet-version",
               "x-aspnetmvc-version", "via", "x-generator"]


def analizar_headers(url):
    print(f"\n{'='*70}\n[*] Analizando cabeceras de: {url}\n{'='*70}")
    try:
        status, cab, _, url_final = http_get(url, timeout=20)
    except Exception as e:  # noqa: BLE001
        print(f"[!] Error al conectar: {e}")
        return None
    print(f"[+] HTTP {status}  (URL final: {url_final})\n")

    inf = {"url": url, "url_final": url_final, "status": status,
           "presentes": {}, "ausentes": [], "filtradoras": {}}

    print("--- Cabeceras de seguridad ---")
    for nombre, (porque, sano) in ESPERADAS.items():
        if nombre in cab:
            print(f"  [OK ] {nombre}: {cab[nombre]}")
            inf["presentes"][nombre] = cab[nombre]
        else:
            print(f"  [!! ] FALTA {nombre}\n         por que: {porque}\n         valor sano: {sano}")
            inf["ausentes"].append(nombre)

    print("\n--- Cabeceras que filtran informacion ---")
    hay = False
    for nombre in FILTRADORAS:
        if nombre in cab:
            hay = True
            print(f"  [info] {nombre}: {cab[nombre]}  <- revela stack/version")
            inf["filtradoras"][nombre] = cab[nombre]
    if not hay:
        print("  (ninguna cabecera verbosa evidente)")

    ok = len(inf["presentes"])
    print(f"\n[=] Puntuacion: {ok}/{len(ESPERADAS)} cabeceras de seguridad presentes.")
    if inf["ausentes"]:
        print("    Prioriza en el informe: " + ", ".join(inf["ausentes"]))
    return inf


def cmd_headers(args):
    informes = []
    for url in args.urls:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        inf = analizar_headers(url)
        if inf:
            informes.append(inf)
    if args.out:
        with open(args.out, "w") as f:
            json.dump(informes, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Informe guardado en {args.out}")


# ==========================================================================
# SUBCOMANDO: serve (captura User-Agents)
# ==========================================================================
def analizar_ua(ua):
    """
    Interpreta un User-Agent "a grandes rasgos". El UA es una cadena que el
    cliente envia; el servidor la usa para fingerprinting (SO/navegador/version),
    deteccion de bots/scanners y content negotiation. OJO: lo controla el cliente
    -> es FALSIFICABLE y, a la vez, es entrada no confiable (sanear antes de
    almacenar/mostrar: posible XSS/SQLi/log-injection).
    """
    low = ua.lower()
    info = {"so": "desconocido", "navegador": "desconocido",
            "tipo": "navegador", "notas": []}
    for clave, nombre in [("windows nt 10", "Windows 10/11"), ("windows", "Windows"),
                          ("android", "Android"), ("iphone", "iOS"), ("ios", "iOS"),
                          ("mac os x", "macOS"), ("macintosh", "macOS"), ("linux", "Linux")]:
        if clave in low:
            info["so"] = nombre
            break
    herramientas = ["sqlmap", "nikto", "nmap", "masscan", "nuclei", "ffuf",
                    "gobuster", "wpscan", "curl", "wget", "python-requests",
                    "go-http-client", "httpx", "zgrab", "bot", "spider",
                    "crawler", "scanner"]
    for h in herramientas:
        if h in low:
            info.update(tipo="bot/herramienta", navegador=h)
            info["notas"].append(
                f"UA tipico de herramienta/scanner: '{h}'. En un sitio real, candidato a bloqueo/rate-limit.")
            return info
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
        info["notas"].append("Sin User-Agent: navegadores siempre lo envian -> cliente scriptado.")
    return info


def hacer_handler(log_path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, formato, *args):  # noqa: A003
            return

        def version_string(self):
            return "ua-capture"

        def _registrar(self):
            ahora = datetime.datetime.now().isoformat(timespec="seconds")
            ua = self.headers.get("User-Agent", "(sin User-Agent)")
            ip = self.client_address[0]
            an = analizar_ua(ua)
            registro = {"ts": ahora, "ip": ip, "metodo": self.command,
                        "ruta": self.path, "user_agent": ua, "analisis_ua": an,
                        "cabeceras": dict(self.headers.items())}
            print(f"[{ahora}] {ip} {self.command} {self.path}")
            print(f"    User-Agent: {ua}")
            print(f"    -> SO: {an['so']} | Cliente: {an['navegador']} | Tipo: {an['tipo']}")
            for n in an["notas"]:
                print(f"    [!] {n}")
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                print(f"    X-Forwarded-For: {xff}  <- posible proxy/balanceador")
            with open(log_path, "a") as f:
                f.write(json.dumps(registro, ensure_ascii=False) + "\n")

        def _responder(self):
            self._registrar()
            cuerpo = (
                "<html><head><title>UA capture</title></head><body>"
                "<h1>Peticion registrada</h1>"
                f"<p>Tu User-Agent: <code>{self.headers.get('User-Agent','')}</code></p>"
                f"<p>Tu IP: <code>{self.client_address[0]}</code></p></body></html>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(cuerpo)))
            self.send_header("Server", "ua-capture")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(cuerpo)

        do_GET = _responder
        do_POST = _responder
        do_HEAD = _responder
    return Handler


def cmd_serve(args):
    log_path = os.path.abspath(args.log)
    servidor = ThreadingHTTPServer((args.host, args.puerto), hacer_handler(log_path))
    print(f"[*] Escuchando en http://{args.host}:{args.puerto}/")
    print(f"[*] Registrando User-Agents en: {log_path}")
    print("[*] Ctrl+C para parar.\n")
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Parando servidor.")
    finally:
        servidor.server_close()


# ==========================================================================
# CLI
# ==========================================================================
def main():
    p = argparse.ArgumentParser(
        prog="osint.py",
        description="Herramienta OSINT/recon unica (ejercicio CPTS). Subcomandos: recon, headers, serve.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("recon", help="enumeracion pasiva y activa de un dominio")
    pr.add_argument("dominio", help="dominio objetivo (p.ej. tajamar.es)")
    pr.add_argument("--activo", action="store_true", help="fase activa (RUIDOSA, requiere permiso)")
    pr.add_argument("--nmap", action="store_true", help="incluye escaneo nmap en la fase activa")
    pr.add_argument("-o", "--outdir", default="recon_out", help="directorio de salida")
    pr.set_defaults(func=cmd_recon)

    ph = sub.add_parser("headers", help="auditoria de cabeceras de seguridad de una URL")
    ph.add_argument("urls", nargs="+", help="URL(s), p.ej. https://tajamar.es")
    ph.add_argument("-o", "--out", help="guardar informe JSON en este fichero")
    ph.set_defaults(func=cmd_headers)

    ps = sub.add_parser("serve", help="servidor HTTP que captura y clasifica User-Agents")
    ps.add_argument("--host", default="0.0.0.0", help="interfaz de escucha")
    ps.add_argument("--puerto", type=int, default=8080, help="puerto (por defecto 8080)")
    ps.add_argument("--log", default="user_agents.log", help="fichero de log JSON-lines")
    ps.set_defaults(func=cmd_serve)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
