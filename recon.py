#!/usr/bin/env python3
"""
recon.py - Enumeracion OSINT pasiva y activa (ejercicio de clase CPTS).

Uso contra dominios PROPIOS o con autorizacion explicita (p.ej. programas
de yeswehack / bug bounty dentro de alcance). La parte "activa" genera
trafico directo contra el objetivo y es ruidosa: usala solo donde tengas
permiso.

Ejemplos:
  python3 recon.py example.com
  python3 recon.py example.com --activo
  python3 recon.py example.com --activo --wordlist subdominios.txt -o salida/

Que es -> por que importa -> como se usa -> que buscar:
  Cada modulo imprime una cabecera y notas sobre que mirar en el output.
"""

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

# requests es opcional; solo lo usamos para consultas HTTP a APIs publicas.
try:
    import requests
except ImportError:
    requests = None


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def banner(titulo):
    linea = "=" * 70
    print(f"\n{linea}\n[*] {titulo}\n{linea}")


def nota(texto):
    print(f"    -> {texto}")


def run_cmd(cmd, timeout=120):
    """Ejecuta un comando externo y devuelve (ok, salida). No lanza excepciones."""
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        salida = (res.stdout or "") + (res.stderr or "")
        return res.returncode == 0, salida.strip()
    except FileNotFoundError:
        return False, f"[!] Herramienta no instalada: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, f"[!] Timeout ({timeout}s) ejecutando: {' '.join(cmd)}"
    except Exception as e:  # noqa: BLE001
        return False, f"[!] Error ejecutando {cmd[0]}: {e}"


def tiene(binario):
    """True si el binario esta en PATH."""
    from shutil import which
    return which(binario) is not None


# --------------------------------------------------------------------------
# FASE PASIVA
# --------------------------------------------------------------------------
def whois_lookup(dominio, resultados):
    """
    QUE: consulta la base de datos publica del registrador (WHOIS).
    POR QUE: revela registrador, fechas de alta/expiracion, name servers y a
             veces datos de contacto y organizacion.
    QUE BUSCAR: nameservers (apuntan a infra/CDN), fechas, estado del dominio,
                correos de contacto, servidor registrador.
    """
    banner("WHOIS (pasivo)")
    if not tiene("whois"):
        nota("binario 'whois' no encontrado; omitiendo.")
        resultados["whois"] = None
        return
    ok, out = run_cmd(["whois", dominio], timeout=30)
    print(out if out else "(sin salida)")
    # Extraemos lineas de interes para el resumen.
    interes = {}
    for linea in out.splitlines():
        low = linea.lower()
        for clave in ("registrar:", "creation date", "registry expiry",
                      "name server", "org:", "registrant"):
            if low.strip().startswith(clave):
                interes.setdefault(clave, []).append(linea.strip())
    nota("Fijate en nameservers y fechas: delatan hosting/CDN y antiguedad.")
    resultados["whois"] = interes or out[:2000]


def dns_registros(dominio, resultados):
    """
    QUE: resolucion de registros DNS publicos (A, AAAA, MX, NS, TXT, SOA).
    POR QUE: mapea la infraestructura: IPs, correo (MX), proveedores (TXT/SPF),
             servidores autoritativos (NS).
    QUE BUSCAR: SPF/DMARC en TXT, IPs reales detras de CDN, proveedores cloud.
    """
    banner("Registros DNS (pasivo/semi-activo)")
    tipos = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    reg = {}
    for t in tipos:
        if tiene("dig"):
            ok, out = run_cmd(["dig", "+short", dominio, t], timeout=20)
        else:
            ok, out = run_cmd(["host", "-t", t, dominio], timeout=20)
        out = out.strip()
        reg[t] = out.splitlines() if out else []
        print(f"[{t}]")
        print("    " + (out.replace("\n", "\n    ") if out else "(vacio)"))
    nota("TXT suele llevar SPF/DMARC/verificaciones de SaaS -> lista proveedores.")
    nota("MX revela el proveedor de correo (Google, O365, propio...).")
    resultados["dns"] = reg


def crtsh(dominio, resultados):
    """
    QUE: consulta crt.sh (logs de Certificate Transparency).
    POR QUE: los certificados TLS emitidos revelan subdominios historicos y
             actuales sin tocar el objetivo (100% pasivo).
    QUE BUSCAR: subdominios internos/olvidados (dev, staging, vpn, mail...).
    """
    banner("crt.sh - Certificate Transparency (pasivo)")
    url = f"https://crt.sh/?q=%25.{dominio}&output=json"
    data = None
    try:
        if requests:
            r = requests.get(url, timeout=30,
                             headers={"User-Agent": "recon-clase/1.0"})
            if r.status_code == 200 and r.text.strip():
                data = r.json()
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "recon-clase/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
    except Exception as e:  # noqa: BLE001
        nota(f"No se pudo consultar crt.sh: {e}")
        resultados["crtsh"] = None
        return

    subs = set()
    for entrada in data or []:
        nombre = entrada.get("name_value", "")
        for s in nombre.splitlines():
            s = s.strip().lstrip("*.").lower()
            if s.endswith(dominio):
                subs.add(s)
    subs = sorted(subs)
    for s in subs:
        print(f"    {s}")
    nota(f"{len(subs)} subdominios unicos vistos en CT logs.")
    nota("Cruza esto con DNS: los que resuelven son superficie viva.")
    resultados["crtsh"] = subs


def wayback(dominio, resultados):
    """
    QUE: consulta el Wayback Machine (snapshots historicos).
    POR QUE: URLs antiguas revelan rutas, parametros y endpoints que ya no
             estan enlazados pero pueden seguir vivos.
    QUE BUSCAR: paneles admin, APIs viejas, ficheros con parametros jugosos.
    """
    banner("Wayback Machine - URLs historicas (pasivo)")
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{dominio}/*"
           f"&output=text&fl=original&collapse=urlkey&limit=200")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "recon-clase/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            urls = resp.read().decode(errors="ignore").splitlines()
    except Exception as e:  # noqa: BLE001
        nota(f"No se pudo consultar Wayback: {e}")
        resultados["wayback"] = None
        return
    for u in urls[:200]:
        print(f"    {u}")
    nota(f"{len(urls)} URLs historicas (limitado a 200). Busca rutas raras.")
    resultados["wayback"] = urls[:200]


def google_dorks(dominio, resultados):
    """
    QUE: genera una lista de Google Dorks lista para pegar en el navegador.
    POR QUE: el dorking es pasivo (consultas al buscador, no al objetivo) y
             encuentra ficheros, paneles e indexados expuestos.
    """
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


# --------------------------------------------------------------------------
# FASE ACTIVA (ruidosa: solo con autorizacion)
# --------------------------------------------------------------------------
def resolver_subs(dominio, subs):
    """Resuelve una lista de subdominios y devuelve los vivos (A record)."""
    vivos = {}
    for s in subs:
        try:
            ip = socket.gethostbyname(s)
            vivos[s] = ip
        except (socket.gaierror, UnicodeError):
            continue
    return vivos


def fase_activa_dns(dominio, resultados):
    """
    QUE: enumeracion activa de subdominios (dnsrecon / amass si estan).
    POR QUE: consulta directa a DNS -> encuentra registros no vistos en CT.
    QUE BUSCAR: subdominios que resuelven = hosts reales a escanear.
    """
    banner("Enumeracion DNS activa (RUIDOSO)")
    if tiene("dnsrecon"):
        nota("Ejecutando dnsrecon -t std ...")
        ok, out = run_cmd(["dnsrecon", "-d", dominio, "-t", "std"], timeout=120)
        print(out[:4000])
    else:
        nota("dnsrecon no instalado; omitiendo.")

    # Resolvemos los subdominios que crt.sh nos dio (si hay).
    subs = resultados.get("crtsh") or []
    if subs:
        nota(f"Resolviendo {len(subs)} subdominios de crt.sh para ver cuales viven...")
        vivos = resolver_subs(dominio, subs)
        for s, ip in sorted(vivos.items()):
            print(f"    {s:45s} -> {ip}")
        nota(f"{len(vivos)} subdominios vivos. Estos son objetivos reales.")
        resultados["subdominios_vivos"] = vivos


def fase_activa_whatweb(dominio, resultados):
    """
    QUE: fingerprinting de tecnologias con whatweb.
    POR QUE: identifica CMS, servidor, lenguajes, WAF -> orienta vulns.
    QUE BUSCAR: versiones concretas (WordPress x.y, nginx x.y) para CVEs.
    """
    banner("Fingerprinting de tecnologias (whatweb) (RUIDOSO)")
    if not tiene("whatweb"):
        nota("whatweb no instalado; omitiendo.")
        return
    for esquema in ("https://", "http://"):
        ok, out = run_cmd(["whatweb", "-a", "3", f"{esquema}{dominio}"], timeout=60)
        if out:
            print(out)
    nota("Apunta CMS y versiones; cruzalo con exploit-db / CVEs.")
    resultados["whatweb"] = True


def fase_activa_nmap(dominio, resultados, full=False):
    """
    QUE: escaneo de puertos/servicios con nmap.
    POR QUE: descubre servicios expuestos; -sV detecta versiones.
    METODOLOGIA (tu CLAUDE.md): dual -> top-ports rapido + -p- completo.
    QUE BUSCAR: puertos no-web (SMB 445, RDP 3389, WSUS 8530/8531...).
    """
    banner("Escaneo de puertos nmap (MUY RUIDOSO)")
    if not tiene("nmap"):
        nota("nmap no instalado; omitiendo.")
        return
    outbase = resultados["_outdir"] + "/nmap_top"
    nota("Escaneo rapido top-ports con -sV -oA (guarda todos los formatos).")
    ok, out = run_cmd(
        ["nmap", "-sV", "-T4", "--top-ports", "1000", "-oA", outbase, dominio],
        timeout=300,
    )
    print(out)
    nota("Para el -p- completo, lanza en OTRA terminal (no bloquear este script):")
    print(f"      nmap -p- -sV -T4 -oA {resultados['_outdir']}/nmap_full {dominio}")
    nota("Nunca te fies solo de top-ports: WSUS 8530/8531 se pierde.")
    resultados["nmap_top"] = out


def ficheros_conocidos(dominio, resultados):
    """
    QUE: descarga robots.txt y sitemap.xml.
    POR QUE: listan rutas que el dueno (a veces) no quiere indexadas ->
             paneles, APIs, directorios interesantes.
    QUE BUSCAR: Disallow con rutas sensibles; sitemap con URLs ocultas.
    """
    banner("Ficheros conocidos: robots.txt / sitemap.xml (semi-activo)")
    hallados = {}
    for fich in ("robots.txt", "sitemap.xml"):
        for esquema in ("https://", "http://"):
            url = f"{esquema}{dominio}/{fich}"
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "recon-clase/1.0"})
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                    cuerpo = resp.read().decode(errors="ignore")
                    print(f"\n[{url}] (HTTP {resp.status})")
                    print("    " + cuerpo[:1500].replace("\n", "\n    "))
                    hallados[fich] = cuerpo[:5000]
                    break
            except Exception:  # noqa: BLE001
                continue
        if fich not in hallados:
            nota(f"{fich} no accesible.")
    nota("Las lineas 'Disallow:' de robots.txt son pistas de rutas sensibles.")
    resultados["ficheros_conocidos"] = hallados


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(
        description="Enumeracion OSINT pasiva/activa (ejercicio CPTS).")
    p.add_argument("dominio", help="dominio objetivo (p.ej. example.com)")
    p.add_argument("--activo", action="store_true",
                   help="ejecuta tambien la fase activa (RUIDOSA, requiere permiso)")
    p.add_argument("--nmap", action="store_true",
                   help="incluye escaneo nmap en la fase activa")
    p.add_argument("-o", "--outdir", default="recon_out",
                   help="directorio de salida (por defecto: recon_out)")
    args = p.parse_args()

    dominio = args.dominio.strip().lower().replace("https://", "").replace("http://", "").strip("/")

    os.makedirs(args.outdir, exist_ok=True)
    resultados = {
        "_dominio": dominio,
        "_fecha": datetime.now(timezone.utc).isoformat(),
        "_outdir": args.outdir,
    }

    print(f"\n### Recon de {dominio} ###")
    print(f"### {resultados['_fecha']} ###")
    if args.activo:
        print("### MODO ACTIVO: trafico directo al objetivo. Asegura autorizacion. ###")

    # -- Pasivo --
    whois_lookup(dominio, resultados)
    dns_registros(dominio, resultados)
    crtsh(dominio, resultados)
    wayback(dominio, resultados)
    google_dorks(dominio, resultados)

    # -- Activo --
    if args.activo:
        fase_activa_dns(dominio, resultados)
        fase_activa_whatweb(dominio, resultados)
        ficheros_conocidos(dominio, resultados)
        if args.nmap:
            fase_activa_nmap(dominio, resultados)

    # -- Guardar JSON --
    salida_json = os.path.join(args.outdir, f"{dominio}_recon.json")
    # Quitamos la clave interna _outdir del dump para limpieza.
    dump = {k: v for k, v in resultados.items() if k != "_outdir"}
    with open(salida_json, "w") as f:
        json.dump(dump, f, indent=2, ensure_ascii=False)
    banner("Resumen")
    nota(f"Resultados guardados en: {salida_json}")
    nota("Recon no es lineal: un subdominio tardio puede abrir una fase nueva.")


if __name__ == "__main__":
    main()
