#!/usr/bin/env python3
"""
security_headers.py - Analiza las cabeceras de seguridad HTTP de un sitio.

QUE: hace una peticion a una URL y evalua las cabeceras de seguridad de la
     respuesta.
POR QUE: cabeceras ausentes/mal configuradas (HSTS, CSP, X-Frame-Options...)
         indican debilidades (clickjacking, sniffing, falta de TLS forzado) y
         son hallazgos tipicos de un informe de perimetro.
COMO: python3 security_headers.py https://example.com
QUE BUSCAR: cabeceras en rojo (FALTA) y cabeceras info que filtran stack
            (Server, X-Powered-By).

No ataca: solo hace una peticion GET normal, como un navegador.
"""

import argparse
import json
import ssl
import sys
import urllib.request
import urllib.error

try:
    import requests
except ImportError:
    requests = None


# Cabeceras de seguridad esperadas: nombre -> (por que importa, que valor sano).
ESPERADAS = {
    "strict-transport-security": (
        "Fuerza HTTPS; sin ella, posible downgrade a HTTP (MITM).",
        "max-age>=15768000; includeSubDomains"),
    "content-security-policy": (
        "Mitiga XSS e inyeccion de recursos. Su ausencia es XSS mas facil.",
        "default-src 'self' (restrictiva)"),
    "x-frame-options": (
        "Previene clickjacking (embeber el sitio en un iframe).",
        "DENY o SAMEORIGIN"),
    "x-content-type-options": (
        "Impide MIME-sniffing del navegador.",
        "nosniff"),
    "referrer-policy": (
        "Controla cuanta URL se filtra en el header Referer.",
        "no-referrer o strict-origin-when-cross-origin"),
    "permissions-policy": (
        "Restringe APIs del navegador (camara, micro, geoloc).",
        "deshabilitar lo no usado"),
    "cross-origin-opener-policy": (
        "Aisla el contexto de navegacion (Spectre / XS-Leaks).",
        "same-origin"),
}

# Cabeceras que FILTRAN informacion (malo que esten o que sean verbosas).
FILTRADORAS = ["server", "x-powered-by", "x-aspnet-version",
               "x-aspnetmvc-version", "via", "x-generator"]


def obtener_cabeceras(url):
    """Devuelve (status, dict_cabeceras_lower). Tolerante a errores TLS."""
    if requests:
        r = requests.get(url, timeout=20, verify=False,
                         headers={"User-Agent": "sec-headers-clase/1.0"},
                         allow_redirects=True)
        cab = {k.lower(): v for k, v in r.headers.items()}
        return r.status_code, cab, r.url
    # Fallback sin requests.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url, headers={"User-Agent": "sec-headers-clase/1.0"})
    with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
        cab = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, cab, resp.url


def analizar(url):
    print(f"\n{'='*70}\n[*] Analizando cabeceras de: {url}\n{'='*70}")
    try:
        status, cab, url_final = obtener_cabeceras(url)
    except Exception as e:  # noqa: BLE001
        print(f"[!] Error al conectar: {e}")
        return None

    print(f"[+] HTTP {status}  (URL final tras redirecciones: {url_final})\n")

    informe = {"url": url, "url_final": url_final, "status": status,
               "presentes": {}, "ausentes": [], "filtradoras": {}}

    print("--- Cabeceras de seguridad ---")
    for nombre, (porque, sano) in ESPERADAS.items():
        if nombre in cab:
            print(f"  [OK ] {nombre}: {cab[nombre]}")
            informe["presentes"][nombre] = cab[nombre]
        else:
            print(f"  [!! ] FALTA {nombre}")
            print(f"         por que: {porque}")
            print(f"         valor sano: {sano}")
            informe["ausentes"].append(nombre)

    print("\n--- Cabeceras que filtran informacion ---")
    hay_filtracion = False
    for nombre in FILTRADORAS:
        if nombre in cab:
            hay_filtracion = True
            print(f"  [info] {nombre}: {cab[nombre]}  <- revela stack/version")
            informe["filtradoras"][nombre] = cab[nombre]
    if not hay_filtracion:
        print("  (ninguna cabecera verbosa evidente)")

    # Puntuacion sencilla.
    total = len(ESPERADAS)
    ok = len(informe["presentes"])
    print(f"\n[=] Puntuacion: {ok}/{total} cabeceras de seguridad presentes.")
    if informe["ausentes"]:
        print("    Prioriza en el informe: " + ", ".join(informe["ausentes"]))
    return informe


def main():
    p = argparse.ArgumentParser(
        description="Analiza cabeceras de seguridad HTTP de una o varias URLs.")
    p.add_argument("urls", nargs="+", help="URL(s), p.ej. https://example.com")
    p.add_argument("-o", "--out", help="guardar informe JSON en este fichero")
    args = p.parse_args()

    # Silenciamos el warning de verify=False si usamos requests.
    if requests:
        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:  # noqa: BLE001
            pass

    informes = []
    for url in args.urls:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        inf = analizar(url)
        if inf:
            informes.append(inf)

    if args.out:
        with open(args.out, "w") as f:
            json.dump(informes, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Informe guardado en {args.out}")


if __name__ == "__main__":
    main()
