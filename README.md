# OSINT 1 — Herramienta de recon pasivo/activo, cabeceras y User-Agent

Entregable de clase (CPTS). Una sola herramienta en Python (`osint.py`) con tres
subcomandos: `recon`, `headers` y `serve`.

> **Uso ético:** la fase *activa* (`--activo`, nmap, whatweb) genera tráfico
> directo contra el objetivo y es ruidosa. Lánzala solo contra dominios
> **propios** o con **autorización explícita** (p. ej. activos en el alcance de
> un programa de YesWeHack / bug bounty). La fase pasiva no toca al objetivo:
> consulta bases de datos de terceros.

## Dependencias

```bash
pip install requests   # opcional; hay fallback con urllib si no está
# Binarios de la fase activa (ya en Kali): whois, dig/host, dnsrecon, whatweb, nmap
```

## Uso

```bash
python3 osint.py -h                 # ayuda general
python3 osint.py recon   -h         # ayuda de cada subcomando

# 1) Recon de un dominio
python3 osint.py recon   example.com                  # solo pasivo
python3 osint.py recon   example.com --activo          # pasivo + activo (ruidoso)
python3 osint.py recon   example.com --activo --nmap   # + escaneo de puertos
python3 osint.py recon   example.com -o salida/        # directorio de salida

# 2) Auditoría de cabeceras de seguridad
python3 osint.py headers https://example.com
python3 osint.py headers example.com github.com -o cabeceras.json

# 3) Servidor que captura y clasifica User-Agents
python3 osint.py serve --puerto 8080
#   luego, desde otra terminal:
#   curl -A "sqlmap/1.7" http://127.0.0.1:8080/login
```

### `recon`

| Fase | Módulo | Qué hace |
|------|--------|----------|
| Pasivo | WHOIS | Registrador, fechas, nameservers |
| Pasivo | DNS | A/AAAA/MX/NS/TXT/SOA/CNAME **+ DMARC** |
| Pasivo | crt.sh | Subdominios vía Certificate Transparency (con reintento) |
| Pasivo | Wayback | URLs históricas archivadas |
| Pasivo | Google Dorks | Lista lista para pegar |
| Activo | dnsrecon + resolución | Subdominios que **viven** |
| Activo | fingerprint | whatweb + heurística (WordPress / Plesk / PHP EOL) |
| Activo | robots.txt / sitemap.xml | Rutas conocidas |
| Activo | nmap | Puertos/servicios (top-ports + aviso `-p-` y `:8443` Plesk) |

Cada módulo explica **qué es → por qué importa → qué buscar** y guarda todo en
`recon_out/<dominio>_recon.json`.

### `headers`

Hace un GET normal y evalúa 7 cabeceras de seguridad (HSTS, CSP, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP). Por cada
ausente explica el riesgo y el valor sano, detecta cabeceras que **filtran** el
stack (`Server`, `X-Powered-By`) y da una puntuación `X/7`.

### `serve`

Servidor HTTP mínimo que registra IP, método, ruta, cabeceras y **User-Agent** de
cada petición, y lo **interpreta en vivo** (SO, navegador, bot/herramienta).
Guarda un log JSON-lines (`user_agents.log`).

---

## Investigación: ¿qué se puede hacer con el User-Agent?

El `User-Agent` es una cabecera HTTP que el **cliente** envía identificando su
software (navegador, versión, motor, SO, a veces dispositivo). A grandes rasgos:

**Desde el servidor / defensa**
- **Fingerprinting de cliente:** deducir navegador, versión y SO → estimar la
  superficie de ataque del cliente y servir compatibilidad.
- **Detección de bots y scanners:** UAs como `sqlmap`, `nikto`, `nmap`,
  `python-requests`, `curl`, `masscan` delatan automatización → base para
  rate-limit, bloqueo o reglas WAF.
- **Analítica:** estadísticas de navegadores/dispositivos.
- **Content negotiation:** servir versión móvil vs escritorio.

**Desde el atacante / ofensiva**
- **Suplantación (spoofing):** el UA lo controla el cliente, así que es trivial
  falsificarlo (`curl -A "..."`) para evadir filtros básicos o hacerse pasar por
  Googlebot.
- **Cloaking / evasión:** cambiar el UA para saltar reglas que solo filtran por
  cadena de UA.
- **Vector de inyección:** si el servidor registra o muestra el UA sin sanear,
  puede dar lugar a **XSS almacenado** (paneles de logs/analítica), **SQLi** o
  **log injection** → el UA es entrada controlada por el atacante.
- **OSINT inverso:** un UA muy específico puede identificar una herramienta o
  cliente concreto.

**Conclusión clave:** el User-Agent es una **señal útil pero NO un control de
seguridad** — es falsificable y, a la vez, es entrada no confiable que debe
sanearse antes de almacenar o mostrar.

---

## Flujo sugerido para el informe de perímetro (YesWeHack)

1. Elige un activo **en alcance** del programa.
2. `python3 osint.py recon <dominio>` → mapa de infra y subdominios.
3. Audita cabeceras de los hosts vivos:
   `python3 osint.py headers <host1> <host2> -o cabeceras.json`.
4. Documenta: infra (WHOIS/DNS/DMARC), subdominios, tecnologías (WordPress/Plesk/
   PHP EOL), cabeceras ausentes y hallazgos de dorks. El recon es **no lineal**:
   un subdominio tardío suele reabrir fases anteriores.
