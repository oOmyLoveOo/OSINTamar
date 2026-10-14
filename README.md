# OSINT 1 — Automatización de recon pasivo/activo, cabeceras y User-Agent

Entregable de clase (CPTS). Tres scripts en Python + esta documentación.

> **Uso ético:** la parte *activa* (`--activo`, nmap, whatweb) genera tráfico
> directo contra el objetivo y es ruidosa. Lánzala solo contra dominios
> **propios** o con **autorización explícita** (p. ej. activos dentro del
> alcance de un programa de YesWeHack / bug bounty). La parte pasiva no toca
> al objetivo (consulta bases de datos de terceros).

## Dependencias

```bash
pip install requests        # opcional; hay fallback con urllib si no está
# Binarios usados por la fase activa (ya en Kali): whois, dig/host, dnsrecon,
# whatweb, nmap
```

---

## 1) `recon.py` — Enumeración pasiva y activa

```bash
python3 recon.py example.com                 # solo pasivo
python3 recon.py example.com --activo         # pasivo + activo (ruidoso)
python3 recon.py example.com --activo --nmap  # + escaneo de puertos
python3 recon.py example.com -o salida/       # directorio de salida
```

| Fase | Módulo | Qué hace |
|------|--------|----------|
| Pasivo | WHOIS | Registrador, fechas, nameservers |
| Pasivo | DNS | Registros A/AAAA/MX/NS/TXT/SOA/CNAME |
| Pasivo | crt.sh | Subdominios vía Certificate Transparency |
| Pasivo | Wayback | URLs históricas archivadas |
| Pasivo | Google Dorks | Lista de dorks lista para pegar |
| Activo | dnsrecon + resolución | Subdominios que **viven** |
| Activo | whatweb | Fingerprinting de tecnologías |
| Activo | robots.txt / sitemap.xml | Rutas conocidas |
| Activo | nmap | Puertos/servicios (dual top-ports + aviso `-p-`) |

Cada módulo imprime **qué es → por qué importa → qué buscar** en el output, y
guarda todo en `<dominio>_recon.json`.

## 2) `security_headers.py` — Auditoría de cabeceras de seguridad

```bash
python3 security_headers.py https://example.com
python3 security_headers.py example.com otro.com -o cabeceras.json
```

Hace una petición GET normal (como un navegador) y evalúa 7 cabeceras de
seguridad (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy, COOP). Por cada **ausente** explica el riesgo y el valor
sano, detecta cabeceras que **filtran** el stack (`Server`, `X-Powered-By`) y da
una puntuación `X/7`.

## 3) `ua_server.py` — Servidor HTTP que captura y analiza User-Agents

```bash
python3 ua_server.py --puerto 8080
# luego visita http://TU_IP:8080/ desde distintos clientes
```

Levanta un servidor mínimo que, por cada petición, registra IP, método, ruta,
cabeceras y **User-Agent**, y lo **interpreta en vivo** (SO, navegador,
bot/herramienta). Guarda un log JSON-lines (`user_agents.log`) fácil de parsear.

---

## Investigación: ¿qué se puede hacer con el User-Agent?

El `User-Agent` es una cabecera HTTP que el **cliente** envía identificando su
software (navegador, versión, motor, SO, a veces dispositivo). Usos a grandes
rasgos:

**Desde el servidor / defensa**
- **Fingerprinting de cliente:** deducir navegador, versión y SO → estimar la
  superficie de ataque del cliente y servir compatibilidad.
- **Detección de bots y scanners:** UAs como `sqlmap`, `nikto`, `nmap`,
  `python-requests`, `curl`, `masscan` delatan automatización → base para
  rate-limit, bloqueo o WAF.
- **Analítica:** estadísticas de navegadores/dispositivos de los visitantes.
- **Content negotiation:** servir versión móvil vs escritorio.

**Desde el atacante / ofensiva**
- **Suplantación (spoofing):** el UA lo controla el cliente, así que es
  trivial falsificarlo (`curl -A "..."`, extensiones) para evadir filtros
  básicos o hacerse pasar por Googlebot.
- **Cloaking / evasión:** cambiar el UA para saltar reglas que solo filtran por
  cadena de UA.
- **Vector de inyección:** si el servidor registra o muestra el UA sin
  sanear, puede dar lugar a **XSS almacenado** (en paneles de logs/analítica),
  **SQLi** o **log injection** → el UA es un campo de entrada controlado por el
  atacante, nunca de confianza.
- **OSINT inverso:** un UA muy específico/raro puede desanonimizar o
  identificar una herramienta concreta del lado cliente.

**Conclusión clave:** el User-Agent es una **señal útil pero NO un control de
seguridad** — es falsificable y, a la vez, es entrada no confiable que debe
sanearse antes de almacenar o mostrar.

---

## Flujo sugerido para el informe de perímetro (YesWeHack)

1. Elige un activo **en alcance** del programa.
2. `python3 recon.py <dominio>` (pasivo) → mapa de infra y subdominios.
3. Resuelve subdominios vivos y audita cabeceras:
   `python3 security_headers.py <subdominios...> -o cabeceras.json`.
4. Documenta: infra (WHOIS/DNS), subdominios, tecnologías (whatweb), cabeceras
   ausentes (riesgo) y hallazgos de dorks. El recon es **no lineal**: un
   subdominio tardío suele reabrir fases anteriores.
