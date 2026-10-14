# Informe de recopilación de información del perímetro — ExpressVPN

> **Documento académico.** Elaborado como ejercicio de clase de OSINT sobre un
> **activo autorizado**: el programa público de bug bounty de ExpressVPN en
> YesWeHack (scope `*.expressvpn.com`, entre otros). El trabajo se limita a
> **recon pasivo** (consultas a bases de datos de terceros: Certificate
> Transparency, DNS, WHOIS). **No se ha escaneado ni enviado tráfico a los
> servidores del objetivo**, en cumplimiento de las reglas del programa, que
> prohíben escáneres automáticos y tráfico elevado. No se ha explotado nada.

- **Objetivo:** `expressvpn.com` y su wildcard `*.expressvpn.com`
- **Fecha:** 2026-10-14
- **Programa:** ExpressVPN — Bug Bounty Program (YesWeHack, público)
- **Herramienta:** `osint.py recon` (modo pasivo, sin `--activo`)
- **Fuentes:** crt.sh (CT logs), registros DNS del dominio raíz, WHOIS

---

## 1. Resumen ejecutivo

El perímetro de ExpressVPN está **íntegramente sobre infraestructura de AWS**
(DNS en Route 53, direcciones de borde de AWS/CloudFront) con **correo en Google
Workspace**. La enumeración pasiva vía Certificate Transparency reveló **369
subdominios** bajo `expressvpn.com`. El hallazgo más llamativo es un **patrón de
entornos de staging efímeros por Pull Request** (`staging-pr-<N>.portal/teams…`),
con **284 subdominios** de este tipo, que exponen públicamente el flujo de CI/CD.
Entre los subdominios nombrados aparecen varios de alto interés
(`internal`, `backend-restricted`, `serveradmin`, `be-okta`,
`vpn-control-plane`) y una **zona de recuperación paralela** (`*.recov.expressvpn.com`).
La postura de correo es **sólida** (`DMARC p=quarantine`), a diferencia de
objetivos peor configurados.

---

## 2. Información general (pasivo)

### WHOIS
| Campo | Valor |
|-------|-------|
| Registrador | SafeNames Ltd. |
| Alta | 2008-09-21 |
| Expiración | 2029-09-21 |
| Estado | `clientTransferProhibited`, `serverDeleteProhibited`… (bloqueos de protección activados) |
| Nameservers | `ns-*.awsdns-*` → **Amazon Route 53** |
| DNSSEC | unsigned |

### DNS del dominio raíz
| Registro | Valor | Observación |
|----------|-------|-------------|
| A | `65.8.202.65/84/102/103` | Rango de **AWS** (borde/CloudFront) |
| NS | `ns-*.awsdns-*` (.org/.net/.com/.co.uk) | Route 53 |
| SOA | `awsdns-hostmaster.amazon.com` | AWS |
| MX | `aspmx.l.google.com`… | **Google Workspace** |
| DMARC | `v=DMARC1; p=quarantine; rua=…postmarkapp.com` | **Buena postura** (cuarentena, no `none`); informes vía Postmark |

### Proveedores SaaS detectados (por TXT)
- **Atlassian** (`atlassian-domain-verification=…`) → Jira/Confluence.
- **Ahrefs** (`ahrefs-site-verification…`) → SEO.
- **Google** (`google-site-verification…`).
- Dos tokens opacos adicionales (verificaciones de terceros).

---

## 3. Superficie: subdominios (Certificate Transparency)

**369 subdominios** únicos bajo `expressvpn.com` observados en certificados.
Se agrupan así:

### 3.1 Entornos de staging efímeros (284)
Patrón `staging-pr-<número>.portal.expressvpn.com` y
`staging-pr-<número>.teams.expressvpn.com`. Son **despliegues de previsualización
por Pull Request** generados automáticamente por el pipeline de CI/CD. Que
aparezcan en CT logs:
- **Revela el flujo de desarrollo** (numeración de PRs, componentes `portal` y
  `teams`, histórico de ramas).
- Es **superficie de ataque relevante** para un investigador: los entornos de
  preproducción suelen estar menos endurecidos que producción y, al estar bajo
  `*.expressvpn.com`, entran en el alcance del programa. *(No verificado en este
  trabajo: solo inventario pasivo.)*

### 3.2 Subdominios nombrados de interés (muestra de los 85 restantes)

| Subdominio | Interés |
|------------|---------|
| `internal.expressvpn.com` | Nombre sugiere uso interno expuesto |
| `backend-restricted.expressvpn.com` | Backend "restringido" accesible por DNS |
| `serveradmin.expressvpn.com` | Posible administración de servidores |
| `be-okta.expressvpn.com` | Integración con **Okta** (SSO) |
| `vpn-control-plane.expressvpn.com` | Plano de control del servicio VPN |
| `auth.expressvpn.com`, `portal.`, `teams.` | Autenticación y portales de cliente/empresa |
| `payments.`, `billing.`, `checkout.`, `store.` | **Flujo de pago** (alto valor) |
| `api.`, `apis.`, `backend.`, `frontend.` | Capa de API/servicios |
| `repo.`, `beta.repo.`, `releasemaster.`, `updates.`, `desktop.updates.` | **Distribución de software/paquetes** |
| `sandbox.checkout.`, `test.checkout.`, `staging.*` | Entornos de prueba nombrados |
| `*.recov.expressvpn.com` (p. ej. `backend.recov`, `be-okta.recov`, `api.payments.recov`) | **Zona de recuperación/DR paralela** que duplica servicios clave |

### 3.3 Observación: zona `recov` (disaster recovery)
Existe un conjunto espejo `*.recov.expressvpn.com` que replica backend, okta,
payments, frontend, etc. Duplica la superficie de los servicios críticos; en una
evaluación real convendría comprobar si el entorno DR mantiene el mismo nivel de
endurecimiento que producción.

---

## 4. Lectura de seguridad (observaciones de perímetro)

> Observaciones derivadas solo del inventario pasivo. No son vulnerabilidades
> confirmadas; son hipótesis y zonas prioritarias que un investigador verificaría
> dentro del alcance del programa.

1. **Exposición del CI/CD por CT logs.** 284 entornos `staging-pr-*` publicados.
   Zona natural donde buscar entornos preproductivos con menos controles
   (autenticación básica ausente, datos de prueba, versiones sin parchear).
2. **Subdominios de nombre sensible** (`internal`, `backend-restricted`,
   `serveradmin`, `vpn-control-plane`). Prioritarios para comprobar si exponen
   paneles o APIs no pensados para Internet.
3. **Zona DR `recov`.** Verificar paridad de hardening con producción.
4. **Buenas prácticas presentes:** `DMARC p=quarantine`, bloqueos de transferencia
   en WHOIS e infraestructura gestionada en AWS/Route 53. La postura de correo es
   correcta (contrasta con dominios que usan `p=none`).

---

## 5. Metodología y alcance ético

- **Solo pasivo.** Fuentes: Certificate Transparency (crt.sh), DNS del dominio
  raíz y WHOIS. No se resolvieron masivamente los 369 subdominios ni se escaneó
  ningún host, respetando la regla del programa contra escáneres y tráfico alto.
- **Dentro de alcance.** `*.expressvpn.com` es un activo in-scope del programa
  público de ExpressVPN en YesWeHack. Cualquier fase de explotación requeriría
  seguir las reglas del programa (fuera del objetivo de este ejercicio).
- **Siguiente paso lógico (no ejecutado aquí):** priorizar un puñado de
  subdominios nombrados, revisar sus cabeceras de seguridad con
  `osint.py headers` (una petición por host, dentro de límites razonables) y
  documentar hallazgos concretos.
