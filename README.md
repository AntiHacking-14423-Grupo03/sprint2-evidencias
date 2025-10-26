# Sprint 2 – Evaluación de Seguridad Web

**Autor:** Bruce Andres Cipriano Chumbes
**Curso:** Anti-Hacking y Nuevas Tendencias de Seguridad – UPC
**Entorno:** Kali Linux (VirtualBox)
**Fecha:** Octubre 2025

---

> Repositorio: evidencia y scripts del Sprint 2.
> Contenido: comandos ejecutados, outputs relevantes y reportes guardados en `~/evidencias/sprint2/`.

---

## Índice

- [Sprint 2 – Evaluación de Seguridad Web](#sprint-2--evaluación-de-seguridad-web)
  - [Índice](#índice)
  - [0) Preparar entorno](#0-preparar-entorno)
  - [1) Evidencia inicial](#1-evidencia-inicial)
  - [2) Estructura de targets](#2-estructura-de-targets)
  - [3) Reconocimiento Pasivo (OSINT)](#3-reconocimiento-pasivo-osint)
    - [3.1) Superficie expuesta por dominio (osint\_table.csv)](#31-superficie-expuesta-por-dominio-osint_tablecsv)
  - [4) Escaneo de red (Nmap) — perfil conservador](#4-escaneo-de-red-nmap--perfil-conservador)
  - [5) Enumeración Web (WhatWeb / Gobuster / Nikto)](#5-enumeración-web-whatweb--gobuster--nikto)
  - [6) DAST Ligero — OWASP ZAP (baseline / passive)](#6-dast-ligero--owasp-zap-baseline--passive)
  - [7) Mapeo automatizado — Nessus (opcional, si tienes licencia)](#7-mapeo-automatizado--nessus-opcional-si-tienes-licencia)
  - [8) Consolidación de Hallazgos — `3.2.3_results.csv`](#8-consolidación-de-hallazgos--323_resultscsv)
    - [8.1) Matriz técnica de hallazgos priorizados](#81-matriz-técnica-de-hallazgos-priorizados)
    - [Guía rápida para llenar filas](#guía-rápida-para-llenar-filas)
  - [9) Capturas y organización final de evidencias](#9-capturas-y-organización-final-de-evidencias)
  - [10) Empaquetado final](#10-empaquetado-final)
  - [11) Subir documentación al repositorio (GitHub)](#11-subir-documentación-al-repositorio-github)

---

## 0) Preparar entorno

Ejecutado como usuario normal (`kali`). Comandos usados para preparar el workspace:

```bash
WORKDIR=~/evidencias/sprint2
mkdir -p "$WORKDIR"/targets
mkdir -p ~/evidencias/screenshots
sudo chown -R $USER:$USER ~/evidencias || true

sudo apt update --allow-releaseinfo-change || sudo apt update --fix-missing
sudo apt install -y nmap whatweb gobuster nikto theharvester ffuf dos2unix zip jq
```

Archivo de evidencia básico: `~/evidencias/prep_evidence.txt` (hostname, ip, kernel).

![Captura 1 — Entorno de trabajo](./evidencias/Screenshot/captura1.png)

---

## 1) Evidencia inicial

```bash
echo "=== prep evidence: $(date) ===" > ~/evidencias/prep_evidence.txt
hostname >> ~/evidencias/prep_evidence.txt
ip a >> ~/evidencias/prep_evidence.txt
uname -a >> ~/evidencias/prep_evidence.txt
sed -n '1,200p' ~/evidencias/prep_evidence.txt
```

Capturas (entorno, interfaces de red, uname, etc.) en `~/evidencias/screenshots/`.

![Captura 2 — Entorno de trabajo](./evidencias/Screenshot/captura2.png)

---

## 2) Estructura de targets

```bash
targets=(puntodepartidauc triphasik raymi virtuolabs)
mkdir -p ~/evidencias/sprint2/targets
for t in "${targets[@]}"; do mkdir -p ~/evidencias/sprint2/targets/$t; done
```

Mapeo (nombre → URL objetivo):

* `puntodepartidauc` → `https://www.puntodepartidauc.com`
* `triphasik` → `https://app.triphasikperformance.com`
* `raymi` → `https://raymifest.com`
* `virtuolabs` → `https://www.virtuolabs.dev`

![Captura 3 — Entorno de trabajo](./evidencias/Screenshot/captura3.png)

---

## 3) Reconocimiento Pasivo (OSINT)

* Recolección OSINT con `theHarvester` (google, urlscan) sobre dominios y subdominios.
* Identificación de endpoints web críticos (por ejemplo `/login`, `/api`, `/api/auth`, `/admin`).
* Recolección de artefactos públicos relacionados (por ejemplo PDFs asociados a Triphasik).
* Extracción de posibles datos sensibles (correos, paths internos expuestos, endpoints API públicos).

```bash
theHarvester -d puntodepartidauc.com -b google -l 200 > ~/evidencias/sprint2/targets/puntodepartidauc/theharvester_google.txt 2>&1
theHarvester -d puntodepartidauc.com -b urlscan -l 200 > ~/evidencias/sprint2/targets/puntodepartidauc/theharvester_urlscan.txt 2>&1
# (repetido para triphasikperformance.com, raymifest.com, virtuolabs.dev)
```
Extraer correos y dominios (ejemplo):

```bash
grep -E -o "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}" ~/evidencias/sprint2/targets/*/theharvester_*.txt | sort -u > ~/evidencias/sprint2/found_emails.txt
grep -Eo "([a-z0-9\-]+\.)+[a-z]{2,}" ~/evidencias/sprint2/targets/*/theharvester_*.txt | sort -u > ~/evidencias/sprint2/found_domains.txt
```

Plantilla CSV OSINT:

```bash
cat > ~/evidencias/sprint2/osint_table.csv <<'CSV'
dominio,subdominio,email,endpoint_api,pdf_file,pdf_author,pdf_version,source,timestamp,evidence_file
CSV
```
Se registraron resultados consolidados en `osint_table.csv`.

![Captura 4 — Entorno de trabajo](./evidencias/Screenshot/captura4.png)

### 3.1) Superficie expuesta por dominio (osint_table.csv)

Esta tabla resume, por dominio/subdominio, qué endpoints sensibles están públicos, de dónde salió la evidencia y dónde se guardó:

| Dominio                      | Subdominio                                                        | Endpoint crítico / API                 | Fuente / Técnica usada                          | Evidencia técnica                                                                     |
| ---------------------------- | ----------------------------------------------------------------- | -------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------- |
| puntodepartidauc.com         | [www.puntodepartidauc.com](http://www.puntodepartidauc.com)       | `/login`, `/api`                       | TheHarvester (urlscan, google)                  | `theharvester_google.txt`, `theharvester_urlscan.txt`                                 |
| app.triphasikperformance.com | app.triphasikperformance.com                                      | `/login`, `/api/auth`                  | ZAP baseline / TheHarvester                     | `Triphasik_amjorh.pdf`, `2025-10-25-ZAP-Report-app.triphasikperformance.com.html`     |
| raymifest.com                | [www.raymifest.com](http://www.raymifest.com) / api.raymifest.com | `/api/auth`, `/api/v1/events`          | WhatWeb / Nikto                                 | `whatweb.txt`, `nikto.txt`                                                            |
| virtuolabs.dev               | [www.virtuolabs.dev](http://www.virtuolabs.dev)                   | `/api/login`                           | TheHarvester / Nmap / Nikto                     | `nmap_full_tcp_lab.txt`, `nikto.txt`                                                  |
| triphasikperformance.com     | app.triphasikperformance.com                                      | `/api/auth`, Swagger/OpenAPI potencial | TheHarvester / ZAP                              | `theharvester_urlscan.txt`, `2025-10-25-ZAP-Report-app.triphasikperformance.com.html` |
| puntodepartidauc.com         | static.puntodepartidauc.com                                       | `/api`                                 | WhatWeb / Nmap (fingerprinting de servicio web) | `whatweb.txt`, `nmap_topports.txt`                                                    |
| raymifest.com                | api.raymifest.com (lógico)                                        | `/api/v1/events`                       | Nikto / WhatWeb                                 | `nikto.txt`, `whatweb.txt`                                                            |
| virtuolabs.dev               | admin.virtuolabs.dev (lógico)                                     | `/admin` (panel admin expuesto)        | Nmap / WhatWeb                                  | `nmap_sV_scripts.txt`, `whatweb.txt`                                                  |

> Esta tabla demuestra el paso clave del Sprint 2: ya no sólo se mapean dominios como en el Sprint 1, ahora se identifican **puntos de entrada concretos** (login, admin panel, API) que serán objetivo de pruebas de explotación controlada en el Sprint 3.

---

## 4) Escaneo de red (Nmap) — perfil conservador

```bash
TARGET_URL=app.triphasikperformance.com
OUTDIR=~/evidencias/sprint2/targets/triphasik
mkdir -p "$OUTDIR"

nmap -Pn -sS -p 80,443,22,21,25,53,3306 -T2 -oN "$OUTDIR/nmap_topports.txt" "$TARGET_URL"
sudo nmap -Pn -sV -sC -p 80,443 -T2 -oN "$OUTDIR/nmap_sV_scripts.txt" "$TARGET_URL"
# (opcional, laboratorio) nmap_full_tcp_lab.txt
```

Evidencias guardadas:

* `nmap_topports.txt`
* `nmap_sV_scripts.txt`
* `nmap_full_tcp_lab.txt`

![Captura 5 — Entorno de trabajo](./evidencias/Screenshot/captura5.png)

---

## 5) Enumeración Web (WhatWeb / Gobuster / Nikto)

```bash
whatweb -v -a 3 <target> > whatweb.txt
gobuster dir -u <target> -w common.txt -o gobuster.txt
nikto -h <target> -output nikto.txt
```

Evidencias generadas:

* `whatweb.txt` (tecnologías y versiones detectadas)
* `gobuster.txt` (paneles tipo `/admin`, `/backup`, `/wp-content`, etc.)
* `nikto.txt` (cabeceras de seguridad ausentes, banners por defecto)

![Captura 6 — Enumeración de rutas, tecnologías y cabeceras](./evidencias/Screenshot/captura6.png)

---

## 6) DAST Ligero — OWASP ZAP (baseline / passive)

Modo: sólo passive scan (sin fuzzing agresivo).

1. Abrir ZAP
2. Quick Start → Automated Scan
3. Seleccionar `Passive Scan only`
4. Exportar reporte HTML

El resultado se guardó por target en
`~/evidencias/sprint2/targets/<target>/ZAP_report.html`.

![Captura 7 — OWASP ZAP baseline](./evidencias/Screenshot/captura7.png)

![Captura 8 — OWASP ZAP alerts](./evidencias/Screenshot/captura8.png)

![Captura 9 — Cookies inseguras / Headers faltantes](./evidencias/Screenshot/captura9.png)

![Captura 10 — Export del reporte ZAP](./evidencias/Screenshot/captura10.png)

---

## 7) Mapeo automatizado — Nessus (opcional, si tienes licencia)

Pasos:

1. `sudo systemctl start nessusd`
2. Abrir `https://localhost:8834/`
3. Crear `Basic Network Scan` o `Web Application Scan`
4. Exportar reporte PDF por target:

   * `~/evidencias/sprint2/targets/<target>/<target>_Nessus_Report.pdf`

![Captura 11 — Nessus ejecutándose](./evidencias/Screenshot/captura11.png)

![Captura 12 — Export de hallazgos críticos en Nessus](./evidencias/Screenshot/captura12.png)

---

## 8) Consolidación de Hallazgos — `3.2.3_results.csv`

Se consolidaron todos los hallazgos técnicos (Nmap, WhatWeb, Nikto, Gobuster, ZAP, Nessus, theHarvester) dentro de una sola matriz CSV con:

* ID interno
* Descripción técnica
* Severidad estimada (CVSS v3.1)
* Impacto potencial para el negocio
* Acción recomendada inmediata
* Evidencia (archivo / captura)

Los hallazgos críticos y altos de esta matriz son los candidatos a pruebas de explotación controlada en el Sprint 3.

### 8.1) Matriz técnica de hallazgos priorizados

| ID      | Vulnerabilidad                                                                 | Descripción técnica                                                                                                                                                                                 | Herramienta usada / Evidencia                                                 | Severidad (CVSS estimado) | Impacto potencial                                                                                        | Recomendación inmediata                                                                                                                                           |
| ------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PDP-001 | DBs accesibles desde Internet (MySQL/Postgres)                                 | Nmap detectó puertos 3306 (MySQL/MariaDB) y 5432 (Postgres) accesibles en host público; las bases de datos serían alcanzables remotamente sin segmentación dedicada ni filtrado por IP.             | `nmap_full_tcp_lab.txt`, `nmap_topports.txt`                                  | 8.0 (Alta / Crítica)      | Exfiltración o manipulación directa de datos productivos.                                                | Restringir acceso DB vía firewall (solo IP internas/VPN), cerrar puertos al exterior, obligar autenticación fuerte y monitorear intentos externos.                |
| PDP-002 | Falta de cabeceras de seguridad HTTP (HSTS / X-Frame-Options / X-Content-Type) | Nikto y WhatWeb evidenciaron ausencia de cabeceras críticas; sin HSTS no se fuerza HTTPS, sin X-Frame-Options es posible clickjacking, y sin X-Content-Type-Options hay riesgo de content sniffing. | `nikto.txt`, `whatweb.txt`                                                    | 6.1 (Media)               | Clickjacking, MITM downgrade, inyección de contenido.                                                    | Agregar `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, y CSP mínima. Forzar siempre HTTPS.                                             |
| PDP-003 | Página por defecto / host sin app desplegada                                   | Respuesta HTTP con página por defecto o banner del proveedor (por ejemplo `defaultwebpage.cgi`), revelando hosting y paths internos.                                                                | `nmap_sV_scripts.txt`, `whatweb.txt`                                          | 5.0 (Media)               | Fuga de metadatos de infraestructura, facilita fingerprinting automatizado.                              | Eliminar/ocultar páginas por defecto, configurar correctamente el virtual host y despublicar entornos “en construcción”.                                          |
| TRP-001 | Missing security headers & insecure TLS (Triphasik)                            | ZAP + Nikto detectaron ausencia de HSTS y cabeceras de endurecimiento. También se observaron cookies sin `Secure`, `HttpOnly` ni `SameSite` en endpoints de login/API.                              | `2025-10-25-ZAP-Report-app.triphasikperformance.com.html`, `nikto.txt`        | 6.5 (Media-Alta)          | Riesgo de robo/fijación de sesión; tráfico no forzado a HTTPS; posible clickjacking.                     | Configurar HTTPS estricto, habilitar HSTS, marcar cookies con `Secure; HttpOnly; SameSite=Strict`, y definir CSP adecuada (restricción de scripts y framing).     |
| TRP-002 | Endpoints administrativos sin protección (/admin /login /backup)               | Gobuster y WhatWeb revelaron rutas administrativas potencialmente accesibles desde Internet sin controles adicionales (sin restricción de IP ni MFA).                                               | `gobuster.txt`, `whatweb.txt`                                                 | 6.8 (Media-Alta)          | Fuerza bruta de credenciales, acceso a panel de gestión, descarga de respaldos.                          | Proteger `/admin` con allowlist de IP/VPN, habilitar MFA en panel de administración, y sacar respaldos (`.zip`, `.sql`) fuera del webroot.                        |
| RAY-001 | Servidor con defaultwebpage / hosting placeholder                              | El host responde con página por defecto (ej. cPanel/Caddy placeholder), confirmando despliegue incompleto y filtrando información sobre el proveedor.                                               | `nmap_sV_scripts.txt`, `whatweb.txt`                                          | 5.5 (Media)               | Filtración de información útil para reconocimiento dirigido (fingerprinting de proveedor, stack, rutas). | Retirar páginas por defecto, apuntar cada virtual host a su app real y bloquear entornos de staging para que no sean públicos.                                    |
| VRT-001 | Servicios administrativos expuestos (SSH 22 abierto públicamente)              | Nmap mostró SSH (22/tcp) accesible desde Internet en hosts como `virtuolabs.dev`. Si hay login por contraseña, es vulnerable a fuerza bruta remota.                                                 | `nmap_topports.txt`, `nmap_sV_scripts.txt`                                    | 7.2 (Alta)                | Acceso inicial al sistema mediante password guessing → escalada de privilegios → control del host.       | Restringir SSH con firewall/ACL por IP, deshabilitar autenticación por contraseña, usar solo llaves y (si es posible) MFA o port knocking.                        |
| VRT-002 | Configuración TLS débil / certificados no endurecidos                          | Respuestas HTTPS con configuraciones TLS potencialmente débiles (por ejemplo suites antiguas o cadena de certificado inconsistente), lo que abre la puerta a downgrade/MITM.                        | `theharvester_urlscan.txt`, `curl -I`, resultados de `sslscan` (revisión TLS) | 6.5 (Media-Alta)          | Intercepción o modificación del tráfico cifrado, robo de credenciales/tokens.                            | Forzar TLS ≥ 1.2, endurecer suites criptográficas modernas (AES-GCM / CHACHA20-POLY1305), revisar cadena de certificados y habilitar `Strict-Transport-Security`. |

---

### Guía rápida para llenar filas

* **ID**: identificador interno del hallazgo (ej. `TRP-001`).
* **Vulnerabilidad**: título corto que un gerente entienda.
* **Descripción técnica**: lo que vimos exactamente en las herramientas.
* **Herramienta usada / Evidencia**: archivo `.txt`, `.html`, `.pdf`, screenshot.
* **Severidad (CVSS estimado)**: aproximación usando CVSS v3.1.
* **Impacto potencial**: qué tan grave sería en producción.
* **Recomendación inmediata**: acción concreta que el cliente debería tomar YA.

---

## 9) Capturas y organización final de evidencias

Listado de evidencia generada por target:

```bash
find ~/evidencias/sprint2 -maxdepth 3 -type f -printf "%P\n" | sed -n '1,200p'
```

Asegurar permisos:

```bash
sudo chown -R $USER:$USER ~/evidencias/sprint2
```

Capturas almacenadas en `~/evidencias/screenshots/`:

* `captura1.png` (preparación de entorno, hostname, IP)
* `captura2.png` (estado inicial de la VM Kali / red)
* `captura3.png` (estructura de carpetas de evidencias)
* `captura4.png` (theHarvester / OSINT)
* `captura5.png` (escaneo Nmap / puertos críticos)
* `captura6.png` (WhatWeb / Gobuster / Nikto)
* `captura7.png`, `captura8.png`, `captura9.png`, `captura10.png` (ZAP)
* `captura11.png`, `captura12.png` (Nessus)

Estas capturas son la evidencia visual directa de la ejecución de las herramientas indicadas arriba.

---

## 10) Empaquetado final

```bash
cd ~
zip -r ~/Desktop/sprint2_evidences_$(date +%Y%m%d_%H%M).zip evidencias/sprint2
ls -lah ~/Desktop | grep sprint2_evidences_
```

Entregable final:
`~/Desktop/sprint2_evidences_<timestamp>.zip`

---

## 11) Subir documentación al repositorio (GitHub)

```bash
cd ~/Documentos/sprint2  # o ruta correspondiente al repo
nano README.md          # pegar este contenido
git add README.md
git commit -m "Sprint 2 - Documentación de pruebas y evidencias (Bruce Cipriano)"
git push origin main
```

---
