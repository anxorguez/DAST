# DAST Framework

[![Lint](https://github.com/anxorguez/DAST/actions/workflows/lint.yml/badge.svg)](https://github.com/anxorguez/DAST/actions/workflows/lint.yml)
[![Test](https://github.com/anxorguez/DAST/actions/workflows/test.yml/badge.svg)](https://github.com/anxorguez/DAST/actions/workflows/test.yml)
[![Docker Build](https://github.com/anxorguez/DAST/actions/workflows/docker-build.yml/badge.svg)](https://github.com/anxorguez/DAST/actions/workflows/docker-build.yml)

Framework de Dynamic Application Security Testing (DAST) por línea de comandos que detecta
automáticamente ocho clases de vulnerabilidades de inyección en aplicaciones web: inyección SQL,
XSS, inyección de comandos, SSRF, XXE, deserialización insegura, path traversal y open redirect.

---

## Índice

1. [Visión general](#visión-general)
2. [Aplicación objetivo](#aplicación-objetivo)
3. [Arquitectura](#arquitectura)
4. [Clases de vulnerabilidad](#clases-de-vulnerabilidad)
5. [Requisitos](#requisitos)
6. [Inicio rápido](#inicio-rápido)
7. [Configuración](#configuración)
8. [Salida](#salida)
9. [Ejecutar los tests](#ejecutar-los-tests)
10. [CI/CD](#cicd)
11. [Seguridad](#seguridad)
12. [Contribuir](#contribuir)
13. [Licencia](#licencia)

---

## Visión general

DAST Framework es una herramienta de seguridad desarrollada en Python como Trabajo de Fin de
Máster (TFM). Realiza testing de inyección en modo black-box sobre aplicaciones web: rastrea
dinámicamente el objetivo, identifica los parámetros inyectables, envía payloads de ataque y
genera un informe de vulnerabilidades estructurado con puntuaciones CVSS 3.1.

Clases de vulnerabilidad soportadas:

| Clase | Técnicas | CVSS 3.1 |
|---|---|---|
| Inyección SQL | error-based, UNION-based, blind booleana, time-based | 9.1 / 5.9 |
| Cross-Site Scripting | reflejado, DOM-based, almacenado (segunda pasada) | 6.1 / 5.4 |
| Inyección de comandos | error-based, time-based | 9.8 |
| SSRF | in-band: metadatos cloud, delta de tamaño de respuesta | 5.3 |
| XXE | lectura de fichero vía DTD, wrappers PHP, error del parser | 8.2 |
| Deserialización insegura | objetos malformados Java / PHP / Python / .NET | 9.8 |
| Path Traversal | secuencias `../`, bypass por URL-encoding, null-byte | 7.5 |
| Open Redirect | cabecera Location, meta-refresh, redirección JS | 6.1 |

La herramienta no tiene interfaz gráfica. Toda la interacción es por línea de comandos y toda
la salida se escribe en el sistema de ficheros como HTML, JSON y SQLite.

---

## Aplicación objetivo

El framework necesita una aplicación web como objetivo de escaneo. Por defecto se distribuye con
DVWA (Damn Vulnerable Web App), que se levanta automáticamente como parte del entorno Docker
Compose.

DVWA es una aplicación PHP intencionadamente vulnerable, diseñada para practicar testing de
seguridad web. Código y documentación: https://github.com/digininja/DVWA

Credenciales por defecto de DVWA utilizadas por el framework:

| Campo    | Valor    |
|----------|----------|
| Usuario  | admin    |
| Password | password |

El nivel de seguridad lo fija en `low` el script `start.sh` para garantizar que todas las clases
de vulnerabilidad sean detectables.

Para escanear otra aplicación, define `TARGET_URL` en tu fichero `.env` antes de ejecutar.

### Topología de servicios

El entorno de Compose expone tres objetivos equivalentes en contenido pero distintos en
exposición, además del propio escáner:

| Servicio      | Alias interno  | Puerto host | Propósito                                |
|---------------|----------------|-------------|------------------------------------------|
| dvwa-origin   | dvwa-origin    | 8080        | Objetivo vulnerable (sin filtrado)       |
| dvwa-waf      | dvwa           | 8088        | DVWA + ModSecurity v2 + OWASP CRS PL=1   |
| cf-sim        | dvwa-cf        | 8089        | Simulador del reto cf_clearance          |
| dast-app      | (n/d)          | (n/d)       | El escáner DAST (ejecución one-shot)     |

`dvwa-origin` (puerto host 8080) es la instancia limpia de DVWA, útil como línea base. `dvwa-waf`
(puerto host 8088) es Apache + ModSecurity v2 con el OWASP Core Rule Set por delante de
`dvwa-origin`, y toma el alias de red `dvwa` — de modo que cualquier escaneo lanzado con
`--url http://dvwa` atraviesa el WAF de forma transparente. `cf-sim` (puerto host 8089) simula un
reto anti-bot `cf_clearance` de Cloudflare por delante de `dvwa-origin`, bajo el alias `dvwa-cf`.
La configuración del WAF y sus exclusiones se documentan en
[`infra/modsecurity/README.md`](./infra/modsecurity/README.md); el simulador en
[`infra/cf-sim/README.md`](./infra/cf-sim/README.md).

| Objetivo del comando de escaneo | Pasa a través de              | Sirve para                       |
|---------------------------------|-------------------------------|----------------------------------|
| `--url http://dvwa-origin`      | DVWA directo, sin nada delante| Línea base (sin WAF)             |
| `--url http://dvwa`             | WAF ModSecurity               | Validar `--obfuscation`          |
| `--url http://dvwa-cf`          | Simulador cf_clearance        | Validar el puente cookie/UA      |

---

## Arquitectura

El pipeline ejecuta cuatro módulos de forma secuencial:

```
URL objetivo
   |
   v
[Módulo 1 - Crawler]
   Playwright con Chromium headless. Recorrido BFS hasta MAX_DEPTH.
   Intercepta XHR/fetch. Gestiona preautenticación opcional por formulario.
   Salida: lista de CrawledPage (url, html, forms, links, xhr_endpoints)
   |
   v
[Módulo 2 - Identificación de vectores]
   BeautifulSoup4 + lxml parsean el HTML de cada página.
   Extrae campos de formulario, parámetros URL, manejadores de eventos.
   Heurísticas asignan los VulnType aplicables por campo (nombre, tipo, enctype,
   valor por defecto). Deduplica por (url, método, nombre_de_campo).
   Salida: lista de AttackVector
   |
   v
[Módulo 3 - Motor de fuzzing]  ← CONCURRENTE (asyncio.Semaphore)
   CONCURRENT_VECTORS vectores escaneados en paralelo.
   Por vector, CONCURRENT_PAYLOADS payloads probados concurrentemente.
   Los payloads time-based se serializan siempre (asyncio.Lock dedicado).
   Rate limiting opcional (REQUESTS_PER_SECOND > 0).
   Scanners:
     SQLiScanner            - patrones de error, delta temporal, marcadores UNION
     XSSScanner             - reflexión del payload, comprobación DOM-based
     CMDiScanner            - patrones de salida del SO, delta temporal
     SSRFScanner            - patrones de metadatos cloud, delta de tamaño de respuesta
     XXEScanner             - resolución de entidad DTD, errores del parser
     DeserializationScanner - patrones de excepción, correlación con HTTP 500
     PathTraversalScanner   - patrones de contenido de ficheros del sistema, errores de FS
     OpenRedirectScanner    - cabecera Location, meta-refresh, redirección JS
   Reintentos por payload. Hallazgo confirmado al repetirse la detección.
   Tras el fuzzing: segunda pasada del crawler para detectar XSS almacenado.
   Salida: lista de RawFinding
   |
   v
[Módulo 4 - Análisis e informe]
   Validator normaliza y enriquece los hallazgos.
   SeverityScorer: mapea cada hallazgo → CVSSVector vía cvss_mapper,
     calcula el CVSS 3.1 Base Score y deriva la severidad de las bandas numéricas.
   ReportGenerator escribe findings.db (SQLite), report.json, report.html.
   Todas las salidas incluyen cvss_vector_string (p.ej. CVSS:3.1/AV:N/AC:L/...).
   Salida: ScanReport + ficheros en reports/<scan_id>/
```

### Retos anti-bot (puente cf_clearance)

Algunos objetivos reales se sitúan tras una capa anti-bot como Cloudflare, que emite una cookie
`cf_clearance` solo tras un reto JavaScript que un cliente HTTP plano no puede resolver. El
crawler del framework ejecuta un navegador real (Playwright) y *sí* puede resolver estos retos;
el fuzzer usa `httpx` y no puede. El **puente cf_clearance** cierra esa brecha: el crawler
captura tanto las cookies de sesión *como* el `User-Agent` de su `BrowserContext` autenticado, y
el pipeline los propaga al `HTTPClient` que construye el fuzzer. Propagar el `User-Agent` importa
porque la cookie del reto está ligada al UA que la solicitó — enviar el UA por defecto de `httpx`
invalidaría la clearance.

El comportamiento se selecciona con `--cf-clearance-mode` (o `CF_CLEARANCE_MODE`):

- `off` (por defecto): sin propagación de cookie ni UA — el fuzzer usa su propia sesión y
  recibirá 403 en cada petición a un objetivo protegido por cf.
- `propagate`: las cookies y el User-Agent del crawler se empujan al `HTTPClient` del fuzzer,
  pero sin refresco reactivo.
- `refresh`: propagación **más** refresco reactivo — cuando un upstream responde con
  `X-Cf-Sim-Challenge: expired`/`missing`, el `HTTPClient` relanza Playwright para renovar la
  cookie y el UA, y reintenta la petición una vez.

El servicio `cf-sim` (ver Topología de servicios) es un fixture local que implementa este
contrato para las pruebas.

---

## Clases de vulnerabilidad

| VulnType | Scanner | Técnica de detección | CVSS típico |
|---|---|---|---|
| `sqli` | SQLiScanner | patrones de error SQL, marcador UNION, retardo time-based | 9.1 / 5.9 |
| `xss` | XSSScanner | reflexión del payload (literal + parcial), patrones de ejecución | 6.1 / 5.4 |
| `cmdi` | CMDiScanner | patrones de salida de comando del SO, retardo time-based | 9.8 |
| `ssrf` | SSRFScanner | contenido de metadatos cloud, diferencia de tamaño de respuesta | 5.3 |
| `xxe` | XXEScanner | reflexión del contenido de fichero, errores del parser XML | 8.2 |
| `deserialization` | DeserializationScanner | mensajes de excepción de deser., HTTP 500 + payload serializado | 9.8 |
| `path_traversal` | PathTraversalScanner | contenido de `/etc/passwd` / `win.ini`, errores de FS | 7.5 |
| `open_redirect` | OpenRedirectScanner | cabecera Location 3xx, meta-refresh, `window.location` JS | 6.1 |

Heurísticas de VulnType (nombre del campo → scanner):

- **SSRF**: url, endpoint, api, webhook, proxy, fetch, load, src, href, callback
- **Path Traversal**: file, filename, path, template, include, dir, download, read, load
- **Open Redirect**: url, redirect, next, return, goto, target, destination, redir, continue
- **CMDi**: cmd, command, exec, execute, shell, ping, host, ip, file, filename, path
- **XXE**: solo cuando el enctype del formulario es `application/xml` / `text/xml`
- **Deserialización**: solo cuando el valor por defecto del campo parece un dato serializado (base64/`O:`/`rO0AB`)

---

## Requisitos

- Docker >= 24
- docker compose >= 2.20 (el subcomando `docker compose`, no `docker-compose`)
- Bash >= 4 (para `start.sh` y `stop.sh`)

No se requiere instalar Python en el host. Todo se ejecuta dentro de contenedores.

---

## Inicio rápido

```bash
# 1. Clonar el repositorio
git clone https://github.com/anxorguez/DAST.git
cd DAST

# 2. Copiar la plantilla de entorno
cp .env.example .env

# 3. Levantar el backend, el WAF y el cf-sim, y esperar a que estén listos
./start.sh

# 4a. Escaneo de línea base contra DVWA SIN el WAF
docker compose run --rm dast-app --url http://dvwa-origin \
    --concurrent-vectors 5 --concurrent-payloads 10 --requests-per-second 0 \
    --depth 3 --max-pages 100 --max-payloads-per-vector 50 \
    --payload-types sqli,xss,cmdi,ssrf,xxe,deserialization,path_traversal,open_redirect \
    --request-timeout 30

# 4b. Escaneo contra DVWA A TRAVÉS del WAF ModSecurity, ejercitando --obfuscation
docker compose run --rm dast-app --url http://dvwa \
    --obfuscation none,double_url,base64 \
    --concurrent-vectors 5 --concurrent-payloads 10 --requests-per-second 0 \
    --depth 3 --max-pages 100 --max-payloads-per-vector 50 \
    --payload-types sqli,xss,cmdi,ssrf,xxe,deserialization,path_traversal,open_redirect \
    --request-timeout 30

# 5. Encuentra tu informe en ./reports/outputs/<scan_id>/
ls reports/outputs/
```

---

## Configuración

Todos los ajustes se leen de variables de entorno (fichero `.env` o entorno del shell).

| Variable                  | Defecto                                      | Descripción                                         |
|---------------------------|----------------------------------------------|-----------------------------------------------------|
| TARGET_URL                | http://dvwa                                  | URL de la aplicación a escanear                     |
| OUTPUT_DIR                | /app/reports                                 | Directorio de salida dentro del contenedor          |
| LOG_LEVEL                 | INFO                                         | Nivel de log: DEBUG, INFO, WARNING, ERROR           |
| MAX_DEPTH                 | 3                                            | Profundidad máxima del crawling BFS                 |
| MAX_PAGES                 | 100                                          | Número máximo de páginas a visitar                  |
| REQUEST_TIMEOUT           | 30                                           | Timeout de petición HTTP en segundos                |
| CONCURRENT_PAGES          | 5                                            | Páginas procesadas concurrentemente por Playwright  |
| AUTH_ENABLED              | false                                        | Habilita el login por formulario previo al escaneo  |
| AUTH_URL                  | (vacío)                                      | URL del formulario de login                         |
| AUTH_USERNAME             | (vacío)                                      | Usuario a enviar en el formulario de login          |
| AUTH_PASSWORD             | (vacío)                                      | Password a enviar en el formulario de login         |
| AUTH_USERNAME_FIELD       | username                                     | atributo name del input de usuario                  |
| AUTH_PASSWORD_FIELD       | password                                     | atributo name del input de password                 |
| AUTH_SUCCESS_URL          | (vacío)                                      | URL para verificar el redirect de login correcto    |
| PAYLOAD_TYPES             | sqli,xss,cmdi,ssrf,xxe,deserialization,…     | Lista CSV de clases de vulnerabilidad activas       |
| MAX_PAYLOADS_PER_VECTOR   | 50                                           | Máximo de payloads probados por vector de ataque    |
| CONCURRENT_VECTORS        | 5                                            | Número de vectores fuzzeados concurrentemente       |
| CONCURRENT_PAYLOADS       | 10                                           | Payloads probados en paralelo por scanner           |
| REQUESTS_PER_SECOND       | 0                                            | Límite de peticiones (0 = sin límite)               |
| CF_CLEARANCE_MODE         | off                                          | Modo del puente cf_clearance: off / propagate / refresh |
| DVWA_SECURITY_LEVEL       | low                                          | Nivel de seguridad de DVWA para los tests de integración |
| DVWA_USERNAME             | admin                                        | Usuario de login de DVWA                            |
| DVWA_PASSWORD             | password                                     | Password de login de DVWA                           |

Los flags de la CLI siempre tienen prioridad sobre las variables de entorno y los valores por defecto.

### Autenticación contra DVWA

DVWA redirige cada página a `login.php` hasta que se establece una cookie de sesión, de modo que
un escaneo con `AUTH_ENABLED=false` solo fuzzeará el formulario de login y no alcanzará ninguno de
los endpoints vulnerables (sqli, xss_r, xss_s, exec, file_inclusion, ...). Se registra un aviso
cuando el crawl se detiene en una única página de login sin autenticación habilitada.

Para escanear DVWA correctamente, añade el siguiente bloque a tu `.env`:

```env
# --- Autenticación contra DVWA ---
AUTH_ENABLED=true
AUTH_URL=http://dvwa/login.php
AUTH_USERNAME=admin
AUTH_PASSWORD=password
AUTH_USERNAME_FIELD=username
AUTH_PASSWORD_FIELD=password
AUTH_SUCCESS_URL=http://dvwa/index.php
```

Con estos valores el crawler inicia sesión una vez antes de empezar el BFS, reutiliza la cookie
`PHPSESSID` en cada petición posterior, y es capaz de descubrir y fuzzear las páginas vulnerables:
`/vulnerabilities/sqli/?id=...`, `/vulnerabilities/xss_r/?name=...`, `/vulnerabilities/xss_s/`,
`/vulnerabilities/exec/`, `/vulnerabilities/fi/?page=...`, y otras.

### Parámetros de tuning

El comportamiento del framework se controla íntegramente desde la línea de comandos. La tabla
siguiente recoge el conjunto completo de flags disponibles, agrupadas por su función, junto con su
valor por defecto. Cada flag de velocidad y cobertura puede fijarse también por su variable de
entorno (la CLI gana en caso de conflicto).

| Flag | Grupo | Defecto | Descripción |
|------|-------|---------|-------------|
| `--url` | General | (obligatorio) | URL del objetivo a escanear |
| `--concurrent-vectors` | Velocidad | 5 | Vectores de ataque fuzzeados en paralelo; cambia la rapidez, no lo que se prueba |
| `--concurrent-payloads` | Velocidad | 10 | Payloads probados en paralelo dentro de cada scanner |
| `--requests-per-second` | Velocidad | 0 | Límite global de peticiones/s compartido por todos los scanners (0 = sin límite) |
| `--depth` | Cobertura | 3 | Profundidad máxima de la búsqueda BFS del crawler; admite `unlimited` |
| `--max-pages` | Cobertura | 100 | Tope absoluto de páginas rastreadas; admite `unlimited` |
| `--max-payloads-per-vector` | Cobertura | 50 | Máximo de payloads por vector y scanner; palanca dominante del coste. Admite `unlimited` |
| `--payload-types` | Cobertura | (las 8 clases) | Lista CSV de las clases de scanner activas |
| `--obfuscation` | Cobertura | none | Lista CSV de codificaciones de ofuscación aplicadas a los payloads |
| `--request-timeout` | Cobertura | 30 | Timeout HTTP por petición, en segundos |
| `--scanner-vector-timeout` | Cobertura | 120 | Tope de reloj por scanner y vector antes de cancelar sus payloads; admite `unlimited` |
| `--cf-clearance-mode` | Sesión | off | Modo del puente cf_clearance para objetivos con capa anti-bot |
| `--output` | General | (marca temporal) | Nombre del directorio de salida del escaneo |
| `--output-base` | General | ./reports | Directorio base donde se crean las carpetas de escaneo |
| `--log-level` | General | INFO | Verbosidad del registro de ejecución |

Valores admitidos por las flags de dominio acotado:

- `--payload-types`: `sqli`, `xss`, `cmdi`, `ssrf`, `xxe`, `deserialization`, `path_traversal`,
  `open_redirect`. Cada valor activa el scanner de esa clase; por defecto se activan las ocho.
- `--obfuscation`: `none`, `url`, `double_url`, `base64`, `sql_comment`. Cada scanner declara
  cuáles tienen sentido y el conjunto efectivo es la intersección con lo solicitado.
- `--cf-clearance-mode`: `off` (sin propagación de sesión; 403 en objetivos protegidos),
  `propagate` (cookies y User-Agent del crawler llegan al fuzzer sin refresco), `refresh`
  (propagación con refresco reactivo de la cookie).
- `--log-level`: `DEBUG`, `INFO`, `WARNING`, `ERROR`. DEBUG registra cada payload y respuesta.
- Convención `unlimited`: las flags `--depth`, `--max-pages`, `--max-payloads-per-vector` y
  `--scanner-vector-timeout` aceptan el valor `unlimited` (o `none`/`inf`/`-1`) para eliminar el
  tope correspondiente.

#### Velocidad / huella

Estas flags controlan **cuántas peticiones se ejecutan en paralelo y a qué ritmo**. NO cambian lo
que se prueba, solo la rapidez y lo visible que es el escaneo para los logs/IDS del objetivo.

| Flag CLI                | Variable de entorno    | Defecto | Descripción                                       |
|-------------------------|------------------------|---------|---------------------------------------------------|
| `--concurrent-vectors`  | `CONCURRENT_VECTORS`   | 5       | Vectores fuzzeados en paralelo                    |
| `--concurrent-payloads` | `CONCURRENT_PAYLOADS`  | 10      | Payloads probados en paralelo por scanner         |
| `--requests-per-second` | `REQUESTS_PER_SECOND`  | 0       | Límite global aplicado a TODOS los scanners (0 = sin límite) |

**Nota**: `--requests-per-second` es un único limitador compartido — el ritmo configurado es la
tasa de salida *combinada* de todos los scanners y vectores, no una tasa por scanner.

#### Cobertura / alcance

Estas flags controlan **qué partes del objetivo se exploran y con qué exhaustividad**. Son las
palancas que cambian el número de hallazgos.

| Flag CLI                     | Variable de entorno      | Defecto | Descripción                                         |
|------------------------------|--------------------------|---------|-----------------------------------------------------|
| `--depth`                    | `MAX_DEPTH`              | 3       | Profundidad máxima del BFS del crawler              |
| `--max-pages`                | `MAX_PAGES`              | 100     | Tope duro de páginas rastreadas                     |
| `--max-payloads-per-vector`  | `MAX_PAYLOADS_PER_VECTOR`| 50      | Máx. payloads por (vector × scanner). Palanca dominante |
| `--payload-types`            | `PAYLOAD_TYPES`          | (las 8) | CSV de clases de scanner activas                    |
| `--request-timeout`          | `REQUEST_TIMEOUT`        | 30      | Timeout de petición HTTP en segundos                |

#### Combinaciones recomendadas

Las columnas de abajo reproducen los estilos de escaneo mínimo/equilibrado/agresivo/sigiloso,
expresados en términos de las flags.

| Estilo         | cv | cp | rps | depth | páginas | mppv | payload-types  |
|----------------|----|----|-----|-------|---------|------|----------------|
| **mínimo**     | 1  | 1  | 1   | 1     | 5       | 5    | sqli           |
| **equilibrado**| 5  | 10 | 0   | 3     | 100     | 50   | (las 8)        |
| **agresivo**   | 10 | 20 | 0   | 5     | 500     | 200  | (las 8)        |
| **sigiloso**   | 2  | 3  | 5   | 2     | 50      | 20   | (las 8)        |

Los informes HTML y JSON incluyen un bloque "Effective Configuration" que vuelca cada campo de
Settings usado en la ejecución, de modo que el analista puede verificar exactamente qué
combinación produjo los hallazgos.

---

## Salida

Cada escaneo crea una carpeta con nombre único bajo `reports/`:

```
reports/
+-- 20250315_142301_3f9a1c2b/
    +-- findings.db     Base de datos SQLite con todos los hallazgos validados
    +-- report.html     Informe HTML completo renderizado desde plantilla Jinja2
    +-- report.json     Informe legible por máquina (mismos datos que el HTML)
    +-- scan.log        Log completo de esta sesión de escaneo
```

El directorio `reports/` está excluido del control de versiones (`.gitignore`). Solo se versiona
`reports/outputs/.gitkeep`.

---

## Ejecutar los tests

Instala primero las dependencias de desarrollo (o usa el entorno Docker):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
playwright install chromium
```

Ejecuta los tests unitarios (no necesitan servicios externos):

```bash
pytest tests/unit/ -v --cov=src --cov-report=term-missing
```

Ejecuta los tests de integración contra DVWA (requiere haber ejecutado `./start.sh` antes):

```bash
pytest tests/integration/ -v -m integration
```

---

## CI/CD

Tres workflows de GitHub Actions se ejecutan en cada push y pull request a `main`:

| Workflow     | Fichero                                 | Qué hace                                                   |
|--------------|-----------------------------------------|------------------------------------------------------------|
| Lint         | .github/workflows/lint.yml              | ruff check, ruff format check, mypy strict                |
| Test         | .github/workflows/test.yml              | Levanta DVWA, ejecuta tests unitarios + integración, sube coverage |
| Docker Build | .github/workflows/docker-build.yml      | Construye imagen multi-arch, la publica en GHCR en tag/main |

---

## Seguridad

Los reportes de vulnerabilidad del propio framework deben enviarse mediante GitHub Security
Advisories. Consulta `SECURITY.md` para la política completa y el SLA de respuesta.

Esta herramienta está diseñada exclusivamente para usarse contra aplicaciones que poseas o para
las que tengas permiso escrito explícito de testing. El uso no autorizado contra sistemas de
terceros puede violar la legislación aplicable. Los autores no aceptan responsabilidad alguna por
un mal uso.

---

## Contribuir

Consulta `CONTRIBUTING.md` para el entorno de desarrollo, las convenciones de código y el proceso
de pull request.

---

## Licencia

Licencia MIT. Consulta `LICENSE` para el texto completo.
