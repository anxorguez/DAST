# `dvwa-waf` — WAF ModSecurity delante de DVWA

## Rol del componente

`dvwa-waf` es un **Web Application Firewall** colocado entre el escáner
`dast-app` y el backend real `dvwa-origin`. Toma el alias de red `dvwa`, de
modo que cualquier escaneo lanzado con `--url http://dvwa` atraviesa el WAF
de forma transparente, sin que la CLI ni el `.env` tengan que cambiar de
host. El backend sin protección sigue accesible como `http://dvwa-origin`.

```
dast-app  ──HTTP──>  dvwa-waf (alias `dvwa`)  ──HTTP──>  dvwa-origin  ──>  db
            --url http://dvwa                  proxy interno
```

## Tecnología

- **Apache 2.4** como servidor/reverse proxy.
- **ModSecurity v2.9** como motor de reglas WAF.
- **OWASP Core Rule Set (CRS) 4.x** como conjunto de reglas.
- Imagen oficial: [`owasp/modsecurity-crs:apache`](https://hub.docker.com/r/owasp/modsecurity-crs).

La imagen escucha en el puerto `8080` interno; el `docker-compose.yml`
publica el `8088` del host para inspección directa desde el navegador.

## Por qué `PARANOIA=1`

El CRS define cuatro *Paranoia Levels* (PL). `PL=1` es el valor por defecto:
captura los ataques clásicos sin generar falsos positivos sobre tráfico
legítimo. Los niveles `PL=2` y `PL=3` son más estrictos pero bloquean el
flujo de autenticación de DVWA (tokens hex, formularios), por lo que para
esta topología `PARANOIA=1` es lo correcto. Endurecer la prueba subiendo el
PL debe hacerse en una tarea separada con su propia verificación.

## Cómo inspeccionar bloqueos

```bash
# Resumen rápido de los bloqueos en el log de Apache:
docker compose logs dvwa-waf | grep "ModSecurity:"

# Audit log detallado (cada transacción interceptada, con IDs de regla):
docker compose exec dvwa-waf cat /var/log/apache2/modsec_audit.log
```

## Cómo añadir exclusiones

Si una request legítima dispara una regla CRS (típicamente durante el
login o el cambio de nivel de seguridad de DVWA):

1. Localiza el ID de la regla en `modsec_audit.log`.
2. Añade una exclusión **atada a esa request concreta** (path + parámetro)
   en [`exclusions.conf`](./exclusions.conf). Nunca desactives una regla de
   forma global.
3. Reinicia el WAF:

   ```bash
   docker compose restart dvwa-waf
   ```

El bind mount carga `exclusions.conf` en `/etc/modsecurity.d/`, que la
imagen lee automáticamente después de las reglas base del CRS.

## Cómo bypassear el WAF para depurar

Para escanear DVWA sin el WAF delante (baseline limpio):

```bash
docker compose run --rm dast-app --url http://dvwa-origin ...
```

## IDs CRS relevantes para el TFM

| Familia | Clase de ataque                | Ejemplos de reglas               |
|---------|--------------------------------|----------------------------------|
| 942xxx  | SQL Injection                  | 942100 (libinjection_sqli), 942110 (SQL Comment) |
| 941xxx  | Cross-Site Scripting           | 941100 (XSS — libinjection)      |
| 932xxx  | Remote Command Execution       | 932100 (Unix command injection)  |
| 930xxx  | Local File Inclusion           | 930100 (path traversal)          |
| 934xxx  | Server-Side Request Forgery    | 934100 (SSRF)                    |
| 920xxx  | Protocol enforcement           | 920350 (Host header is numeric)  |

Conocer estas familias permite al analista leer el `modsec_audit.log` y
entender exactamente qué payloads bloqueó el WAF y cuáles lograron pasar
gracias a `--obfuscation`.
