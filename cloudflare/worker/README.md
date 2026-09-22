# Club Deportivo API — migración a Cloudflare

Esta carpeta prepara el backend nuevo sin modificar la aplicación pública actual.

## Primera fase

Incluye:

- Worker con `/api/health`.
- Inicio de sesión con `/api/login`.
- Validación de sesión con `/api/session`.
- Esquema D1 para usuarios, registros, asistencias, borradores y log.
- Protección para no guardar claves/PIN en texto plano.

## Recursos de Cloudflare pendientes de crear/vincular

1. Crear D1 con nombre `club-deportivo-db`.
2. Vincularla al Worker usando el binding `DB`.
3. Configurar secretos:
   - `SESSION_SECRET`
   - `PIN_PEPPER`
4. Configurar variable:
   - `ALLOWED_ORIGINS` con los orígenes permitidos separados por coma.

No se deben guardar PIN, `SESSION_SECRET` ni `PIN_PEPPER` en GitHub.

## Después de vincular D1

Aplicar la migración `0001_initial.sql` y crear los usuarios iniciales con hashes calculados fuera del repositorio.

La versión actual basada en Apps Script sigue siendo la versión funcional hasta que esta rama sea probada.
