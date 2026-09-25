# Club Deportivo API — Cloudflare

Backend del Club Deportivo sobre Cloudflare Workers + D1.

## Autenticación actual

- Los usuarios se autentican con su PIN existente.
- Los PIN no se guardan en texto plano: se almacenan con PBKDF2-SHA-256, sal aleatoria y 100.000 iteraciones.
- `PIN_PEPPER` genera una huella HMAC independiente del hash de contraseña. Esa huella permite garantizar que dos cuentas no utilicen el mismo PIN sin guardar el PIN.
- Los usuarios anteriores se migran de forma gradual: en su siguiente inicio de sesión correcto se completa automáticamente su `pin_fingerprint`.
- Si el sistema detecta que dos cuentas antiguas comparten el mismo PIN, bloquea ese acceso y exige resolver el conflicto desde Administración.
- Después de 5 intentos fallidos dentro de una ventana de 10 minutos, el inicio de sesión queda bloqueado durante 15 minutos.
- Las sesiones usan tokens aleatorios de 256 bits; D1 conserva únicamente el hash del token.

## Recursos

D1:

- `club-deportivo-db`
- binding: `DB`

Secreto obligatorio:

- `PIN_PEPPER`: cadena aleatoria larga y privada. No debe cambiarse después de comenzar a generar huellas de PIN.

Variable:

- `ALLOWED_ORIGINS`: orígenes web permitidos, separados por coma.

No se deben guardar PIN ni `PIN_PEPPER` en GitHub.

## Migraciones

Aplicar en orden:

1. `migrations/0001_initial.sql`
2. `migrations/0002_auth_hardening.sql`

La segunda migración agrega la huella única de PIN y el control de intentos de acceso.

## Compatibilidad

Si `PIN_PEPPER` todavía no está configurado, los usuarios existentes pueden seguir entrando mediante la comprobación PBKDF2 anterior, pero no se permite crear ni cambiar PIN hasta configurar el secreto. Esto evita introducir nuevas cuentas sin la protección de unicidad.

El respaldo heredado de Google Sheets todavía depende temporalmente del PIN en memoria del navegador. Debe desacoplarse antes de activar passkeys como método principal, porque una autenticación biométrica no proporciona el PIN original al frontend.
