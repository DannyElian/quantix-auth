# Servidor de cuentas QUANTIX

Las cuentas viven en este servicio. El administrador crea usuarios y cualquier teléfono puede entrar.

El administrador entra con las credenciales definidas en las variables de entorno `ADMIN_USERNAME` y `ADMIN_PASSWORD`.

El plan gratuito de Render se duerme a los 15 minutos sin tráfico. El primer login puede tardar hasta un minuto. Un ping cada 10 minutos (GitHub Actions) intenta mantenerlo despierto.

## Variables

- `PORT` — Render la asigna
- `GIST_ID` — almacén de cuentas
- `GITHUB_TOKEN` — token con permiso `gist` para guardar cuentas entre reinicios
- `ADMIN_PASSWORD`

No subas `data/` al git.
