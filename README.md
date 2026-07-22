# 🎬 YT Studio — Planificador privado para YouTube

Web autónoma, privada y **cifrada** para organizar el contenido de tu canal de
YouTube. Se publica gratis en GitHub Pages y es accesible desde cualquier
dispositivo (móvil, tablet, ordenador).

## ✨ Qué incluye

- **Acceso con credenciales** (correo + contraseña). Ni el correo ni la
  contraseña están escritos en el código: solo se guarda un *hash* irreversible.
- **Cifrado AES-256-GCM**: toda tu información se guarda cifrada. La clave se
  deriva de tu contraseña al entrar y **solo vive en memoria** — nunca se guarda.
  Sin tu contraseña, los datos son ilegibles incluso desde la consola del navegador.
- **Memoria permanente**: nada se borra al cerrar sesión o cerrar el navegador.
  Todo queda guardado (cifrado) en el propio dispositivo.
- **Semanas** que puedes **añadir o eliminar** libremente.
  - Cada semana tiene **dos campos de planning semanal**.
  - Cada semana tiene **7 días** (Lunes a Domingo). Por cada día:
    - Título del vídeo
    - **Miniatura**: subir, cambiar, descargar y eliminar
    - Guion del vídeo
    - Descripción del vídeo
    - Etiquetas del vídeo
    - Comentario a fijar
    - Prompt de la miniatura
- **Copia de seguridad cifrada** (botones *Copia* / *Restaurar*) para llevar tus
  datos de un dispositivo a otro de forma segura.
- Diseño **visual, responsive y elegante**.

## 🚀 Cómo publicarla en GitHub Pages

1. En GitHub, ve a **Settings → Pages**.
2. En **Build and deployment → Source**, elige **Deploy from a branch**.
3. En **Branch**, elige **`main`** y carpeta **`/ (root)`** → **Save**.
4. Espera ~1 minuto. Tu web estará en: `https://<tu-usuario>.github.io/<tu-repo>/`

> Tras cualquier cambio, haz una **recarga forzada** (Ctrl+F5 / Cmd+Shift+R) para
> ver la última versión sin caché.

## 🔐 Sobre la seguridad (importante y honesto)

Esta web es **100% estática** (no tiene servidor). Eso implica:

- ✅ Tus datos van **cifrados** con una clave derivada de tu contraseña. Nadie
  puede leerlos sin ella, ni siquiera abriendo el código o la consola.
- ✅ En el código **no aparece tu contraseña**, solo un hash PBKDF2 (310.000
  iteraciones) que no permite recuperarla.
- ⚠️ Al ser estática, cualquiera puede *abrir la página*, pero verá solo la
  pantalla de acceso. Sin tu contraseña no puede desbloquear ni descifrar nada.
- ⚠️ La página es pública, así que un atacante podría intentar **adivinar** la
  contraseña por fuerza bruta contra el hash. Por eso conviene usar una
  contraseña larga y única. Puedes cambiarla en cualquier momento (ver abajo).

### ¿Puedo tener el repositorio en privado?

- En el **plan gratuito de GitHub**, GitHub Pages **solo publica desde repos
  públicos**. Para publicar desde un repo **privado** necesitas **GitHub Pro**.
- No es necesario para tu privacidad: el código no contiene secretos (solo hashes)
  y **todos tus datos van cifrados**. Un repo público es perfectamente seguro aquí.
- Si aun así quieres todo privado, la opción es GitHub Pro (o alojar los archivos
  estáticos en otro sitio, p. ej. Cloudflare Pages, que sí permite repos privados
  gratis).

## ☁️ Sincronización entre dispositivos (con GitHub)

La web puede **guardar y sincronizar tus datos usando tu propio repositorio de
GitHub**, sin ningún servidor extra. Así ves y editas todo desde el móvil y otros
ordenadores. Tus datos se guardan **cifrados** en tu rama `main`, en el archivo
`datos/vault.enc.json`, por lo que aunque el repo sea público nadie puede leer su
contenido.

### Cómo activarla (una vez por dispositivo)

1. Crea un **token de acceso** en GitHub (ajustes de tu cuenta, no del repo):
   - Tu foto de perfil → **Settings** → abajo del todo → **Developer settings**.
   - **Personal access tokens → Fine-grained tokens → Generate new token**.
   - *Repository access*: **Only select repositories** → `RDB`.
   - *Permissions → Repository permissions*: busca **Contents** y ponlo en
     **Read and write** (Metadata: Read-only se añade solo, es correcto).
   - **Generate token** y copia el código (empieza por `github_pat_...`).
2. En la web, pulsa **☁ Sincronizar** (arriba a la derecha).
3. Deja los valores por defecto (usuario `jnrElias`, repo `RDB`, rama `main`,
   ruta `datos/vault.enc.json`) y pega el token.
4. Pulsa **Conectar y sincronizar**. ¡Listo!

En cada dispositivo nuevo, repite los pasos 2–4 con el mismo token (o crea uno por
dispositivo). El token se guarda **cifrado en el dispositivo**, nunca en el código.

- Los cambios se suben solos unos segundos después de escribir.
- Al abrir la web o volver a la pestaña, se descarga automáticamente lo más reciente.
- Regla ante conflictos: gana la última edición (por marca de tiempo). Evita editar
  el mismo día en dos dispositivos a la vez.

### Alternativa sin token: copia manual

Si prefieres no usar token, están los botones **Copia** (descarga un archivo
cifrado) y **Restaurar** (en el otro dispositivo). El archivo solo se abre con tu
contraseña.

## 🔁 Cambiar el correo o la contraseña

Las credenciales viven como hashes en `app.js` (constante `CFG`). Para
regenerarlas con seguridad, ejecuta el script incluido:

```bash
node scripts/gen-credentials.js "tu@correo.com" "TuNuevaContraseña"
```

Copia los valores que imprime (`saltVer`, `saltKey`, `verifier`) dentro del
objeto `CFG` en `app.js`, súbelo y listo.

> Si cambias la contraseña, la copia de seguridad hecha con la anterior deja de
> poder restaurarse. Exporta una copia **antes** de cambiarla si quieres conservar
> los datos, restaura, y vuelve a exportar con la nueva.
