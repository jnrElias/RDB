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

1. Sube estos archivos a tu repositorio (rama `main`).
2. En GitHub, ve a **Settings → Pages**.
3. En **Build and deployment → Source**, elige **GitHub Actions**.
4. Espera a que termine el workflow "Deploy to GitHub Pages" (pestaña *Actions*).
5. Tu web estará en: `https://<tu-usuario>.github.io/<tu-repo>/`

> Alternativa sencilla: en **Settings → Pages → Source** elige
> **Deploy from a branch → `main` → `/ (root)`**.

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

### Sincronización entre dispositivos

Los datos se guardan **en cada dispositivo** (almacenamiento local cifrado). Para
mover tu información de un dispositivo a otro, usa el botón **Copia** (descarga un
archivo cifrado) y **Restaurar** en el otro dispositivo. El archivo solo se puede
abrir con tu contraseña.

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
