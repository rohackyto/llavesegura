# LlaveSegura 🔐

Bóveda personal para tus **API keys**, cifradas, que reemplaza el documento de texto. Funciona en la laptop (local) y está lista para publicarse en **Streamlit Cloud** y usarse desde el celular. Usa el mismo estilo *Power Platform Pills* de las POCs (`Pocs/_tema`).

## Qué hace
- **Registrar** claves: nombre, API key, servicio, enlace a la consola, etiquetas y nota. Buscar y filtrar por servicio.
- **Ver / copiar** una clave (botón 👁 Ver → ícono de copiar). En la lista siempre aparecen enmascaradas (`sk-p••••••abcd`).
- **Importar** tu documento de texto actual (`.txt`, `.env`, o pegándolo). Reconoce `NOMBRE=clave`, `Nombre: clave`, `Nombre | clave` y *nombre en una línea, clave en la siguiente*. Antes de importar puedes corregir nombres y servicios.
- **Desbloquear** con:
  | Método | Dónde | Fuerza |
  |---|---|---|
  | 🔑 Contraseña maestra | Siempre | La principal. Sin ella no se recupera nada. |
  | 👆 Face ID / huella / Windows Hello (passkey) | App publicada (https) o `http://localhost` | Alta |
  | 🔢 Código MFA (Google/Microsoft Authenticator…) | Cualquiera | Alta (no se puede reutilizar un código) |
  | 🔟 PIN de 6 dígitos preconfigurado | Cualquiera | La más cómoda y la menos fuerte |
  En el celular primero aparecen los métodos rápidos; en la laptop, la contraseña.
- **Bloqueo automático** a los 5 min sin uso (`MINUTOS_BLOQUEO`) y botón 🔒 Bloquear.
- **Intentos fallidos**: desde el 5.º fallo hay esperas crecientes (30 s, 60 s… hasta 1 h). Con 10 fallos seguidos solo sirve la contraseña maestra. El contador se guarda en la bóveda, así que vale para todos los dispositivos.
- **Respaldo** cifrado (.json) y exportación a `.env` en texto plano (pide la contraseña maestra).

## Cómo protege tus claves
- Las claves se cifran con **AES-256-GCM** usando una llave de datos aleatoria (DEK). En el archivo no queda nada en claro, ni siquiera los nombres.
- La DEK se guarda **envuelta dos veces**:
  1. con tu **contraseña maestra** (derivada con scrypt);
  2. con la **llave del servidor** (`LLAVE_SERVIDOR`), para el desbloqueo rápido. La app solo la usa después de verificar Face ID, el código MFA o el PIN.
- La configuración del desbloqueo rápido (secreto MFA, hash del PIN, passkeys) también va cifrada con la llave del servidor, y no se puede alterar sin que la app lo note.
- **Límite honesto**: quien tenga **a la vez** el archivo de la bóveda y la llave del servidor podría descifrarla sin el PIN. Por eso en la nube van en lugares distintos: la bóveda en un **repo privado de GitHub** y la llave en los **Secrets de Streamlit**. En modo local la llave está en `data/.llave_servidor`, así que el desbloqueo rápido local protege igual que la cuenta de Windows. Si quieres solo contraseña, no actives métodos rápidos.
- Las claves descifradas viven solo en la memoria de tu sesión y se borran al bloquear.

## Usar en local (laptop)
```powershell
cd C:\Users\rohac\source\llavesegura
.\iniciar.ps1          # abre http://localhost:8612
```
- La primera vez te pide crear la contraseña maestra. La bóveda queda en `data\boveda.json` (y la versión anterior en `data\boveda.bak.json`).
- Usa **`localhost`**, no `127.0.0.1`: Windows Hello / passkeys exigen un nombre de dominio.
- Desde el celular en la misma red (`http://192.168.x.x:8612`) funcionan la contraseña, el PIN y el código MFA, pero **no Face ID**, porque el navegador exige https. Face ID funciona en la versión publicada.
- Pruebas: `.venv\Scripts\python.exe -m unittest -v`

## Publicar en Streamlit Cloud (para usarla en el celular)
Streamlit Cloud borra el disco en cada reinicio. Por eso la bóveda (ya cifrada) se guarda en un **repo privado de GitHub**.

1. **Repo de la app** (puede ser privado): `rohackyto/llavesegura` con esta carpeta. `.gitignore` ya excluye `data/`, `.streamlit/secrets.toml` y `.venv/`.
2. **Repo de datos privado y vacío**: `rohackyto/llavesegura-datos`, con un README para que exista la rama `main`.
3. **Token de GitHub fine-grained**: solo para `llavesegura-datos`, con permiso **Contents: Read and write** y una fecha de vencimiento.
4. **Llave del servidor**: ya está generada en `secrets-para-streamlit-cloud.toml` (este archivo no se sube a git). Para una nueva: `.venv\Scripts\python.exe -c "import boveda; print(boveda.nueva_llave_servidor())"`
5. En Streamlit Cloud, crea la app (archivo `app.py`, subdominio `llavesegura`; vuelve a escribirlo porque el formulario lo autocompleta). Luego, en **Settings → Secrets**, pega el contenido de `secrets-para-streamlit-cloud.toml` con tu token. Sin esos Secrets, la app publicada muestra un aviso y no deja crear la bóveda, para que no se pierda.
6. **Recomendado**: en *Settings → Sharing*, deja la app **privada**, solo para tu correo. Así hay una capa más (login de Google/GitHub) antes de la bóveda.
7. Abre la app en el celular → crea la contraseña maestra → **⚙️ Seguridad** → registra Face ID, el código MFA y/o el PIN → en Safari/Chrome usa *Agregar a pantalla de inicio* para abrirla como app.

> Las passkeys quedan ligadas al dominio. Una registrada en `localhost` no sirve en `llavesegura.streamlit.app`, así que regístrala desde cada dirección y cada dispositivo. Si cambias de dominio, define `ORIGEN` en los Secrets.

**Pasar tus claves locales a la nube**: lo más simple es usar **📥 Importar** directamente en la app publicada con tu documento de texto. Si ya las tienes en la bóveda local, otra opción es subir `data/boveda.json` como `boveda.json` al repo de datos: se abre con la misma contraseña maestra. Luego, en Seguridad, vuelve a registrar los métodos rápidos (la llave del servidor es otra).

## Después de importar
Cuando confirmes que todas tus claves están en la bóveda, **borra el documento de texto original y vacía la papelera**. Aprovecha también para **rotar** las claves que hayan estado mucho tiempo en texto plano.

## Archivos
| Archivo | Qué es |
|---|---|
| `app.py` | Interfaz Streamlit (crear, desbloquear, llaves, agregar, importar, seguridad) |
| `boveda.py` | Cifrado, contraseña, PIN, TOTP, intentos fallidos (sin Streamlit) |
| `passkey.py` | Face ID / huella / Windows Hello con WebAuthn (componente v2 de Streamlit + librería `webauthn`) |
| `almacen.py` | Guardado local o en repo privado de GitHub, con detección de cambios desde otro dispositivo |
| `importar.py` | Lector del documento de texto y exportación `.env` |
| `estilo_pills.py`, `.streamlit/config.toml` | Copia del tema de `Pocs/_tema` |
| `test_boveda.py` | 12 pruebas del núcleo |

## Pendiente / ideas
- Probar Face ID en el iPhone ya publicada (en local se probó el resto del flujo).
- Fecha de vencimiento por clave y aviso de rotación.
- Copiar al portapapeles con un toque y borrado automático del portapapeles.
