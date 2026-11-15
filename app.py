"""LlaveSegura: bóveda personal de API keys cifradas (laptop + celular).

Desbloqueo: contraseña maestra, o en modo rápido Face ID / huella (passkey), código MFA (TOTP) o PIN de 6 dígitos.
"""
from __future__ import annotations

import io
import json
import re
import time
from html import escape
from pathlib import Path

import streamlit as st

import almacen
import boveda as bv
import importar

st.set_page_config(page_title="LlaveSegura", page_icon="🔐", layout="centered")
import estilo_pills  # noqa: E402
import passkey  # noqa: E402  (registra el componente; necesita set_page_config antes)

estilo_pills.aplicar()
CARPETA = Path(__file__).resolve().parent
ss = st.session_state

st.html("""<style>
.ls-chip { display:inline-block; font:600 10.5px/1 var(--pp-mono); letter-spacing:.1em; text-transform:uppercase;
  padding:.3rem .5rem; border-radius:999px; border:1px solid var(--pp-line-2); color:var(--pp-cyan); background:rgb(34 211 238 / .08); }
.ls-chip.ls-gris { color: var(--pp-muted); background: transparent; }
.ls-item { display:flex; align-items:center; gap:.7rem; }
.ls-ico { flex:none; width:2.4rem; height:2.4rem; border-radius:12px; display:grid; place-items:center;
  font:800 1.15rem/1 var(--pp-display); color:var(--pp-on-accent); background:linear-gradient(135deg, var(--pp-cyan), var(--pp-violet)); }
.ls-info { min-width:0; flex:1; }
.ls-nombre { font:700 1.25rem/1.1 var(--pp-display); color:var(--pp-fg); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.ls-mask { font:500 .82rem/1.3 var(--pp-mono); color:var(--pp-muted); margin-top:.15rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.ls-chips { display:flex; gap:.3rem; flex-wrap:wrap; margin-top:.35rem; }
.ls-estado { display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:.45rem; margin:.3rem 0 .8rem; }
.ls-estado > div { background:rgb(11 15 42 / .7); border:1px solid var(--pp-line); border-radius:12px; padding:.55rem .65rem; min-width:0; }
.ls-estado small { display:block; font:600 10px/1.2 var(--pp-mono); letter-spacing:.12em; color:var(--pp-muted); text-transform:uppercase; }
.ls-estado b { display:block; font:700 1.05rem/1.2 var(--pp-display); margin-top:.2rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.ls-candado { text-align:center; margin:1.2rem 0 .4rem; font-size:3rem; filter: drop-shadow(0 0 18px rgb(34 211 238 / .45)); }
[class*="st-key-acc_"] [data-testid="stHorizontalBlock"] { flex-wrap:nowrap !important; gap:.4rem !important; }
[class*="st-key-acc_"] [data-testid="stColumn"] { min-width:0 !important; width:auto !important; flex:1 1 0 !important; }
[class*="st-key-acc_"] button { min-height:2.5rem !important; padding:0 .4rem !important; }
.st-key-barra [data-testid="stHorizontalBlock"] { flex-wrap:nowrap !important; align-items:center; }
.st-key-barra [data-testid="stColumn"] { min-width:0 !important; }
.st-key-barra [data-testid="stColumn"]:last-child { flex:0 0 8.5rem !important; }
</style>""")
# Teclado numérico y autocompletar de código 2FA en los campos de PIN y MFA (revisión liviana cada 700 ms)
st.html("""<script>(function(){ if (window.__lsNum) return; window.__lsNum = setInterval(() => {
  document.querySelectorAll('[class*="st-key-num_"] input:not([inputmode])').forEach(i => {
    i.setAttribute('inputmode', 'numeric'); i.setAttribute('autocomplete', 'one-time-code'); }); }, 700);
})();</script>""", unsafe_allow_javascript=True)

# ---------- configuración ----------
CFG = almacen.leer_config(st.secrets)
ALMACEN = almacen.elegir(CFG, CARPETA)
MINUTOS_BLOQUEO = float(CFG.get("MINUTOS_BLOQUEO") or 5)
UA = st.context.headers.get("User-Agent", "") or ""
MOVIL = bool(re.search(r"iPhone|iPad|Android|Mobile", UA))
NOMBRE_BIO = "Face ID" if re.search(r"iPhone|iPad", UA) else ("huella" if "Android" in UA else
                                                               ("Windows Hello" if "Windows" in UA else "Touch ID / passkey"))


def _llave_servidor() -> tuple[bytes | None, str]:
    """Secreto LLAVE_SERVIDOR; en modo local, si no existe, se crea en data/.llave_servidor."""
    try:
        if CFG.get("LLAVE_SERVIDOR"):
            return bv.llave_desde_texto(CFG["LLAVE_SERVIDOR"]), "secreto LLAVE_SERVIDOR"
    except ValueError as e:
        return None, str(e)
    if isinstance(ALMACEN, almacen.AlmacenLocal):
        f = CARPETA / "data" / ".llave_servidor"
        if not f.exists():
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(bv.nueva_llave_servidor(), encoding="utf-8")
        return bv.llave_desde_texto(f.read_text(encoding="utf-8")), "archivo local data/.llave_servidor"
    return None, "falta el secreto LLAVE_SERVIDOR"


LLAVE_SRV, ORIGEN_LLAVE = _llave_servidor()
EN_LA_NUBE = str(CARPETA).startswith("/mount/src")  # Streamlit Community Cloud
if EN_LA_NUBE and (isinstance(ALMACEN, almacen.AlmacenLocal) or not LLAVE_SRV):
    estilo_pills.cabecera("LlaveSegura", "Falta configurar los Secrets.", eyebrow="Configuración", icono="🔐")
    st.error("En Streamlit Cloud el disco se borra al reiniciar: sin los Secrets tu bóveda se perdería. "
             "Agrega LLAVE_SERVIDOR, GITHUB_TOKEN y GITHUB_REPO en Settings → Secrets (ver README).")
    st.stop()


# ---------- estado y guardado ----------
def cargar() -> None:
    ss.boveda, ss.version = ALMACEN.cargar()


def modificar(cambio) -> bool:
    """Aplica cambio(boveda) y guarda. Si otro dispositivo guardó antes, recarga y lo vuelve a aplicar."""
    for _ in range(3):
        try:
            cambio(ss.boveda)
            ss.version = ALMACEN.guardar(ss.boveda, ss.version)
            return True
        except almacen.Conflicto:
            cargar()
        except almacen.ErrorAlmacen as e:
            st.error(f"No se pudo guardar en {ALMACEN.nombre}: {e}")
            cargar()
            return False
    st.error("La bóveda cambió desde otro dispositivo varias veces seguidas. Vuelve a intentarlo.")
    return False


def bloquear(motivo: str = "") -> None:
    for k in ("dek", "revelada", "editando", "borrando", "totp_nuevo", "reto_in", "reto_reg"):
        ss.pop(k, None)
    ss.boveda = None
    if motivo:
        ss.aviso = motivo


def entradas() -> list[dict]:
    return bv.leer_entradas(ss.boveda, ss.dek)


def rapido_cfg() -> dict | None:
    try:
        return bv.leer_rapido(ss.boveda, LLAVE_SRV)
    except bv.SinLlaveServidor:
        return None


if ss.get("boveda") is None:
    try:
        cargar()
    except almacen.ErrorAlmacen as e:
        st.error(f"No se pudo leer la bóveda desde {ALMACEN.nombre}: {e}")
        st.stop()

estilo_pills.cabecera("LlaveSegura", "Tus API keys cifradas, a mano en la laptop y en el celular.",
                      eyebrow="Bóveda personal · AES-256", icono="🔐")
if ss.get("aviso"):
    st.info(ss.pop("aviso"), icon="🔒")


# ======================================================================
# 1) Crear la bóveda (primera vez)
# ======================================================================
def pantalla_crear() -> None:
    st.subheader("Crea tu bóveda")
    st.write("Elige una **contraseña maestra**. Es la llave principal: si la olvidas, nadie (ni la app) puede "
             "recuperar tus claves. Luego podrás activar Face ID / huella, código MFA o PIN para el celular.")
    with st.form("crear"):
        p1 = st.text_input("Contraseña maestra", type="password", help=f"Mínimo {bv.MIN_PASSWORD} caracteres. "
                           "Una frase de 4–5 palabras es fácil de recordar y difícil de adivinar.")
        p2 = st.text_input("Repítela", type="password")
        ok = st.form_submit_button("Crear bóveda cifrada", width="stretch")
    if ok:
        if p1 != p2:
            st.error("Las contraseñas no coinciden.")
        elif len(p1) < bv.MIN_PASSWORD:
            st.error(f"Usa al menos {bv.MIN_PASSWORD} caracteres.")
        else:
            b, dek = bv.crear(p1, LLAVE_SRV)
            try:
                ss.version = ALMACEN.guardar(b, None)
            except (almacen.Conflicto, almacen.ErrorAlmacen) as e:
                st.error(f"No se pudo crear: {e or 'ya existe una bóveda'}. Recarga la página.")
                return
            ss.boveda, ss.dek, ss.ultimo = b, dek, time.time()
            st.rerun()
    st.caption(f"Se guardará en: {ALMACEN.nombre}.")


# ======================================================================
# 2) Desbloquear
# ======================================================================
def _entrar(dek: bytes, extra=None) -> None:
    def cambio(b):
        bv.registrar_exito(b)
        if extra:
            extra(b)
    modificar(cambio)
    ss.dek, ss.ultimo = dek, time.time()
    for k in ("reto_in",):
        ss.pop(k, None)
    st.rerun()


def _fallo(texto: str) -> None:
    modificar(bv.registrar_fallo)
    quedan = bv.FALLOS_MAX_RAPIDO - ss.boveda["bloqueo"]["fallos"]
    st.error(texto + (f" Te quedan {quedan} intentos antes de que solo valga la contraseña maestra." if 0 < quedan <= 5 else ""))


def _puede_intentar() -> bool:
    cargar()  # contador de intentos siempre fresco (vale para todos los dispositivos)
    espera = bv.espera_restante(ss.boveda)
    if espera:
        st.error(f"Demasiados intentos fallidos. Espera {espera} s.")
        return False
    return True


def tab_password() -> None:
    with st.form("f_pw", clear_on_submit=True):
        pw = st.text_input("Contraseña maestra", type="password")
        ok = st.form_submit_button("Desbloquear", width="stretch")
    if ok and pw and _puede_intentar():
        try:
            dek = bv.abrir_con_password(ss.boveda, pw)
        except bv.ClaveIncorrecta:
            _fallo("Contraseña incorrecta.")
            return

        def extra(b):  # repara el desbloqueo rápido si la llave del servidor cambió o faltaba
            if LLAVE_SRV and not bv.llave_servidor_vigente(b, LLAVE_SRV):
                bv.envolver_servidor(b, dek, LLAVE_SRV)
        _entrar(dek, extra)


def tab_pin() -> None:
    with st.form("f_pin", clear_on_submit=True):
        pin = st.text_input("PIN de 6 dígitos", type="password", max_chars=6, key="num_pin")
        ok = st.form_submit_button("Desbloquear", width="stretch")
    if ok and pin and _puede_intentar():
        cfg = rapido_cfg()
        if cfg and not bv.rapido_bloqueado(ss.boveda) and bv.pin_correcto(cfg, pin):
            _entrar(bv.abrir_rapido(ss.boveda, LLAVE_SRV))
        else:
            _fallo("PIN incorrecto.")


def tab_totp() -> None:
    with st.form("f_totp", clear_on_submit=True):
        cod = st.text_input("Código de 6 dígitos de tu app autenticadora", max_chars=6, key="num_totp")
        ok = st.form_submit_button("Desbloquear", width="stretch")
    if ok and cod and _puede_intentar():
        cfg = rapido_cfg()
        cont = bv.totp_correcto(cfg, cod) if cfg and not bv.rapido_bloqueado(ss.boveda) else None
        if cont is None:
            _fallo("Código incorrecto o ya usado.")
            return

        def extra(b):  # el mismo código no se puede reutilizar
            c = bv.leer_rapido(b, LLAVE_SRV)
            c["totp_ultimo"] = max(c.get("totp_ultimo", 0), cont)
            bv.guardar_rapido(b, LLAVE_SRV, c)
        _entrar(bv.abrir_rapido(ss.boveda, LLAVE_SRV), extra)


def tab_passkey(cfg: dict) -> None:
    rp_id, origen, motivo = passkey.rp_y_origen(CFG)
    if not rp_id:
        st.warning(motivo)
        return
    llaves = [p for p in cfg["passkeys"] if p.get("rp") == rp_id]
    if not llaves:
        st.info(f"Este dominio ({rp_id}) no tiene {NOMBRE_BIO} registrado. Entra con otro método y regístralo en Seguridad.")
        return
    if "reto_in" not in ss:
        ss.reto_in = passkey.opciones_entrada(rp_id, llaves)
    opciones, reto = ss.reto_in
    r = passkey.boton("entrar", opciones, reto, f"Desbloquear con {NOMBRE_BIO}", key="pk_entrar")
    if r and _puede_intentar():
        ss.pop("reto_in", None)
        try:
            usada = passkey.verificar_entrada(r["credencial"], reto, rp_id, origen, llaves)
        except Exception as e:  # noqa: BLE001
            _fallo(f"No se pudo verificar la passkey ({e}).")
            return

        def extra(b):
            c = bv.leer_rapido(b, LLAVE_SRV)
            for p in c["passkeys"]:
                if p["id"] == usada["id"]:
                    p["cuenta"], p["usado"] = usada["cuenta"], time.time()
            bv.guardar_rapido(b, LLAVE_SRV, c)
        _entrar(bv.abrir_rapido(ss.boveda, LLAVE_SRV), extra)


def pantalla_desbloqueo() -> None:
    st.html('<div class="ls-candado">🔒</div>')
    b = ss.boveda
    espera = bv.espera_restante(b)
    if espera:
        st.warning(f"Bloqueada por intentos fallidos. Podrás intentar en {espera} s.")
    cfg = rapido_cfg() if bv.llave_servidor_vigente(b, LLAVE_SRV) else None
    metodos = []
    if cfg and not bv.rapido_bloqueado(b):
        if cfg["passkeys"]:
            metodos.append((f"👆 {NOMBRE_BIO}", lambda: tab_passkey(cfg)))
        if cfg["totp"]:
            metodos.append(("🔢 Código MFA", tab_totp))
        if cfg["pin"]:
            metodos.append(("🔟 PIN", tab_pin))
    pw = ("🔑 Contraseña", tab_password)
    metodos = metodos + [pw] if MOVIL else [pw] + metodos
    if bv.rapido_bloqueado(b):
        st.warning("Por seguridad, tras varios intentos fallidos solo se puede entrar con la contraseña maestra.")
    elif not cfg:
        st.caption("Desbloqueo rápido no disponible: " + (ORIGEN_LLAVE if not LLAVE_SRV else
                   "la llave del servidor cambió; entra con la contraseña para repararlo."))
    if len(metodos) == 1:
        metodos[0][1]()
    else:
        for tab, (_, fn) in zip(st.tabs([m[0] for m in metodos]), metodos):
            with tab:
                fn()


# ======================================================================
# 3) Bóveda abierta
# ======================================================================
@st.fragment(run_every=20)
def vigilante() -> None:
    """Bloqueo automático por inactividad."""
    if ss.get("dek") and time.time() - ss.get("ultimo", 0) > MINUTOS_BLOQUEO * 60:
        bloquear(f"Se bloqueó tras {MINUTOS_BLOQUEO:g} min sin uso.")
        st.rerun(scope="app")


def tarjeta(e: dict) -> None:
    eid = e["id"]
    with st.container(border=True, key=f"card_{eid}"):
        chips = "".join(f'<span class="ls-chip">{escape(x)}</span>' for x in ([e["servicio"]] if e["servicio"] else []))
        chips += "".join(f'<span class="ls-chip ls-gris">{escape(t)}</span>' for t in e.get("etiquetas", []))
        st.html(f'<div class="ls-item"><div class="ls-ico">{escape((e["servicio"] or e["nombre"] or "?")[0].upper())}</div>'
                f'<div class="ls-info"><div class="ls-nombre">{escape(e["nombre"])}</div>'
                f'<div class="ls-mask">{escape(importar.enmascarar(e["clave"]))}</div>'
                + (f'<div class="ls-chips">{chips}</div>' if chips else "") + '</div></div>')
        revelada = ss.get("revelada") == eid
        with st.container(key=f"acc_{eid}"):
            c1, c2, c3 = st.columns(3)
            if c1.button("🙈 Ocultar" if revelada else "👁 Ver", key=f"ver_{eid}", width="stretch",
                         type="primary" if not revelada else "secondary"):
                ss.revelada = None if revelada else eid
                st.rerun()
            if c2.button("✏️ Editar", key=f"ed_{eid}", width="stretch"):
                ss.editando = None if ss.get("editando") == eid else eid
                st.rerun()
            if c3.button("🗑 Borrar", key=f"bo_{eid}", width="stretch"):
                ss.borrando = eid
                st.rerun()
        if revelada:
            st.code(e["clave"], language=None, wrap_lines=True)
            st.caption("Toca el ícono de copiar (arriba a la derecha del recuadro).")
            if e.get("url"):
                st.markdown(f"[Abrir consola del servicio ↗]({e['url']})")
            if e.get("nota"):
                st.caption(e["nota"])
        if ss.get("editando") == eid:
            formulario(e)
        if ss.get("borrando") == eid:
            st.warning(f"¿Borrar **{e['nombre']}**? No se puede deshacer.")
            a, b = st.columns(2)
            if a.button("Sí, borrar", key=f"si_{eid}", type="primary", width="stretch"):
                if modificar(lambda bo: bv.guardar_entradas(bo, ss.dek, [x for x in bv.leer_entradas(bo, ss.dek)
                                                                       if x["id"] != eid])):
                    ss.borrando = None
                    st.toast("Borrada")
                    st.rerun()
            if b.button("Cancelar", key=f"no_{eid}", width="stretch"):
                ss.borrando = None
                st.rerun()


def _servicios() -> list[str]:
    base = sorted({e["servicio"] for e in entradas() if e["servicio"]} | set(importar.PALABRAS) - {"Claude"})
    return base


def formulario(e: dict | None = None) -> None:
    """Agregar (e=None) o editar una entrada."""
    nuevo = e is None
    e = e or {}
    with st.form(f"form_{e.get('id', 'nueva')}", clear_on_submit=nuevo):
        nombre = st.text_input("Nombre *", value=e.get("nombre", ""), placeholder="OpenAI – proyecto grifoapp")
        clave = st.text_input("API key *", value=e.get("clave", ""), type="password")
        servs = _servicios()
        actual = e.get("servicio") or None
        if actual and actual not in servs:
            servs = [actual] + servs
        servicio = st.selectbox("Servicio", servs, index=servs.index(actual) if actual else None,
                                accept_new_options=True, placeholder="Elige o escribe uno")
        url = st.text_input("Enlace a la consola (opcional)", value=e.get("url", ""), placeholder="https://platform.openai.com/api-keys")
        etiquetas = st.text_input("Etiquetas (separadas por coma)", value=", ".join(e.get("etiquetas", [])),
                                  placeholder="producción, n8n")
        nota = st.text_area("Nota (opcional)", value=e.get("nota", ""), height=80,
                            placeholder="Límite de gasto, fecha de vencimiento, quién la usa…")
        ok = st.form_submit_button("Guardar cifrada" if nuevo else "Guardar cambios", width="stretch")
    if not ok:
        return
    if not nombre.strip() or not clave.strip():
        st.error("Nombre y API key son obligatorios.")
        return
    tags = [t.strip() for t in etiquetas.split(",") if t.strip()]
    if nuevo:
        ent = bv.nueva_entrada(nombre, clave, servicio or importar.adivinar_servicio(nombre, clave), url, nota, tags)

        def cambio(b):
            bv.guardar_entradas(b, ss.dek, bv.leer_entradas(b, ss.dek) + [ent])
    else:
        eid = e["id"]

        def cambio(b):
            lista = bv.leer_entradas(b, ss.dek)
            for x in lista:
                if x["id"] == eid:
                    x.update(nombre=nombre.strip(), clave=clave.strip(), servicio=(servicio or "").strip(),
                             url=url.strip(), nota=nota.strip(), etiquetas=tags, actualizado=time.time())
            bv.guardar_entradas(b, ss.dek, lista)
    if modificar(cambio):
        ss.editando = None
        st.toast("Guardada y cifrada ✔")
        st.rerun()


def tab_llaves() -> None:
    lista = entradas()
    if not lista:
        st.info("Aún no tienes claves. Agrégalas en **➕ Agregar** o trae tu archivo de texto en **📥 Importar**.")
        return
    q = st.text_input("Buscar", placeholder="Nombre, servicio, etiqueta o nota…", label_visibility="collapsed")
    servs = sorted({e["servicio"] for e in lista if e["servicio"]})
    filtro = st.pills("Servicio", servs, selection_mode="multi", label_visibility="collapsed") if len(servs) > 1 else []
    ql = q.lower().strip()
    vis = [e for e in lista
           if (not ql or ql in " ".join([e["nombre"], e["servicio"], e.get("nota", ""), *e.get("etiquetas", [])]).lower())
           and (not filtro or e["servicio"] in filtro)]
    vis.sort(key=lambda e: (e["servicio"].lower() or "~", e["nombre"].lower()))
    st.caption(f"{len(vis)} de {len(lista)} claves")
    for e in vis:
        tarjeta(e)


def tab_agregar() -> None:
    formulario(None)


def tab_importar() -> None:
    st.write("Pega el contenido de tu documento de texto o súbelo. Reconoce `NOMBRE=clave`, `Nombre: clave` "
             "y el formato *nombre en una línea, clave en la siguiente*.")
    archivo = st.file_uploader("Archivo .txt / .env", type=["txt", "env", "md", "csv"])
    texto = st.text_area("…o pégalo aquí", height=160, placeholder="OpenAI: sk-proj-...\nGEMINI_API_KEY=AIza...")
    if archivo is not None:
        texto = archivo.getvalue().decode("utf-8", errors="replace")
    if not texto.strip():
        return
    halladas = importar.analizar(texto)
    if not halladas:
        st.warning("No encontré claves en ese texto. Revisa el formato o agrégalas a mano.")
        return
    existentes = {e["clave"] for e in entradas()}
    filas = [{"importar": h["clave"] not in existentes, "nombre": h["nombre"], "servicio": h["servicio"],
              "clave": importar.enmascarar(h["clave"]), "nota": h["nota"] or ("ya está en la bóveda" if h["clave"] in existentes else "")}
             for h in halladas]
    st.caption(f"Encontré {len(halladas)} claves. Corrige nombres y servicios antes de importar.")
    editado = st.data_editor(filas, hide_index=True, width="stretch", key="ed_importar",
                             column_config={"importar": st.column_config.CheckboxColumn("✓", width="small"),
                                            "clave": st.column_config.TextColumn("Clave", disabled=True)})
    elegidas = [(h, f) for h, f in zip(halladas, editado) if f["importar"]]
    if st.button(f"Importar {len(elegidas)} cifradas", type="primary", width="stretch", disabled=not elegidas):
        nuevas = [bv.nueva_entrada(f["nombre"] or h["nombre"], h["clave"], f["servicio"] or "", nota=f["nota"] or "")
                  for h, f in elegidas]
        if modificar(lambda b: bv.guardar_entradas(b, ss.dek, bv.leer_entradas(b, ss.dek) + nuevas)):
            ss.pop("ed_importar", None)
            st.success(f"Listo: {len(nuevas)} claves cifradas. Cuando confirmes que están todas, **borra el archivo de "
                       "texto original** (y vacía la papelera).")


def _qr_png(texto: str) -> bytes:
    import qrcode
    img = qrcode.make(texto, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def tab_seguridad() -> None:
    cfg = rapido_cfg()
    n_pk = len(cfg["passkeys"]) if cfg else 0
    est = [("Guardado en", ALMACEN.nombre), ("Bloqueo automático", f"{MINUTOS_BLOQUEO:g} min"),
           ("Face ID / huella", f"{n_pk} dispositivo(s)" if n_pk else "—"),
           ("Código MFA", "Activo" if cfg and cfg["totp"] else "—"), ("PIN", "Activo" if cfg and cfg["pin"] else "—"),
           ("Desbloqueo rápido", "Disponible" if cfg else "No disponible")]
    st.html('<div class="ls-estado">' + "".join(f'<div><small>{escape(a)}</small><b>{escape(b)}</b></div>' for a, b in est)
            + '</div>')
    if cfg is None:
        st.warning(f"El desbloqueo rápido necesita la llave del servidor ({ORIGEN_LLAVE}). Mira el README.")
        seccion_password()
        seccion_respaldo()
        return

    def guardar_cfg(fn) -> bool:
        def cambio(b):
            c = bv.leer_rapido(b, LLAVE_SRV)
            fn(c)
            bv.guardar_rapido(b, LLAVE_SRV, c)
        return modificar(cambio)

    # --- Face ID / huella ---
    with st.expander("👆 Face ID / huella / Windows Hello (passkey)", expanded=MOVIL and not n_pk):
        rp_id, origen, motivo = passkey.rp_y_origen(CFG)
        for p in cfg["passkeys"]:
            c1, c2 = st.columns([4, 1])
            c1.markdown(f"**{p['nombre']}** · `{p['rp']}`  \n<small>registrada {time.strftime('%d/%m/%Y', time.localtime(p['creado']))}"
                        + (f" · último uso {time.strftime('%d/%m %H:%M', time.localtime(p['usado']))}" if p.get("usado") else "")
                        + "</small>", unsafe_allow_html=True)
            if c2.button("Quitar", key=f"qpk_{p['id']}", width="stretch"):
                pid = p["id"]
                if guardar_cfg(lambda c: c.update(passkeys=[x for x in c["passkeys"] if x["id"] != pid])):
                    st.rerun()
        if not rp_id:
            st.info(motivo)
        else:
            st.caption(f"Se registra para este dominio: **{rp_id}**. Una passkey creada en localhost no sirve en la app publicada: "
                       "regístrala desde cada dirección y cada dispositivo que uses.")
            disp = st.text_input("Nombre del dispositivo", value="iPhone" if "iPhone" in UA else
                                 ("Android" if "Android" in UA else "Laptop"), key="pk_nombre")
            if "reto_reg" not in ss:
                ss.reto_reg = passkey.opciones_registro(rp_id, [p for p in cfg["passkeys"] if p.get("rp") == rp_id])
            opciones, reto = ss.reto_reg
            r = passkey.boton("registrar", opciones, reto, f"Registrar {NOMBRE_BIO} en este dispositivo", key="pk_reg")
            if r:
                ss.pop("reto_reg", None)
                try:
                    nueva = passkey.verificar_registro(r["credencial"], reto, rp_id, origen, disp.strip() or "Dispositivo")
                except Exception as e:  # noqa: BLE001
                    st.error(f"No se pudo registrar: {e}")
                else:
                    if guardar_cfg(lambda c: c["passkeys"].append(nueva)):
                        st.success(f"{NOMBRE_BIO} registrado. Ya puedes desbloquear con él.")
                        st.rerun()

    # --- Código MFA (TOTP) ---
    with st.expander("🔢 Código MFA (Google Authenticator, Microsoft Authenticator, 1Password…)"):
        if cfg["totp"]:
            st.success("Activo.")
            if st.button("Desactivar código MFA", key="totp_off"):
                if guardar_cfg(lambda c: c.update(totp=None, totp_ultimo=0)):
                    st.rerun()
        else:
            import pyotp
            if "totp_nuevo" not in ss:
                ss.totp_nuevo = pyotp.random_base32()
            uri = pyotp.TOTP(ss.totp_nuevo).provisioning_uri(name="Bóveda", issuer_name="LlaveSegura")
            st.write("1. Escanea el QR con tu app autenticadora (o copia la clave). 2. Escribe el código que te muestra.")
            c1, c2 = st.columns([1, 1.4])
            c1.image(_qr_png(uri), width=200)
            with c2:
                st.code(ss.totp_nuevo, language=None)
                st.markdown(f"[Abrir en la app autenticadora de este teléfono]({uri})")
            with st.form("f_totp_alta", clear_on_submit=True):
                cod = st.text_input("Código de 6 dígitos", max_chars=6, key="num_totp_alta")
                ok = st.form_submit_button("Activar", width="stretch")
            if ok:
                prueba = {"totp": ss.totp_nuevo, "totp_ultimo": 0}
                cont = bv.totp_correcto(prueba, cod)
                if cont is None:
                    st.error("Código incorrecto. Revisa que la hora del teléfono sea automática.")
                else:
                    sec = ss.totp_nuevo
                    if guardar_cfg(lambda c: c.update(totp=sec, totp_ultimo=cont)):
                        ss.pop("totp_nuevo", None)
                        st.success("Código MFA activado.")
                        st.rerun()

    # --- PIN ---
    with st.expander("🔟 PIN de 6 dígitos"):
        st.caption("El más cómodo y el menos fuerte: tras 5 fallos hay esperas crecientes y con 10 solo vale la contraseña maestra.")
        with st.form("f_pin_alta", clear_on_submit=True):
            p1 = st.text_input("Nuevo PIN", type="password", max_chars=6, key="num_pin1")
            p2 = st.text_input("Repítelo", type="password", max_chars=6, key="num_pin2")
            ok = st.form_submit_button("Guardar PIN" if not cfg["pin"] else "Cambiar PIN", width="stretch")
        if ok:
            if p1 != p2:
                st.error("No coinciden.")
            else:
                try:
                    h = bv.hash_pin(p1)
                except ValueError as e:
                    st.error(str(e))
                else:
                    if guardar_cfg(lambda c: c.update(pin=h)):
                        st.success("PIN guardado.")
        if cfg["pin"] and st.button("Quitar PIN", key="pin_off"):
            if guardar_cfg(lambda c: c.update(pin=None)):
                st.rerun()

    seccion_password()
    seccion_respaldo()


def seccion_password() -> None:
    with st.expander("🔑 Cambiar contraseña maestra"):
        with st.form("f_cambio", clear_on_submit=True):
            actual = st.text_input("Contraseña actual", type="password")
            n1 = st.text_input("Nueva", type="password")
            n2 = st.text_input("Repite la nueva", type="password")
            ok = st.form_submit_button("Cambiar", width="stretch")
        if ok:
            try:
                bv.abrir_con_password(ss.boveda, actual)
            except bv.ClaveIncorrecta:
                st.error("La contraseña actual no es correcta.")
                return
            if n1 != n2:
                st.error("Las nuevas no coinciden.")
            elif len(n1) < bv.MIN_PASSWORD:
                st.error(f"Usa al menos {bv.MIN_PASSWORD} caracteres.")
            elif modificar(lambda b: bv.cambiar_password(b, ss.dek, n1)):
                st.success("Contraseña maestra cambiada.")


def seccion_respaldo() -> None:
    with st.expander("💾 Respaldo y exportar"):
        st.download_button("Descargar respaldo cifrado (.json)", json.dumps(ss.boveda, indent=1),
                           file_name=f"llavesegura-respaldo-{time.strftime('%Y%m%d')}.json", mime="application/json",
                           width="stretch")
        st.caption("El respaldo sigue cifrado: se abre con tu contraseña maestra. Guárdalo fuera de la nube si quieres.")
        with st.form("f_env"):
            pw = st.text_input("Contraseña maestra para exportar en texto plano (.env)", type="password")
            ok = st.form_submit_button("Preparar .env", width="stretch")
        if ok:
            try:
                bv.abrir_con_password(ss.boveda, pw)
                ss.env_listo = importar.a_env(entradas())
            except bv.ClaveIncorrecta:
                st.error("Contraseña incorrecta.")
        if ss.get("env_listo"):
            if st.download_button("⚠️ Descargar .env (SIN cifrar)", ss.env_listo, file_name="claves.env",
                                  width="stretch"):
                ss.pop("env_listo", None)


def pantalla_boveda() -> None:
    ss.ultimo = time.time()
    vigilante()
    with st.container(key="barra"):
        c1, c2 = st.columns([3, 1])
        c1.html(f'<div class="pp-label" style="color:var(--pp-ok)">● Desbloqueada · {len(entradas())} claves</div>')
        if c2.button("🔒 Bloquear", width="stretch"):
            bloquear("Bóveda bloqueada.")
            st.rerun()
    t1, t2, t3, t4 = st.tabs(["🔑 Mis llaves", "➕ Agregar", "📥 Importar", "⚙️ Seguridad"])
    with t1:
        tab_llaves()
    with t2:
        tab_agregar()
    with t3:
        tab_importar()
    with t4:
        tab_seguridad()


if ss.boveda is None:
    pantalla_crear()
elif not ss.get("dek"):
    pantalla_desbloqueo()
else:
    pantalla_boveda()
estilo_pills.pie("Cifrado AES-256-GCM con scrypt. Tus claves solo se descifran en la memoria de esta sesión; "
                 "se bloquea sola tras unos minutos sin uso.")
