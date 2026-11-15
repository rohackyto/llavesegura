"""Face ID / huella / Windows Hello con passkeys (WebAuthn).

El navegador pide la biometría y firma un reto; el servidor verifica la firma con la llave
pública registrada (librería `webauthn`). La biometría nunca sale del teléfono.

Requisitos del navegador: HTTPS (Streamlit Cloud) o http://localhost. No funciona por
http://192.168.x.x ni por 127.0.0.1 (WebAuthn exige un dominio).
"""
from __future__ import annotations

import base64
import json
from urllib.parse import urlparse

import streamlit as st
from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

RP_NOMBRE = "LlaveSegura"
USUARIO_ID = b"llavesegura-duenio"


def rp_y_origen(config: dict) -> tuple[str | None, str | None, str]:
    """(rp_id, origen, motivo si no se puede). ORIGEN en secrets fuerza el valor (p. ej. https://x.streamlit.app)."""
    origen = config.get("ORIGEN")
    if not origen:
        url = st.context.url or ""
        u = urlparse(url)
        if not u.scheme or not u.hostname:
            return None, None, "No se pudo leer la dirección de la app."
        origen = f"{u.scheme}://{u.netloc}"
    u = urlparse(origen)
    host = u.hostname or ""
    if host.replace(".", "").isdigit() or ":" in host:
        return None, None, "Face ID / huella no funciona entrando por IP. Usa http://localhost o la app publicada (https)."
    if u.scheme != "https" and host != "localhost":
        return None, None, "Face ID / huella necesita https (la app publicada) o http://localhost."
    return host, origen, ""


def _descriptores(passkeys: list[dict]) -> list[PublicKeyCredentialDescriptor]:
    return [PublicKeyCredentialDescriptor(id=base64url_to_bytes(p["id"])) for p in passkeys]


def opciones_registro(rp_id: str, passkeys: list[dict]) -> tuple[str, str]:
    op = generate_registration_options(
        rp_id=rp_id, rp_name=RP_NOMBRE, user_id=USUARIO_ID, user_name="duenio", user_display_name="Dueño de la bóveda",
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED, user_verification=UserVerificationRequirement.REQUIRED),
        exclude_credentials=_descriptores(passkeys))
    return options_to_json(op), bytes_to_base64url(op.challenge)


def verificar_registro(cred: dict, reto: str, rp_id: str, origen: str, nombre: str) -> dict:
    v = verify_registration_response(credential=cred, expected_challenge=base64url_to_bytes(reto),
                                     expected_rp_id=rp_id, expected_origin=origen, require_user_verification=True)
    import time
    return {"id": bytes_to_base64url(v.credential_id), "pk": base64.b64encode(v.credential_public_key).decode(),
            "cuenta": v.sign_count, "nombre": nombre, "rp": rp_id, "creado": time.time()}


def opciones_entrada(rp_id: str, passkeys: list[dict]) -> tuple[str, str]:
    op = generate_authentication_options(rp_id=rp_id, allow_credentials=_descriptores(passkeys),
                                         user_verification=UserVerificationRequirement.REQUIRED)
    return options_to_json(op), bytes_to_base64url(op.challenge)


def verificar_entrada(cred: dict, reto: str, rp_id: str, origen: str, passkeys: list[dict]) -> dict:
    """Devuelve la passkey usada (con el contador actualizado). Lanza excepción si no es válida."""
    p = next((p for p in passkeys if p["id"] == cred.get("id")), None)
    if p is None:
        raise ValueError("Esta passkey no está registrada en la bóveda")
    v = verify_authentication_response(credential=cred, expected_challenge=base64url_to_bytes(reto),
                                       expected_rp_id=rp_id, expected_origin=origen,
                                       credential_public_key=base64.b64decode(p["pk"]),
                                       credential_current_sign_count=p["cuenta"], require_user_verification=True)
    p["cuenta"] = v.new_sign_count
    return p


# ---------- componente del navegador (Streamlit components v2: corre en la página, no en un iframe) ----------
_HTML = '<div class="pk"><button type="button" class="pk-btn"></button><div class="pk-msg"></div></div>'
_CSS = """
.pk { font-family: var(--pp-body, system-ui, sans-serif); }
.pk-btn { width: 100%; min-height: 3.1rem; border: 0; border-radius: 12px; cursor: pointer;
  font: 700 1rem/1 var(--pp-body, system-ui, sans-serif); color: #081028;
  background: linear-gradient(90deg, #22d3ee, #8b5cf6); box-shadow: 0 10px 26px -12px rgb(34 211 238 / .7); }
.pk-btn:disabled { opacity: .6; cursor: wait; }
.pk-msg { color: #f87171; font-size: .85rem; margin-top: .45rem; min-height: 1rem; }
"""
_JS = r"""
const dec = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer; };
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const ERRORES = { NotAllowedError: 'Cancelado o tiempo agotado. Vuelve a intentarlo.',
  InvalidStateError: 'Este dispositivo ya está registrado.', SecurityError: 'El navegador bloqueó la operación (dominio o https).',
  NotSupportedError: 'Este navegador no soporta passkeys.' };

export default function (component) {
  const { data, setTriggerValue, parentElement } = component;
  const btn = parentElement.querySelector('.pk-btn');
  const msg = parentElement.querySelector('.pk-msg');
  btn.textContent = data.texto;
  btn.disabled = false;
  if (!window.PublicKeyCredential) { msg.textContent = 'Este navegador no soporta passkeys.'; btn.disabled = true; return; }
  btn.onclick = async () => {
    msg.textContent = ''; btn.disabled = true;
    try {
      const o = JSON.parse(data.opciones);
      o.challenge = dec(o.challenge);
      (o.excludeCredentials || []).forEach(c => c.id = dec(c.id));
      (o.allowCredentials || []).forEach(c => c.id = dec(c.id));
      let salida;
      if (data.modo === 'registrar') {
        o.user.id = dec(o.user.id);
        const c = await navigator.credentials.create({ publicKey: o });
        salida = { id: c.id, rawId: enc(c.rawId), type: c.type, authenticatorAttachment: c.authenticatorAttachment,
          clientExtensionResults: c.getClientExtensionResults(),
          response: { clientDataJSON: enc(c.response.clientDataJSON), attestationObject: enc(c.response.attestationObject),
            transports: c.response.getTransports ? c.response.getTransports() : [] } };
      } else {
        const c = await navigator.credentials.get({ publicKey: o });
        salida = { id: c.id, rawId: enc(c.rawId), type: c.type, authenticatorAttachment: c.authenticatorAttachment,
          clientExtensionResults: c.getClientExtensionResults(),
          response: { clientDataJSON: enc(c.response.clientDataJSON), authenticatorData: enc(c.response.authenticatorData),
            signature: enc(c.response.signature), userHandle: c.response.userHandle ? enc(c.response.userHandle) : null } };
      }
      setTriggerValue('resultado', JSON.stringify({ reto: data.reto, credencial: salida }));
    } catch (e) {
      msg.textContent = ERRORES[e.name] || ('Error: ' + (e.message || e.name));
      btn.disabled = false;
    }
  };
}
"""
_componente = st.components.v2.component("llavesegura_passkey", html=_HTML, css=_CSS, js=_JS)


def boton(modo: str, opciones_json: str, reto: str, texto: str, key: str) -> dict | None:
    """Muestra el botón. Devuelve {'reto', 'credencial'} en la ejecución en que el usuario completó la biometría."""
    r = _componente(key=key, data={"modo": modo, "opciones": opciones_json, "reto": reto, "texto": texto},
                    on_resultado_change=lambda: None)
    valor = getattr(r, "resultado", None)
    if not valor:
        return None
    try:
        out = json.loads(valor)
    except (TypeError, ValueError):
        return None
    return out if out.get("reto") == reto else None
