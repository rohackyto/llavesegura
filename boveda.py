"""Núcleo criptográfico de LlaveSegura (sin Streamlit, probado en test_boveda.py).

Modelo (cifrado de sobre):
- DEK: llave aleatoria de 256 bits que cifra la lista de API keys (AES-256-GCM).
- La DEK se guarda envuelta dos veces:
    dek_pw  -> con una llave derivada de tu contraseña maestra (scrypt). Siempre funciona.
    dek_srv -> con la LLAVE DEL SERVIDOR (secreto de Streamlit / archivo local). Permite el
               desbloqueo rápido (Face ID / huella, código MFA, PIN) sin escribir la contraseña.
- La configuración del desbloqueo rápido (secreto TOTP, hash del PIN, passkeys) va cifrada
  con la llave del servidor (AES-GCM también impide que alguien la altere).
- Bloqueo por intentos fallidos guardado en la bóveda (sobrevive a recargas y dispositivos).

Sin la contraseña maestra, o sin (llave del servidor + factor rápido), los datos no se leen.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VERSION = 1
SCRYPT = {"n": 2**15, "r": 8, "p": 1}
MIN_PASSWORD = 10
FALLOS_SIN_ESPERA = 4          # del 5.º fallo en adelante hay espera creciente
FALLOS_MAX_RAPIDO = 10         # con 10 fallos seguidos solo vale la contraseña maestra
ESPERA_BASE, ESPERA_MAX = 30, 3600


class ClaveIncorrecta(Exception):
    """Contraseña, PIN o código incorrecto (o datos alterados)."""


class SinLlaveServidor(Exception):
    """El desbloqueo rápido necesita la llave del servidor y no está configurada o no coincide."""


# ---------- utilidades ----------
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def nueva_llave_servidor() -> str:
    return _b64(secrets.token_bytes(32))


def llave_desde_texto(texto: str | None) -> bytes | None:
    if not texto:
        return None
    try:
        k = _unb64(texto.strip())
    except Exception as e:  # noqa: BLE001
        raise ValueError("LLAVE_SERVIDOR no es base64 válido") from e
    if len(k) != 32:
        raise ValueError("LLAVE_SERVIDOR debe tener 32 bytes (44 caracteres base64)")
    return k


def _cifrar(llave: bytes, datos: bytes, aad: bytes) -> dict:
    nonce = os.urandom(12)
    return {"nonce": _b64(nonce), "ct": _b64(AESGCM(llave).encrypt(nonce, datos, aad))}


def _descifrar(llave: bytes, caja: dict, aad: bytes) -> bytes:
    try:
        return AESGCM(llave).decrypt(_unb64(caja["nonce"]), _unb64(caja["ct"]), aad)
    except Exception as e:  # noqa: BLE001  (InvalidTag, base64, etc.)
        raise ClaveIncorrecta from e


def _derivar(password: str, kdf: dict) -> bytes:
    return Scrypt(salt=_unb64(kdf["salt"]), length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(
        password.encode("utf-8"))


def ahora() -> float:
    return time.time()


# ---------- crear / desbloquear ----------
def crear(password: str, llave_srv: bytes | None) -> tuple[dict, bytes]:
    """Bóveda nueva y vacía. Devuelve (bóveda, dek)."""
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"La contraseña maestra debe tener al menos {MIN_PASSWORD} caracteres")
    dek = AESGCM.generate_key(256)
    kdf = {"salt": _b64(os.urandom(16)), **SCRYPT}
    b = {"v": VERSION, "creada": ahora(), "kdf": kdf,
         "dek_pw": _cifrar(_derivar(password, kdf), dek, b"dek_pw"),
         "dek_srv": None, "rapido": None, "bloqueo": {"fallos": 0, "hasta": 0}, "datos": None}
    guardar_entradas(b, dek, [])
    if llave_srv:
        envolver_servidor(b, dek, llave_srv)
    return b, dek


def abrir_con_password(b: dict, password: str) -> bytes:
    return _descifrar(_derivar(password, b["kdf"]), b["dek_pw"], b"dek_pw")


def abrir_rapido(b: dict, llave_srv: bytes | None) -> bytes:
    """DEK vía llave del servidor. Llamar SOLO después de verificar el factor rápido."""
    if not llave_srv or not b.get("dek_srv"):
        raise SinLlaveServidor
    try:
        return _descifrar(llave_srv, b["dek_srv"], b"dek_srv")
    except ClaveIncorrecta as e:
        raise SinLlaveServidor from e


def envolver_servidor(b: dict, dek: bytes, llave_srv: bytes) -> None:
    """(Re)crea dek_srv. Si la llave del servidor cambió, la config rápida anterior se pierde."""
    b["dek_srv"] = _cifrar(llave_srv, dek, b"dek_srv")
    try:
        leer_rapido(b, llave_srv)
    except SinLlaveServidor:
        b["rapido"] = None
    if b.get("rapido") is None:
        guardar_rapido(b, llave_srv, rapido_vacio())


def llave_servidor_vigente(b: dict, llave_srv: bytes | None) -> bool:
    try:
        abrir_rapido(b, llave_srv)
        return True
    except SinLlaveServidor:
        return False


def cambiar_password(b: dict, dek: bytes, nueva: str) -> None:
    if len(nueva) < MIN_PASSWORD:
        raise ValueError(f"La contraseña maestra debe tener al menos {MIN_PASSWORD} caracteres")
    kdf = {"salt": _b64(os.urandom(16)), **SCRYPT}
    b["kdf"], b["dek_pw"] = kdf, _cifrar(_derivar(nueva, kdf), dek, b"dek_pw")


# ---------- entradas (API keys) ----------
def leer_entradas(b: dict, dek: bytes) -> list[dict]:
    return json.loads(_descifrar(dek, b["datos"], b"datos"))


def guardar_entradas(b: dict, dek: bytes, entradas: list[dict]) -> None:
    b["datos"] = _cifrar(dek, json.dumps(entradas, ensure_ascii=False).encode("utf-8"), b"datos")


def nueva_entrada(nombre: str, clave: str, servicio: str = "", url: str = "", nota: str = "",
                  etiquetas: list[str] | None = None) -> dict:
    t = ahora()
    return {"id": uuid.uuid4().hex, "nombre": nombre.strip(), "clave": clave.strip(), "servicio": servicio.strip(),
            "url": url.strip(), "nota": nota.strip(), "etiquetas": etiquetas or [], "creado": t, "actualizado": t}


# ---------- desbloqueo rápido ----------
def rapido_vacio() -> dict:
    return {"totp": None, "totp_ultimo": 0, "pin": None, "passkeys": []}


def leer_rapido(b: dict, llave_srv: bytes | None) -> dict:
    if not llave_srv:
        raise SinLlaveServidor
    if not b.get("rapido"):
        return rapido_vacio()
    try:
        return json.loads(_descifrar(llave_srv, b["rapido"], b"rapido"))
    except ClaveIncorrecta as e:
        raise SinLlaveServidor from e


def guardar_rapido(b: dict, llave_srv: bytes, cfg: dict) -> None:
    b["rapido"] = _cifrar(llave_srv, json.dumps(cfg).encode(), b"rapido")


def hash_pin(pin: str) -> dict:
    if not (len(pin) == 6 and pin.isdigit()):
        raise ValueError("El PIN debe tener exactamente 6 dígitos")
    if len(set(pin)) == 1 or pin in "0123456789" or pin in "9876543210":
        raise ValueError("Ese PIN es muy fácil de adivinar (repetido o consecutivo)")
    kdf = {"salt": _b64(os.urandom(16)), **SCRYPT}
    return {**kdf, "hash": _b64(_derivar(pin, kdf))}


def pin_correcto(cfg: dict, pin: str) -> bool:
    p = cfg.get("pin")
    return bool(p) and hmac.compare_digest(_derivar(pin, p), _unb64(p["hash"]))


def totp_correcto(cfg: dict, codigo: str, t: float | None = None) -> int | None:
    """Devuelve el contador TOTP usado si el código es válido (±30 s) y no se reutilizó; si no, None."""
    import pyotp
    if not cfg.get("totp"):
        return None
    codigo = codigo.strip().replace(" ", "")
    t = ahora() if t is None else t
    totp = pyotp.TOTP(cfg["totp"])
    for desfase in (0, -1, 1):
        cont = int(t // 30) + desfase
        if cont > cfg.get("totp_ultimo", 0) and hmac.compare_digest(totp.at(cont * 30), codigo):
            return cont
    return None


# ---------- intentos fallidos ----------
def espera_restante(b: dict, t: float | None = None) -> int:
    t = ahora() if t is None else t
    return max(0, int(b.get("bloqueo", {}).get("hasta", 0) - t + 0.999))


def rapido_bloqueado(b: dict) -> bool:
    return b.get("bloqueo", {}).get("fallos", 0) >= FALLOS_MAX_RAPIDO


def registrar_fallo(b: dict, t: float | None = None) -> None:
    t = ahora() if t is None else t
    bl = b.setdefault("bloqueo", {"fallos": 0, "hasta": 0})
    bl["fallos"] = bl.get("fallos", 0) + 1
    extra = bl["fallos"] - FALLOS_SIN_ESPERA
    if extra > 0:
        bl["hasta"] = t + min(ESPERA_MAX, ESPERA_BASE * 2 ** (extra - 1))


def registrar_exito(b: dict) -> None:
    b["bloqueo"] = {"fallos": 0, "hasta": 0}


def huella(b: dict) -> str:
    """Huella corta de la bóveda (para detectar si otro dispositivo la cambió)."""
    return hashlib.sha256(json.dumps(b, sort_keys=True).encode()).hexdigest()[:12]
