"""Dónde se guarda la bóveda cifrada: archivo local (laptop) o un repo PRIVADO de GitHub (Streamlit Cloud).

Streamlit Cloud borra el disco cada vez que la app se reinicia, por eso en la nube la bóveda
(ya cifrada) se guarda como un archivo JSON en un repositorio privado vía la API de GitHub.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import requests


class Conflicto(Exception):
    """La bóveda cambió desde otro dispositivo después de cargarla."""


class ErrorAlmacen(Exception):
    pass


class AlmacenLocal:
    nombre = "archivo local"

    def __init__(self, ruta: Path):
        self.ruta = Path(ruta)

    def cargar(self) -> tuple[dict | None, str | None]:
        if not self.ruta.exists():
            return None, None
        texto = self.ruta.read_text(encoding="utf-8")
        return json.loads(texto), str(self.ruta.stat().st_mtime_ns)

    def guardar(self, boveda: dict, version: str | None) -> str:
        actual = str(self.ruta.stat().st_mtime_ns) if self.ruta.exists() else None
        if actual != version:
            raise Conflicto
        self.ruta.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.ruta.with_suffix(".tmp")
        tmp.write_text(json.dumps(boveda, indent=1), encoding="utf-8")
        if self.ruta.exists():  # copia de respaldo de la versión anterior (sigue cifrada)
            self.ruta.replace(self.ruta.with_suffix(".bak.json"))
        tmp.replace(self.ruta)
        return str(self.ruta.stat().st_mtime_ns)


class AlmacenGitHub:
    nombre = "repo privado de GitHub"
    API = "https://api.github.com"

    def __init__(self, token: str, repo: str, ruta: str = "boveda.json", rama: str = "main"):
        self.repo, self.ruta, self.rama = repo, ruta, rama
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                               "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "llavesegura"})

    def _url(self) -> str:
        return f"{self.API}/repos/{self.repo}/contents/{self.ruta}"

    def cargar(self) -> tuple[dict | None, str | None]:
        r = self.s.get(self._url(), params={"ref": self.rama}, timeout=20)
        if r.status_code == 404:
            return None, None
        if r.status_code != 200:
            raise ErrorAlmacen(f"GitHub respondió {r.status_code}: {r.text[:200]}")
        j = r.json()
        return json.loads(base64.b64decode(j["content"])), j["sha"]

    def guardar(self, boveda: dict, version: str | None) -> str:
        cuerpo = {"message": "Actualiza bóveda cifrada", "branch": self.rama,
                  "content": base64.b64encode(json.dumps(boveda, indent=1).encode()).decode()}
        if version:
            cuerpo["sha"] = version
        r = self.s.put(self._url(), json=cuerpo, timeout=20)
        if r.status_code in (409, 422):  # sha desactualizado: otro dispositivo guardó antes
            raise Conflicto
        if r.status_code not in (200, 201):
            raise ErrorAlmacen(f"GitHub respondió {r.status_code}: {r.text[:200]}")
        return r.json()["content"]["sha"]


def elegir(config: dict, carpeta_app: Path):
    """GITHUB_TOKEN + GITHUB_REPO configurados -> GitHub; si no, archivo local en data/."""
    token, repo = config.get("GITHUB_TOKEN"), config.get("GITHUB_REPO")
    if token and repo:
        return AlmacenGitHub(token, repo, config.get("GITHUB_RUTA", "boveda.json"), config.get("GITHUB_RAMA", "main"))
    return AlmacenLocal(Path(config.get("RUTA_BOVEDA") or carpeta_app / "data" / "boveda.json"))


def leer_config(secretos) -> dict:
    """Une st.secrets (o un dict) con variables de entorno del mismo nombre."""
    claves = ("LLAVE_SERVIDOR", "GITHUB_TOKEN", "GITHUB_REPO", "GITHUB_RUTA", "GITHUB_RAMA", "RUTA_BOVEDA",
              "ORIGEN", "MINUTOS_BLOQUEO")
    out = {}
    for k in claves:
        v = None
        try:
            v = secretos.get(k) if secretos is not None else None
        except Exception:  # noqa: BLE001  (st.secrets sin archivo)
            v = None
        out[k] = v or os.environ.get(k)
    return out
