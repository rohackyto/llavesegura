"""Lee tu archivo de texto actual de API keys y propone entradas (nombre, clave, servicio).

Formatos que reconoce (se pueden mezclar en el mismo archivo):
    OPENAI_API_KEY=sk-...                 (estilo .env, también con "export" y comillas)
    OpenAI: sk-...      OpenAI - sk-...   OpenAI | sk-...   OpenAI -> sk-...
    OpenAI                                 (un nombre en una línea...)
    sk-...                                 (...y la clave en la siguiente)
Las líneas que empiezan con # o // se toman como nota de la entrada siguiente.
"""
from __future__ import annotations

import re

SEPARADORES = re.compile(r"^\s*(?:export\s+)?(?P<nombre>[^=:|\t]{1,80}?)\s*(?:=|:|\||\t|->|=>|\s-\s)\s*(?P<clave>\S.*?)\s*$")

# servicio conocido por prefijo de la clave o palabra en el nombre
PREFIJOS = [
    ("sk-ant-", "Anthropic"), ("sk-proj-", "OpenAI"), ("sk-or-", "OpenRouter"), ("sk-", "OpenAI"),
    ("AIza", "Google"), ("ghp_", "GitHub"), ("github_pat_", "GitHub"), ("gho_", "GitHub"),
    ("xoxb-", "Slack"), ("xoxp-", "Slack"), ("AKIA", "AWS"), ("sk_live_", "Stripe"), ("sk_test_", "Stripe"),
    ("pk_live_", "Stripe"), ("SG.", "SendGrid"), ("hf_", "Hugging Face"), ("gsk_", "Groq"), ("glpat-", "GitLab"),
    ("r8_", "Replicate"), ("pplx-", "Perplexity"), ("ntn_", "Notion"), ("secret_", "Notion"), ("re_", "Resend"),
]
PALABRAS = ["Anthropic", "Claude", "OpenAI", "Gemini", "Google", "GitHub", "Azure", "AWS", "Stripe", "Supabase",
            "Firebase", "Twilio", "SendGrid", "Mapbox", "YouTube", "Notion", "Slack", "Telegram", "Groq", "Mistral",
            "DeepSeek", "Hugging Face", "OpenRouter", "Perplexity", "Cohere", "ElevenLabs", "Resend", "n8n",
            "Cloudflare", "Vercel", "Netlify", "Pinecone", "Replicate", "Brevo", "Mailgun", "Unsplash", "Canva"]


def parece_clave(texto: str) -> bool:
    t = texto.strip().strip("\"'")
    if len(t) < 16 or " " in t:
        return False
    if any(t.startswith(p) for p, _ in PREFIJOS):
        return True
    clases = sum(bool(re.search(p, t)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[-_.]"))
    return clases >= 2 and len(t) >= 20


def adivinar_servicio(nombre: str, clave: str) -> str:
    for p, s in PREFIJOS:
        if clave.startswith(p):
            return s
    bajo = nombre.lower().replace("_", " ")
    for s in PALABRAS:
        if s.lower() in bajo:
            return "Anthropic" if s == "Claude" else s
    return ""


def _limpiar_nombre(n: str) -> str:
    n = n.strip().strip("-*•·").strip()
    return re.sub(r"\s+", " ", n)


def analizar(texto: str) -> list[dict]:
    """Devuelve [{nombre, clave, servicio, nota}] en el orden del archivo, sin duplicados exactos."""
    salida: list[dict] = []
    vistos: set[str] = set()
    pendiente_nombre: str | None = None
    nota: list[str] = []

    def agregar(nombre: str, clave: str) -> None:
        nonlocal nota
        clave = clave.strip().strip("\"'")
        if not clave or clave in vistos:
            return
        vistos.add(clave)
        nombre = _limpiar_nombre(nombre) or f"Clave {len(salida) + 1}"
        salida.append({"nombre": nombre, "clave": clave, "servicio": adivinar_servicio(nombre, clave),
                       "nota": " ".join(nota).strip()})
        nota = []

    for linea in texto.replace("\r\n", "\n").split("\n"):
        s = linea.strip()
        if not s:
            continue
        if s.startswith(("#", "//")):
            nota.append(s.lstrip("#/ ").strip())
            continue
        m = SEPARADORES.match(s)
        if m and parece_clave(m.group("clave")) and not parece_clave(m.group("nombre")):
            agregar(m.group("nombre"), m.group("clave"))
            pendiente_nombre = None
        elif parece_clave(s):
            agregar(pendiente_nombre or "", s)
            pendiente_nombre = None
        else:
            pendiente_nombre = s.rstrip(":").strip()
    return salida


def enmascarar(clave: str) -> str:
    if len(clave) <= 8:
        return "•" * len(clave)
    return f"{clave[:4]}••••••{clave[-4:]}"


def a_env(entradas: list[dict]) -> str:
    """Exporta como .env (NOMBRE_EN_MAYUSCULAS=clave)."""
    lineas = []
    for e in entradas:
        var = re.sub(r"[^A-Za-z0-9]+", "_", e["nombre"]).strip("_").upper() or "CLAVE"
        lineas.append(f"{var}={e['clave']}")
    return "\n".join(lineas) + "\n"
