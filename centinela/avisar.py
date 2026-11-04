"""Mandar un aviso por Telegram. Lo usan `bin/avisar` y el vigía.

Lee TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID del ambiente o de ~/.config/centinela/telegram.env
(líneas CLAVE=valor; ese archivo no vive en ningún repo).
"""
import json
import os
import urllib.parse
import urllib.request
from pathlib import Path

ARCHIVO = Path.home() / ".config" / "centinela" / "telegram.env"


def leer_env(archivo, claves):
    """Completa `claves` con el ambiente y, lo que falte, con un archivo CLAVE=valor."""
    valores = {k: os.environ.get(k) for k in claves}
    if not all(valores.values()) and archivo.exists():
        for linea in archivo.read_text().splitlines():
            clave, _, valor = linea.partition("=")
            if clave.strip() in valores and not valores[clave.strip()]:
                valores[clave.strip()] = valor.strip().strip('"\'')
    return valores


def config():
    v = leer_env(ARCHIVO, ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"))
    return v["TELEGRAM_BOT_TOKEN"], v["TELEGRAM_CHAT_ID"]


def mandar(texto):
    """True si Telegram lo aceptó, False si falló, None si no está configurado.

    Texto plano y sin preview de links: los avisos traen rutas y user agents que elige quien ataca.
    """
    token, chat = config()
    if not token or not chat:
        return None
    datos = urllib.parse.urlencode({"chat_id": chat, "text": texto[:4000], "disable_web_page_preview": "true"}).encode()
    try:
        with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", datos, timeout=30) as r:
            return bool(json.load(r).get("ok"))
    except Exception:  # nunca mostrar la excepción: la URL lleva el token
        return False
