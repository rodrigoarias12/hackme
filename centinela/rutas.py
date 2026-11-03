"""Rutas y perillas de Centinela. Todo lo configurable vive acá."""
import os
import subprocess
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
ESTADO = RAIZ / "estado"   # lo de una sola ronda; se borra sin perder nada
ESPEJO = ESTADO / "espejo"  # copia liviana de los repos que escanea Aguara

GITHUB = Path(os.environ.get("CENTINELA_GITHUB", Path.home() / "Documents" / "GitHub"))
AGUARA = os.environ.get("CENTINELA_AGUARA", str(Path.home() / "go" / "bin" / "aguara"))

# Dónde corre esta ronda:
#   todo -> los repos y la Mac (una corrida a mano en la Mac)
#   nube -> la rutina en la nube de Claude: solo los repos clonados de GitHub, sin Mac
#   mac  -> la tarea local: la Mac y las carpetas que no tienen remoto (la nube no las ve)
MODO = os.environ.get("CENTINELA_MODO", "todo")

# Informes y memoria entre rondas viven en un repo PRIVADO aparte: dicen qué repo tiene qué
# problema. Este repo (el código) puede ser público; ese nunca.
PRIVADO = Path(os.environ.get("CENTINELA_PRIVADO", GITHUB / "centinela-privado"))
INFORMES = PRIVADO / "informes"
MEMORIA = PRIVADO / "memoria" / MODO  # avisos ya vistos, hallazgos previos, hashes de --monitor

# Carpetas de GITHUB que no son proyectos a revisar.
PROPIOS = {"centinela-privado"}

RADAR_ITEMS = "https://www.oktsec.com/radar/items.json"

# Archivos con secretos: nunca se copian ni se leen. Solo se avisa si están versionados en
# git (por nombre, con `git ls-files`). `.env.example` sí se copia: son nombres sin valores.
SECRETOS = [
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.crt", "*.cer", "id_rsa*", "id_ed25519*",
    "*.keystore", "*.jks", "credentials*.json", "service-account*.json", "*.tfstate", ".npmrc", ".pypirc",
]
INCLUIR_ESPEJO = [".env.example"]

# Lo que no se copia al espejo: secretos, dependencias instaladas, builds, cachés, medios.
# Las dependencias las revisa `aguara check` contra el repo real, no el espejo.
EXCLUIR_ESPEJO = SECRETOS + [
    ".git", "node_modules", ".next", ".venv", "venv", "dist", "build", ".turbo",
    ".vercel", ".cache", "__pycache__", "worktrees", ".aguaraignore", ".aguara.yml",
    "*.mp4", "*.mov", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.pdf",
    "*.zip", "*.sqlite", "*.db", "*.wav", "*.mp3", "*.m4a", "*.ttf", "*.woff*",
]
TAMANO_MAXIMO = "2m"

# Carpetas que nunca se recorren al armar el inventario.
PODAR = {".git", "node_modules", ".next", ".venv", "venv", "dist", "build", ".turbo",
         ".vercel", ".cache", "__pycache__", "worktrees", "site-packages"}

# Apagado hasta que Rodrigo lo autorice: abrir issues en los repos con hallazgos. Las alertas
# van como issues al repo privado de Centinela, nunca a los repos revisados.
ABRIR_ISSUES = False


def _tiene_remoto(carpeta):
    r = subprocess.run(["git", "-C", str(carpeta), "remote", "get-url", "origin"],
                       capture_output=True, text=True)
    return r.returncode == 0 and bool(r.stdout.strip())


def repos():
    """Las carpetas de GITHUB que revisa esta ronda, según el MODO."""
    todas = sorted(p for p in GITHUB.iterdir()
                   if p.is_dir() and not p.name.startswith(".") and p.name not in PROPIOS)
    if MODO == "mac":
        return [p for p in todas if not _tiene_remoto(p)]
    return todas
