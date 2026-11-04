"""Inventario de todo lo que corre el dueño: cada repo de ~/Documents/GitHub y la Mac.

Solo lee. De los repos saca dependencias declaradas y lockeadas, imágenes de Docker,
actions de GitHub, servidores MCP y pistas de servicios (Vercel, Railway, …). De la Mac,
apps, brew, extensiones de editores, runtimes y MCPs configurados.

Nunca abre un `.env` real: de las variables solo mira los nombres en `.env.example`.
"""
import json
import os
import plistlib
import re
import subprocess
from pathlib import Path

from . import rutas

LOCKS = {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock",
         "requirements.txt", "pyproject.toml", "uv.lock", "poetry.lock", "go.mod",
         "Dockerfile", "docker-compose.yml", "compose.yml", ".mcp.json", ".env.example"}

# Archivos cuya sola presencia dice en qué servicio corre el repo.
PISTAS_SERVICIO = {
    "vercel.json": "vercel", ".vercel": "vercel", "railway.json": "railway",
    "railway.toml": "railway", "fly.toml": "fly.io", "netlify.toml": "netlify",
    "supabase": "supabase", "wrangler.toml": "cloudflare", "render.yaml": "render",
    "serverless.yml": "aws", "cdk.json": "aws", "app.yaml": "google cloud",
}


def _leer(p):
    try:
        return p.read_text(errors="replace")
    except OSError:
        return ""


def _sumar(destino, eco, nombre, version, donde):
    nombre = nombre.strip().strip('"\'')
    if not nombre or len(nombre) > 214:
        return
    destino.setdefault(eco, {}).setdefault(nombre.lower(), {"nombre": nombre, "versiones": {}})
    destino[eco][nombre.lower()]["versiones"].setdefault(version or "?", []).append(donde)


def _npm(p, rel, pkgs):
    if p.name == "package.json":
        try:
            d = json.loads(_leer(p))
        except ValueError:
            return
        for campo in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for n, v in (d.get(campo) or {}).items():
                _sumar(pkgs, "npm", n, str(v), rel)
    elif p.name == "package-lock.json":
        try:
            d = json.loads(_leer(p))
        except ValueError:
            return
        for clave, info in (d.get("packages") or {}).items():
            if "node_modules/" in clave and isinstance(info, dict):
                _sumar(pkgs, "npm", clave.rsplit("node_modules/", 1)[1], info.get("version"), rel)
    elif p.name == "pnpm-lock.yaml":
        # "  /next@15.1.0:" (v6) o "  next@15.1.0:" / "  '@scope/x@1.2.3':" (v9)
        for m in re.finditer(r"^\s{2}'?/?((?:@[^/@\s]+/)?[^@\s/']+)@(\d[^:('\s]*)", _leer(p), re.M):
            _sumar(pkgs, "npm", m.group(1), m.group(2), rel)
    elif p.name == "yarn.lock":
        for m in re.finditer(r'^"?((?:@[^/@\s]+/)?[^@\s"]+)@[^\n]*\n\s+version:?\s+"?([^"\n]+)', _leer(p), re.M):
            _sumar(pkgs, "npm", m.group(1), m.group(2), rel)
    elif p.name == "bun.lock":
        for m in re.finditer(r'"((?:@[^/@"\s]+/)?[^@"\s/]+)@(\d[^"]*)"', _leer(p)):
            _sumar(pkgs, "npm", m.group(1), m.group(2), rel)


def _python(p, rel, pkgs):
    texto = _leer(p)
    if p.name.startswith("requirements"):  # requirements.txt, requirements-dev.txt, …
        for linea in texto.splitlines():
            m = re.match(r"\s*([A-Za-z0-9_.\-\[\]]+)\s*(?:[=<>!~]=?\s*([^\s;#,]+))?", linea)
            if m and not linea.strip().startswith(("#", "-")):
                _sumar(pkgs, "pypi", m.group(1).split("[")[0], m.group(2), rel)
    elif p.name == "pyproject.toml":
        for m in re.finditer(r'^\s*"([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*([=<>!~]=?\s*[^",;]+)?', texto, re.M):
            _sumar(pkgs, "pypi", m.group(1), (m.group(2) or "").replace(" ", "") or None, rel)
    elif p.name in ("uv.lock", "poetry.lock"):
        for m in re.finditer(r'^name = "([^"]+)"\nversion = "([^"]+)"', texto, re.M):
            _sumar(pkgs, "pypi", m.group(1), m.group(2), rel)


def _go(p, rel, pkgs):
    for m in re.finditer(r"^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]+/[^\s]+)\s+(v[^\s]+)", _leer(p), re.M):
        _sumar(pkgs, "go", m.group(1), m.group(2), rel)


def repo(carpeta):
    """Todo lo que se puede saber de un repo sin ejecutar nada de él."""
    pkgs, imagenes, acciones, mcp, servicios, variables = {}, set(), set(), set(), set(), set()
    for actual, dirs, archivos in os.walk(carpeta):
        dirs[:] = [d for d in dirs if d not in rutas.PODAR]
        aqui = Path(actual)
        if len(aqui.relative_to(carpeta).parts) > 5:
            dirs[:] = []
        for nombre in list(dirs) + archivos:
            if nombre in PISTAS_SERVICIO:
                servicios.add(PISTAS_SERVICIO[nombre])
        if aqui.name == "workflows" and aqui.parent.name == ".github":
            for a in archivos:
                for m in re.finditer(r"uses:\s*['\"]?([^\s'\"#]+)", _leer(aqui / a)):
                    acciones.add(m.group(1))
        for a in archivos:
            if a not in LOCKS and not a.startswith("requirements") and not a.startswith("Dockerfile"):
                continue
            p = aqui / a
            rel = str(p.relative_to(carpeta))
            if a in ("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"):
                _npm(p, rel, pkgs)
            elif (a.startswith("requirements") and a.endswith(".txt")) or a in ("pyproject.toml", "uv.lock", "poetry.lock"):
                _python(p, rel, pkgs)
            elif a == "go.mod":
                _go(p, rel, pkgs)
            elif a.startswith("Dockerfile") or a in ("docker-compose.yml", "compose.yml"):
                for m in re.finditer(r"^\s*(?:FROM|image:)\s+(?:--platform=\S+\s+)?['\"]?([^\s'\"]+)", _leer(p), re.M | re.I):
                    imagenes.add(m.group(1))
            elif a == ".mcp.json":
                try:
                    servers = json.loads(_leer(p)).get("mcpServers", {})
                except ValueError:
                    servers = {}
                for n, cfg in servers.items():
                    mcp.add(f"{n}: {cfg.get('command', '')} {' '.join(map(str, cfg.get('args', [])))}".strip()
                            if isinstance(cfg, dict) else n)
            elif a == ".env.example":
                variables.update(m.group(1) for m in re.finditer(r"^\s*([A-Z][A-Z0-9_]+)\s*=", _leer(p), re.M))
    return {
        "git": (carpeta / ".git").exists(),
        "paquetes": pkgs,
        "imagenes": sorted(imagenes),
        "acciones": sorted(acciones),
        "mcp": sorted(mcp),
        "servicios": sorted(servicios),
        "variables": sorted(variables),
    }


def _cmd(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def mac():
    apps = {}
    for base in (Path("/Applications"), Path.home() / "Applications"):
        for app in base.glob("*.app"):
            try:
                with open(app / "Contents" / "Info.plist", "rb") as f:
                    info = plistlib.load(f)
                apps[app.stem] = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
            except Exception:  # plists rotos o raros: la app cuenta igual, sin versión

                apps[app.stem] = None

    brew = {}
    for linea in (_cmd("brew", "list", "--versions") + _cmd("brew", "list", "--cask", "--versions")).splitlines():
        partes = linea.split()
        if partes:
            brew[partes[0]] = partes[-1] if len(partes) > 1 else None

    extensiones = {}
    for editor, carpeta in (("vscode", ".vscode"), ("cursor", ".cursor"), ("windsurf", ".windsurf")):
        for ext in (Path.home() / carpeta / "extensions").glob("*-*"):
            m = re.match(r"(.+?)-(\d[\w.\-]*?)(?:-(?:darwin|universal)[\w\-]*)?$", ext.name)
            if m:
                extensiones.setdefault(editor, {})[m.group(1)] = m.group(2)

    runtimes = {}
    for nombre, args in (("node.js", ("node", "-v")), ("python", ("python3", "--version")),
                         ("go", ("go", "version")), ("bun", ("bun", "--version")),
                         ("deno", ("deno", "--version")), ("docker", ("docker", "--version")),
                         ("git", ("git", "--version")), ("claude code", ("claude", "--version"))):
        salida = _cmd(*args).strip().splitlines()
        m = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", salida[0]) if salida else None
        if m:
            runtimes[nombre] = m.group(1)

    npm_global = {}
    try:
        npm_global = {n: i.get("version") for n, i in
                      json.loads(_cmd("npm", "ls", "-g", "--depth=0", "--json") or "{}").get("dependencies", {}).items()}
    except ValueError:
        pass

    mcp = {}
    configs = {
        "claude desktop": Path.home() / "Library/Application Support/Claude/claude_desktop_config.json",
        "claude code": Path.home() / ".claude.json",
        "cursor": Path.home() / ".cursor/mcp.json",
    }
    for cliente, p in configs.items():
        try:
            servers = json.loads(_leer(p) or "{}").get("mcpServers", {})
        except ValueError:
            continue
        mcp[cliente] = {n: (f"{c.get('command', '')} {' '.join(map(str, c.get('args', [])))}".strip()
                            if isinstance(c, dict) else "") for n, c in servers.items()}

    return {"apps": apps, "brew": brew, "extensiones": extensiones, "runtimes": runtimes,
            "npm_global": npm_global, "mcp": mcp}


def armar():
    repos = {carpeta.name: repo(carpeta) for carpeta in rutas.repos()}
    vacia = {"apps": {}, "brew": {}, "extensiones": {}, "runtimes": {}, "npm_global": {}, "mcp": {}}
    return {"modo": rutas.MODO, "repos": repos, "mac": vacia if rutas.MODO == "nube" else mac()}


def guardar(inv):
    rutas.ESTADO.mkdir(parents=True, exist_ok=True)
    (rutas.ESTADO / "inventario.json").write_text(json.dumps(inv, ensure_ascii=False, indent=1))
