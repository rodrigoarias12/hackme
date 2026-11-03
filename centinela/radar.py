"""Baja Oktsec Radar y lo cruza contra el inventario.

El cruce es determinista y deliberadamente generoso: prefiere un candidato de más a uno
de menos. Quién decide si de verdad te toca es el agente de la tarea programada, que lee
el aviso, compara versiones contra el rango y mira la evidencia.

Tres fuerzas de coincidencia:
  - "version-afectada": el aviso trae el paquete exacto (OSV) y la versión del inventario
    está en la lista de afectadas. Lo más fuerte que se puede afirmar sin mirar el host.
  - "nombre": un paquete, app, runtime, servicio o MCP del inventario se llama igual que un
    producto o proveedor del aviso (el nombre entero, o su primera palabra si no es
    genérica: "Tailscale SSH" -> tailscale). Hay que comparar versiones a mano.
    No se compara contra el texto libre: "events" o "typescript" coincidían con todo.
  - "mencion": el proveedor aparece en la documentación de un repo (solo para incidentes
    de plataformas y amenazas, donde no hay paquete que comparar: Binance, Railway, …).
"""
import json
import re
import subprocess
import urllib.request

from . import rutas

# Primeras palabras de producto que no identifican a nada ("Secure Firewall ASA").
GENERICOS = {
    "core", "server", "client", "app", "api", "sdk", "cli", "web", "ui", "agent", "agents",
    "tools", "cloud", "tls", "ssl", "user", "users", "accounts", "service", "services", "data",
    "commerce", "gateway", "remote", "support", "access", "open", "secure", "privileged",
    "hot", "banking", "payment", "payments", "pypi", "docker", "ghcr", "the", "aws",
}


def bajar():
    req = urllib.request.Request(rutas.RADAR_ITEMS, headers={"User-Agent": "centinela/1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        datos = json.load(r)
    rutas.ESTADO.mkdir(parents=True, exist_ok=True)
    (rutas.ESTADO / "radar-items.json").write_text(json.dumps(datos, ensure_ascii=False))
    return datos


def _indice(inv):
    """nombre normalizado -> [(tipo, nombre, version, donde)]"""
    idx = {}

    def sumar(nombre, tipo, version, donde):
        if not nombre:
            return
        idx.setdefault(nombre.lower().strip(), []).append((tipo, nombre, version, donde))

    for repo, r in inv["repos"].items():
        for eco, pkgs in r["paquetes"].items():
            for p in pkgs.values():
                for version, archivos in p["versiones"].items():
                    sumar(p["nombre"], f"paquete {eco}", version, f"{repo}/{archivos[0]}")
                if eco == "go":
                    sumar(p["nombre"].rstrip("/").split("/")[-1], "paquete go", None, repo)
        for img in r["imagenes"]:
            base = img.split("@")[0].rsplit(":", 1)[0] if ":" in img.split("/")[-1] else img.split("@")[0]
            sumar(base.split("/")[-1], "imagen docker", img, repo)
        for s in r["servicios"]:
            sumar(s, "servicio", None, repo)
        for m in r["mcp"]:
            sumar(m.split(":")[0], "mcp", None, repo)

    mac = inv["mac"]
    for n, v in mac["apps"].items():
        sumar(n, "app mac", v, "Mac")
        if n.startswith(("Google ", "Microsoft ")):  # "Google Chrome" -> chrome
            sumar(n.split(" ", 1)[1], "app mac", v, "Mac")
    for n, v in mac["brew"].items():
        sumar(n, "brew", v, "Mac")
    for editor, exts in mac["extensiones"].items():
        for n, v in exts.items():
            sumar(n, f"extensión {editor}", v, "Mac")
            sumar(n.split(".", 1)[-1], f"extensión {editor}", v, "Mac")
    for n, v in mac["runtimes"].items():
        sumar(n, "runtime", v, "Mac")
    for n, v in mac["npm_global"].items():
        sumar(n, "npm global", v, "Mac")
    for cliente, servers in mac["mcp"].items():
        for n in servers:
            sumar(n, f"mcp {cliente}", None, "Mac")
    return idx


def _nombres(item):
    """Los nombres con que el aviso identifica lo afectado, normalizados."""
    partes = [item.get("vendor") or "", *item.get("products", [])]
    partes += [a.get("product", "") for a in item.get("affected") or []]
    partes += [p for c in item.get("cve_details", []) for p in (c.get("products") or [])]
    nombres = set()
    for p in partes:
        for trozo in re.split(r"[,/·]", p.lower()):
            trozo = re.sub(r"\([^)]*\)", " ", trozo)                   # "(npm)", "(Windows/macOS)"
            trozo = re.sub(r"\b(\d+(\.\d+)*(\.x)?|before .*|v\d.*)$", " ", trozo.strip())  # "22.x"
            trozo = " ".join(trozo.split())
            if not trozo:
                continue
            nombres.add(trozo)
            primera = trozo.split()[0]
            if primera not in GENERICOS and len(primera) >= 3:
                nombres.add(primera)
                nombres.add(primera.removesuffix(".js"))
    return nombres


def _cruzar(item, idx):
    hallados = {}

    # 1. Paquete exacto con versiones afectadas según OSV.
    for pk in item.get("additional_evidence", {}).get("packages", []):
        q = pk.get("query", {})
        afectadas = {v for rec in pk.get("records", []) for a in rec.get("affected", []) for v in a.get("versions", [])}
        if q.get("version"):
            afectadas.add(q["version"])
        for tipo, nombre, version, donde in idx.get((q.get("name") or "").lower(), []):
            fuerza = "version-afectada" if version in afectadas else "nombre"
            hallados[(tipo, nombre, version, donde)] = fuerza

    # 2. Por nombre: igual a un producto o proveedor del aviso.
    for n in _nombres(item):
        for ref in idx.get(n, []):
            hallados.setdefault(ref, "nombre")
    return [{"fuerza": f, "tipo": t, "nombre": n, "version": v, "donde": d}
            for (t, n, v, d), f in sorted(hallados.items(), key=lambda x: (x[1] != "version-afectada", x[0][3]))]


def _menciones(item):
    """Repos cuya documentación nombra al proveedor. Solo para incidentes sin paquete."""
    if item.get("kind") == "vulnerability" or not rutas.ESPEJO.exists():
        return []
    vendor = (item.get("vendor") or "").strip()
    if len(vendor) < 4 or vendor.lower() in GENERICOS:
        return []
    salida = subprocess.run(
        # Solo docs y configs: en código, "cursor" o "railway" son palabras comunes.
        ["grep", "-rIilw", "--include=*.md", "--include=*.yml", "--include=*.yaml", "--include=*.toml",
         "--include=*.example", "-e", vendor, str(rutas.ESPEJO)],
        capture_output=True, text=True).stdout
    repos = {}
    for archivo in salida.splitlines():
        rel = archivo.removeprefix(str(rutas.ESPEJO) + "/")
        if rel.split("/")[0] != "centinela":  # este repo nombra a todos los proveedores
            repos.setdefault(rel.split("/")[0], []).append(rel)
    return [{"fuerza": "mencion", "tipo": "documentación", "nombre": vendor, "version": None,
             "donde": f"{repo} ({len(a)} archivos, p. ej. {a[0]})"} for repo, a in sorted(repos.items())]


def correr(inv, datos=None):
    datos = datos or bajar()
    rutas.MEMORIA.mkdir(parents=True, exist_ok=True)
    visto_p = rutas.MEMORIA / "radar-visto.json"
    visto = json.loads(visto_p.read_text()) if visto_p.exists() else {}
    idx = _indice(inv)

    candidatos = []
    for item in datos["items"]:
        sello = item.get("last_verified_at") or item.get("updated_at") or item.get("reported_on")
        estado = "nuevo" if item["slug"] not in visto else ("actualizado" if visto[item["slug"]] != sello else "visto")
        visto[item["slug"]] = sello
        coincidencias = _cruzar(item, idx) + _menciones(item)
        if not coincidencias:
            continue
        candidatos.append({
            "slug": item["slug"], "url": item["url"], "titulo": item["title"],
            "prioridad": item["priority"], "tipo": item["kind"], "estado": estado,
            "reportado": item.get("reported_on"), "accion": item.get("action"),
            "afectado": item.get("affected"), "explotacion": item.get("exploitation"),
            "parche": item.get("patch"), "kev": bool(item.get("kev")),
            "pasos": [c.get("title") for c in item.get("checklist", [])],
            "coincidencias": coincidencias[:40], "total_coincidencias": len(coincidencias),
        })

    orden = {"act_now": 0, "this_week": 1, "monitor": 2}
    candidatos.sort(key=lambda c: (orden.get(c["prioridad"], 9), not any(x["fuerza"] == "version-afectada" for x in c["coincidencias"])))
    resultado = {"radar_actualizado": datos.get("updated_at"), "avisos": len(datos["items"]), "candidatos": candidatos}
    (rutas.ESTADO / "radar-cruce.json").write_text(json.dumps(resultado, ensure_ascii=False, indent=1))
    visto_p.write_text(json.dumps(visto, indent=1))
    return resultado


def resumen(r):
    lineas = [f"radar: {r['avisos']} avisos (actualizado {r['radar_actualizado']}), {len(r['candidatos'])} con coincidencias"]
    for c in r["candidatos"]:
        fuertes = sum(x["fuerza"] == "version-afectada" for x in c["coincidencias"])
        lineas.append(f"  [{c['prioridad']}/{c['estado']}] {c['titulo']} — {c['total_coincidencias']} coincidencias"
                      + (f", {fuertes} con versión afectada" if fuertes else ""))
        for x in c["coincidencias"][:4]:
            lineas.append(f"      {x['fuerza']:16} {x['tipo']:18} {x['nombre']} {x['version'] or ''} @ {x['donde']}")
    return "\n".join(lineas)
