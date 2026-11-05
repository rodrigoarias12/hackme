"""Vercel en solo lectura: quién entra a los equipos, qué queda expuesto y qué cambió.

Habla con la API de Vercel por `vercel api` (usa la sesión del CLI, hackme no toca tokens)
o, si hay VERCEL_TOKEN en el ambiente (la nube), directo por HTTPS. Nunca pide valores de
variables: de cada una mira nombre, tipo y ambientes. Nunca cambia nada.

Qué mira, pensado como alguien de seguridad:
  - equipo: pedidos de acceso pendientes y miembros nuevos (alguien adentro que no esperabas)
  - variables: secretos con prefijo público (terminan en el navegador), secretos de producción
    también en development (cualquiera con `vercel env pull` se lleva la base de prod), secretos
    "plain" o "encrypted" en vez de "sensitive" (se pueden volver a leer en claro)
  - proyectos: previews sin protección (cualquiera con la URL entra), firewall apagado en
    proyectos con dominio propio, proyectos viejos que siguen publicados
  - auditoría: quién bajó variables con `env pull`, variables agregadas, deploys bloqueados
  - el chequeo de seguridad del propio Vercel (`vercel security check`, solo lectura): miembros
    sin MFA, tokens que no vencen, demasiados owners, previews sin protección, variables que
    llegan al navegador. Solo con el CLI logueado.
"""
import json
import os
import re
import shutil
import subprocess
import time
import urllib.parse
import urllib.request

from . import memoria

SECRETO = re.compile(r"(SECRET|TOKEN|PASSWORD|_PASS$|PRIVATE|API_KEY|_KEY$|SERVICE_ROLE|DATABASE_URL|CONNECTION_STRING)")
# Públicas por diseño aunque el nombre suene a secreto.
PUBLICA_OK = re.compile(r"(PUBLIC_KEY|SITE_KEY|PUBLISHABLE|ANON_KEY|_DSN$|MEASUREMENT_ID|_APP_ID$)")
PREFIJO_PUBLICO = ("NEXT_PUBLIC_", "VITE_", "PUBLIC_", "EXPO_PUBLIC_", "REACT_APP_", "NUXT_PUBLIC_")
EVENTOS = re.compile(r"(env-variable-read:.*pull|env-variable-(add|remove|update)|team-member|token|"
                     r"protection|firewall|integration|deployment-creation-blocked|ai-security-review)")
VIEJO_DIAS = 180

# `vercel security check`: severidad y título por chequeo. Uno que no esté acá entra como "media".
CHEQUEOS = {
    "members-no-mfa": ("alta", "miembros del equipo sin MFA"),
    "env-vars-exposed-web-app-fwk": ("alta", "variables con nombre de secreto que llegan al navegador"),
    "pats-no-expiration": ("media", "tokens personales que no vencen"),
    "members-too-many-owners": ("media", "demasiados owners en el equipo"),
    "proj-no-preview-depl-protection": ("media", "proyectos con previews sin protección"),
    "env-vars-creds-instead-of-oidc": ("media", "credenciales fijas donde podría usarse OIDC"),
    "depl-no-git-fork-protection": ("media", "deploys desde forks sin protección"),
    "env-vars-non-sensitive": ("baja", "variables no marcadas como sensitive"),
    "env-vars-non-sensitive-stale": ("baja", "variables no sensitive que no se usan hace tiempo"),
}


def _api(ruta):
    token = os.environ.get("VERCEL_TOKEN")
    if token:
        req = urllib.request.Request(f"https://api.vercel.com{ruta}", headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    r = subprocess.run(["vercel", "api", ruta], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError((r.stderr.strip().splitlines() or [f"exit {r.returncode}"])[-1])
    return json.loads(r.stdout)


def _q(ruta, **params):
    return f"{ruta}?{urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})}"


def _proyectos(equipo):
    salida, hasta = [], None
    while True:
        d = _api(_q("/v9/projects", teamId=equipo, limit=100, until=hasta))
        salida += d.get("projects", [])
        hasta = (d.get("pagination") or {}).get("next")
        if not hasta or len(salida) > 2000:
            return salida


def _hallazgo(hid, severidad, titulo, recurso, detalle):
    return {"id": hid, "servicio": "Vercel", "severidad": severidad, "titulo": titulo,
            "recurso": recurso, "detalle": detalle}


def _equipo(equipo, slug, hallazgos, dominio_propio):
    for m in _api(_q(f"/v3/teams/{equipo}/members", limit=100)).get("members", []):
        quien = m.get("username") or m.get("name")
        if not m.get("confirmed"):
            origen = (m.get("joinedFrom") or {}).get("gitUserLogin")
            hallazgos.append(_hallazgo(f"vercel:{slug}:pedido:{m.get('uid')}", "alta",
                                       f"Pedido de acceso pendiente al equipo {slug}: {quien} ({m.get('role')})",
                                       slug, {"rol": m.get("role"), "git": origen}))
        else:
            hallazgos.append(_hallazgo(f"vercel:{slug}:miembro:{m.get('uid')}", "info",
                                       f"Miembro del equipo {slug}: {quien} ({m.get('role')})", slug,
                                       {"rol": m.get("role")}))

    ahora = time.time() * 1000
    viejos = []
    for p in _proyectos(equipo):
        nombre = p["name"]
        alias = [a for a in ((p.get("targets") or {}).get("production") or {}).get("alias", [])]
        propios = [a for a in alias if not a.endswith(".vercel.app")]
        if propios:
            dominio_propio.update(propios)
        if ahora - p.get("updatedAt", ahora) > VIEJO_DIAS * 86400000:
            viejos.append(nombre)
            continue  # lo viejo se reporta junto, sin revisar variables una por una
        if propios and not p.get("ssoProtection") and not p.get("passwordProtection"):
            hallazgos.append(_hallazgo(f"vercel:{slug}:{nombre}:previews", "media",
                                       f"{nombre}: los previews no tienen protección (cualquiera con la URL entra)",
                                       nombre, {"dominios": sorted(propios)[:3]}))
        if propios and not (p.get("security") or {}).get("firewallEnabled"):
            hallazgos.append(_hallazgo(f"vercel:{slug}:{nombre}:firewall", "baja",
                                       f"{nombre}: firewall de Vercel apagado en un proyecto con dominio propio",
                                       nombre, {}))
        _variables(equipo, slug, p, hallazgos)

    if viejos:
        hallazgos.append(_hallazgo(f"vercel:{slug}:viejos", "baja",
                                   f"{len(viejos)} proyectos de {slug} sin cambios hace más de {VIEJO_DIAS} días siguen publicados",
                                   slug, {"cantidad": len(viejos), "ejemplos": sorted(viejos)[:8]}))


def _variables(equipo, slug, p, hallazgos):
    try:
        envs = _api(_q(f"/v10/projects/{p['id']}/env", teamId=equipo)).get("envs", [])
    except (RuntimeError, ValueError, OSError):
        return  # sin permiso para listar (rol del usuario): no es un hallazgo
    nombre, publicas, plain, compartidas, no_sensitive = p["name"], [], [], [], []
    for e in envs:  # solo key, type y target: el valor no se lee ni se guarda
        clave, tipo, destinos = e.get("key", ""), e.get("type"), set(e.get("target") or [])
        if not SECRETO.search(clave) or PUBLICA_OK.search(clave):
            continue
        if clave.startswith(PREFIJO_PUBLICO):
            publicas.append(clave)
        elif tipo == "plain":
            plain.append(clave)
        else:
            if {"production", "development"} <= destinos:
                compartidas.append(clave)
            if tipo != "sensitive" and "production" in destinos:
                no_sensitive.append(clave)
    if publicas:
        hallazgos.append(_hallazgo(f"vercel:{slug}:{nombre}:publicas", "alta",
                                   f"{nombre}: variables con nombre de secreto y prefijo público (llegan al navegador)",
                                   nombre, {"variables": sorted(set(publicas))}))
    if plain:
        hallazgos.append(_hallazgo(f"vercel:{slug}:{nombre}:plain", "alta",
                                   f"{nombre}: secretos guardados como texto plano", nombre, {"variables": sorted(set(plain))}))
    if compartidas:
        hallazgos.append(_hallazgo(f"vercel:{slug}:{nombre}:compartidas", "media",
                                   f"{nombre}: secretos de producción también en development (`vercel env pull` se los lleva)",
                                   nombre, {"variables": sorted(set(compartidas))}))
    if no_sensitive:
        hallazgos.append(_hallazgo(f"vercel:{slug}:{nombre}:sensitive", "baja",
                                   f"{nombre}: {len(set(no_sensitive))} secretos de producción no son 'sensitive' (se pueden releer en claro)",
                                   nombre, {"cantidad": len(set(no_sensitive))}))


def _auditoria(equipo, slug, desde, hallazgos):
    eventos = _api(_q("/v3/events", teamId=equipo, limit=100, since=desde)).get("events", [])
    resumen = {}
    for ev in eventos:
        tipo = ev.get("type", "")
        if not EVENTOS.search(tipo):
            continue
        quien = (ev.get("principal") or ev.get("user") or {}).get("username") or ev.get("principalId") or "?"
        resumen.setdefault((tipo, quien), []).append(ev.get("createdAt"))
    for (tipo, quien), cuando in sorted(resumen.items()):
        severidad = "media" if "pull" in tipo or "team-member" in tipo or "token" in tipo else "baja"
        hallazgos.append(_hallazgo(f"vercel:{slug}:evento:{tipo}:{quien}:{max(cuando)}", severidad,
                                   f"{slug}: {tipo} por {quien} ({len(cuando)} veces desde la ronda anterior)",
                                   slug, {"veces": len(cuando), "ultima": max(cuando)}))


def _chequeo(slug, hallazgos):
    """El chequeo de seguridad de Vercel para el equipo. Trae etiquetas (usuario, proyecto, nombre
    de variable), nunca valores."""
    if not shutil.which("vercel"):
        return
    r = subprocess.run(["vercel", "security", "check", "--json", "--non-interactive", "--scope", slug],
                       capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        raise RuntimeError((r.stderr.strip().splitlines() or [f"exit {r.returncode}"])[-1])
    for nombre, c in (json.loads(r.stdout).get("report") or {}).items():
        cantidad = c.get("violationsCount") or 0
        if not cantidad:
            continue
        severidad, titulo = CHEQUEOS.get(nombre, ("media", nombre))
        ejemplos = [s.get("label") for s in c.get("samples") or [] if s.get("label")]
        detalle = {"cantidad": cantidad, "ejemplos": ejemplos[:12]}
        if c.get("totalCount"):
            detalle["de"] = c["totalCount"]
        if c.get("truncated"):
            detalle["truncado"] = True
        hallazgos.append(_hallazgo(f"vercel:{slug}:chequeo:{nombre}", severidad,
                                   f"{slug}: {cantidad} {titulo} (chequeo de Vercel)", slug, detalle))


def correr():
    if not os.environ.get("VERCEL_TOKEN") and not shutil.which("vercel"):
        return {"hallazgos": [], "dominios": [], "error": "sin VERCEL_TOKEN ni CLI de Vercel"}
    hallazgos, errores, dominios = [], {}, set()
    # 48 h: cubre una ronda salteada. La API de eventos pide ISO 8601, no milisegundos.
    desde = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 2 * 86400))
    try:
        equipos = _api("/v2/teams").get("teams", [])
    except (RuntimeError, ValueError, OSError) as e:
        return {"hallazgos": [], "dominios": [], "error": str(e)}
    for t in equipos:
        for paso in (_equipo, _auditoria, _chequeo):
            try:
                if paso is _equipo:
                    _equipo(t["id"], t["slug"], hallazgos, dominios)
                elif paso is _auditoria:
                    _auditoria(t["id"], t["slug"], desde, hallazgos)
                else:
                    _chequeo(t["slug"], hallazgos)
            except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
                errores[f"{t['slug']}:{paso.__name__.strip('_')}"] = str(e)[:200]
    # Los miembros confirmados son contexto: solo importan cuando aparecen (estado "nuevo").
    primera = memoria.marcar("vercel", hallazgos)
    return {"hallazgos": hallazgos, "errores": errores, "dominios": sorted(dominios), "primera_corrida": primera}


def resumen(r):
    if r.get("error"):
        return f"vercel: {r['error']}"
    nuevos = [h for h in r["hallazgos"] if h["estado"] in ("nuevo", "actualizado") and h["severidad"] != "info"]
    por_sev = {}
    for h in r["hallazgos"]:
        if h["severidad"] != "info":
            por_sev[h["severidad"]] = por_sev.get(h["severidad"], 0) + 1
    return (f"vercel: {sum(por_sev.values())} hallazgos {por_sev}, {len(nuevos)} nuevos, {len(r['dominios'])} dominios propios"
            + "".join(f"  ERROR {k}: {v[:80]}" for k, v in r.get("errores", {}).items()))
