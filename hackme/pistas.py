"""Pistas: lo serio que encontró cada fuente de la ronda, en una sola forma.

Cada fuente habla distinto (Aguara da reglas por archivo, Radar avisos, AWS hallazgos, Vercel
chequeos). Acá se pasan todas a lo mismo, para que `investigar` abra una investigación por cada
una y el agente las recorra de la más grave a la menos grave, sin esperar a que el dueño pregunte.

Una pista trae la evidencia que se puede juntar sin ejecutar nada y sin abrir secretos, ya marcada
por tipo: lo que hackme leyó directo es `observado` (un archivo versionado, una versión en un
lockfile, una configuración de Vercel); lo que afirma un escáner o un detector es `deducido`.

  {origen, id, fuente, repo, carpeta, rama, donde, severidad, titulo, afirmacion,
   arreglo_sugerido, evidencia: [(tipo, que, donde)], sello, proxima}

`sello` es lo que, si cambia, reabre una investigación cerrada (los archivos marcados, las
versiones, las IPs). `repo` es owner/nombre en GitHub cuando la pista vive en un repo: solo esas
pueden terminar en un PR. Vercel Security Review no pasa por acá: `investigar` la trata aparte
porque trae citas de código.
"""
import hashlib
import json
import re
import subprocess

from . import rutas

GRAVES = ("crítica", "alta")
TOPE_EVIDENCIA = 6


def _slug(texto, largo=40):
    return re.sub(r"[^a-z0-9]+", "-", str(texto).lower()).strip("-")[:largo].strip("-")


def _huella(*partes):
    return hashlib.sha256("|".join(str(p) for p in partes).encode()).hexdigest()[:8]


def _git(carpeta, *args):
    try:
        r = subprocess.run(["git", "-C", str(carpeta), *args], capture_output=True, text=True, timeout=30)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def remoto(carpeta):
    """(owner/nombre, rama principal) del repo local, o (None, None) si no está en GitHub."""
    url = _git(rutas.GITHUB / carpeta, "remote", "get-url", "origin")
    m = re.search(r"github\.com[:/]([\w.-]+/[\w.-]+?)(?:\.git)?$", url)
    if not m:
        return None, None
    rama = _git(rutas.GITHUB / carpeta, "symbolic-ref", "--short", "refs/remotes/origin/HEAD").removeprefix("origin/")
    return m.group(1), rama or "main"


def _versionado(carpeta, archivo):
    return bool(_git(rutas.GITHUB / carpeta, "ls-files", "--", archivo))


def _pista(origen, pid, fuente, severidad, titulo, afirmacion, evidencia, sello, carpeta=None, donde="", arreglo="", proxima=""):
    repo, rama = remoto(carpeta) if carpeta else (None, None)
    return {"origen": origen, "id": pid, "fuente": fuente, "repo": repo, "carpeta": carpeta, "rama": rama, "donde": donde or carpeta or "",
            "severidad": severidad, "titulo": titulo, "afirmacion": afirmacion, "arreglo_sugerido": arreglo or "",
            "evidencia": evidencia, "sello": json.dumps(sello, sort_keys=True, ensure_ascii=False, default=str),
            "proxima": proxima or "leer la evidencia y decidir: confirmada, descartada o bloqueada"}


# ── Aguara ──────────────────────────────────────────────────────────────────────────────────

def de_aguara(ag):
    """Una pista por regla y repo (no una por archivo), más secretos versionados y paquetes comprometidos."""
    pistas, grupos = [], {}
    for h in ag.get("importantes", []):
        grupos.setdefault((h["repo"], h["regla"]), []).append(h)
    for (carpeta, regla), hs in sorted(grupos.items()):
        severidad = "crítica" if any(h["severidad"] == "crítica" for h in hs) else "alta"
        credencial = hs[0]["capa"] == "credencial"
        evidencia = [("deducido", f"Aguara lo marca con la regla {regla} ({hs[0]['categoria']}); es un escáner de patrones, no una prueba", "")]
        for h in hs[:TOPE_EVIDENCIA]:
            lugar = f"{carpeta}/{h['archivo']}:{h['linea']}"
            if _versionado(carpeta, h["archivo"]):
                evidencia.append(("observado", "el archivo marcado está versionado en git" + (" (no se muestra su contenido)" if credencial else ""), lugar))
            else:
                evidencia.append(("observado", "el archivo marcado no está versionado en git: vive solo en esta máquina", lugar))
        if len(hs) > TOPE_EVIDENCIA:
            evidencia.append(("deducido", f"y {len(hs) - TOPE_EVIDENCIA} archivos más con la misma regla", ""))
        evidencia.append(("sin-probar", "si eso es real o un falso positivo (un test, un ejemplo, documentación): hay que leer cada archivo", ""))
        que = "una clave escrita en el código" if credencial else "instrucciones o configuración peligrosa en lo que leen los agentes de IA"
        pistas.append(_pista(f"aguara:{carpeta}:{regla}", f"aguara-{_slug(carpeta, 20)}-{_slug(regla, 24)}", "aguara", severidad,
                             f"{hs[0]['nombre']} en {len(hs)} archivo{'s' if len(hs) > 1 else ''} de {carpeta}",
                             f"Aguara encontró {que}: {hs[0]['nombre']}.", evidencia, sorted({h["archivo"] for h in hs}), carpeta,
                             arreglo=next((h["arreglo"] for h in hs if h.get("arreglo") and h["arreglo"] != "None"), "")))
    for carpeta, archivos in sorted(ag.get("secretos_versionados", {}).items()):
        nombres = sorted(str(a) for a in archivos)
        pistas.append(_pista(f"aguara:{carpeta}:secretos-versionados", f"aguara-{_slug(carpeta, 20)}-secretos", "aguara", "crítica",
                             f"{len(nombres)} archivo{'s' if len(nombres) > 1 else ''} de secretos versionado{'s' if len(nombres) > 1 else ''} en {carpeta}",
                             "Hay archivos con nombre de secreto dentro de git: cualquiera con acceso al repo los tiene.",
                             [("observado", f"git ls-files los lista: {', '.join(nombres[:8])} (solo el nombre: no se abren)", carpeta),
                              ("sin-probar", "si adentro hay una credencial viva: no se abre el archivo; lo confirma el dueño", "")],
                             nombres, carpeta, arreglo="Sacarlos de git, sumarlos a .gitignore y rotar lo que tuvieran.",
                             proxima="preguntarle al dueño si el archivo tiene una credencial viva"))
    for carpeta, paquetes in sorted(ag.get("paquetes_comprometidos", {}).items()):
        nombres = sorted(json.dumps(p, ensure_ascii=False, sort_keys=True) if isinstance(p, dict) else str(p) for p in paquetes)
        pistas.append(_pista(f"aguara:{carpeta}:paquetes-comprometidos", f"aguara-{_slug(carpeta, 20)}-paquetes", "aguara", "crítica",
                             f"{len(nombres)} paquete{'s' if len(nombres) > 1 else ''} comprometido{'s' if len(nombres) > 1 else ''} en {carpeta}",
                             "Un paquete instalado o lockeado figura en la base de paquetes comprometidos de Aguara.",
                             [("observado", f"aguara check sobre el repo: {'; '.join(nombres[:5])[:300]}", carpeta),
                              ("sin-probar", "si el paquete llegó a ejecutarse en esta máquina o en un deploy", "")],
                             nombres, carpeta, arreglo="Sacar o actualizar el paquete y revisar qué corrió al instalarlo."))
    sanas = {f"aguara:{c}:" for c in ag.get("por_repo", {}) if c not in (ag.get("errores") or {})}
    return pistas, sanas


# ── Oktsec Radar ────────────────────────────────────────────────────────────────────────────

def de_radar(rd):
    """Avisos que tocan una versión del inventario, o un nombre cuando ya se está explotando."""
    pistas = []
    for c in rd.get("candidatos", []):
        fuertes = [x for x in c.get("coincidencias", []) if x["fuerza"] == "version-afectada"]
        explotado = c.get("explotacion") == "exploited" or c.get("kev") is True
        nombres = [x for x in c.get("coincidencias", []) if x["fuerza"] == "nombre"]
        if fuertes:
            usar, severidad = fuertes, "crítica" if explotado else "alta"
        elif nombres and explotado and c.get("prioridad") == "act_now":
            usar, severidad = nombres, "alta"
        else:
            continue
        rango = "; ".join(f"{a.get('product', '')} {a.get('range', '')}".strip() for a in (c.get("afectado") or [])[:3])[:300]
        evidencia = [("deducido", f"Radar: {c['titulo']}. Afectado: {rango or 'sin rango publicado'}. Explotación: {c.get('explotacion')}; parche: {c.get('parche')}", c["url"])]
        for x in usar[:TOPE_EVIDENCIA]:
            evidencia.append(("observado", f"el inventario tiene {x['tipo']} {x['nombre']} {x.get('version') or ''}".strip(), str(x.get("donde") or "")))
        evidencia.append(("sin-probar", "que el código vulnerable se use de verdad acá" if fuertes else
                          "que la versión instalada caiga en el rango afectado: la coincidencia es solo por nombre", ""))
        lugar = str(usar[0].get("donde") or "")
        carpeta = lugar.split("/")[0].split(" ")[0] if lugar and lugar != "Mac" else None
        if carpeta and not (rutas.GITHUB / carpeta).is_dir():
            carpeta = None
        pistas.append(_pista(f"radar:{c['slug']}", f"radar-{_slug(c['slug'])}", "radar", severidad, c["titulo"],
                             f"Un aviso de Oktsec Radar coincide con {'una versión' if fuertes else 'un nombre'} de tu inventario"
                             + (" y ya se está explotando." if explotado else "."),
                             evidencia, sorted((x["nombre"], str(x.get("version")), str(x.get("donde"))) for x in usar), carpeta, donde=lugar,
                             arreglo=c.get("accion") or "", proxima="comparar la versión instalada con el rango afectado"))
    return pistas, ({"radar:"} if "candidatos" in rd and not rd.get("error") else set())


# ── AWS ─────────────────────────────────────────────────────────────────────────────────────

def de_aws(nube):
    pistas, sanas = [], set()
    for cuenta in nube.get("cuentas", []):
        numero = cuenta.get("cuenta") or cuenta.get("perfil")
        if not cuenta.get("errores"):
            sanas.add(f"aws:{numero}:")
        hs = cuenta.get("hallazgos", [])
        grupos = {}
        for h in hs:
            if h["servicio"] == "GuardDuty" and float(h["severidad"]) >= 7:
                grupos.setdefault(("gd", h["tipo"], h["recurso"]), []).append(h)
            elif h["servicio"] == "Security Hub" and h["severidad"] in ("CRITICAL", "HIGH"):
                grupos.setdefault(("sh", h.get("control") or h["titulo"], h["recurso"]), []).append(h)
            elif h["servicio"] == "Inspector" and h["severidad"] in ("CRITICAL", "HIGH"):
                paquete = (h["titulo"].split(" - ", 1) + [h["titulo"]])[1]
                grupos.setdefault(("insp", paquete, h["recurso"]), []).append(h)
        for (clase, que, recurso), g in sorted(grupos.items()):
            recurso_corto = recurso.rsplit(":", 2)[-2] if recurso.startswith("arn:") and recurso.count(":") > 6 else recurso.rsplit("/", 1)[-1]
            origen = f"aws:{numero}:{clase}:{que}:{recurso}"
            if clase == "gd":
                grave = max(float(h["severidad"]) for h in g)
                ips = sorted({ip for h in g for ip in (h.get("ips") or [])})
                origenes = sorted({o for h in g for o in (h.get("origen") or [])})
                pistas.append(_pista(origen, f"aws-gd-{_huella(origen)}", "aws-guardduty", "crítica" if grave >= 8.5 else "alta",
                                     g[0]["titulo"][:160], f"GuardDuty detectó {que} sobre {recurso}.",
                                     [("deducido", f"GuardDuty lo reporta con severidad {grave:g}: {sum(int(h.get('veces') or 1) for h in g)} veces, "
                                                   f"de {min(h['primera'] for h in g)[:10]} a {max(h['ultima'] for h in g)[:10]}, desde {', '.join(ips) or 'sin IP'} "
                                                   f"({', '.join(origenes) or 'origen desconocido'})", f"guardduty {g[0]['id'][:12]}"),
                                      ("sin-probar", "quién estaba detrás de esas IPs y qué hizo con el acceso: hay que preguntarle al dueño y mirar CloudTrail", "")],
                                     {"tipo": que, "ips": ips}, donde=f"AWS {numero} · {recurso}",
                                     arreglo="Confirmar con el dueño si fue alguien del equipo; si no, rotar esa credencial y revisar qué tocó.",
                                     proxima="preguntarle al dueño si reconoce esas IPs"))
            elif clase == "sh":
                pistas.append(_pista(origen, f"aws-sh-{_slug(que, 12)}-{_huella(origen)}", "aws-security-hub", "crítica" if g[0]["severidad"] == "CRITICAL" else "alta",
                                     f"{g[0]['titulo']} ({recurso_corto})", f"Security Hub marca que {recurso} no cumple el control {que}.",
                                     [("deducido", f"Security Hub lo da por fallado ({g[0]['severidad']}), actualizado {g[0].get('actualizado', '')[:10]}", f"control {que} · {recurso}"),
                                      ("sin-probar", "el estado real del recurso: el usuario de solo lectura de hackme no puede describirlo", "")],
                                     {"control": que, "recurso": recurso}, donde=f"AWS {numero} · {recurso}",
                                     arreglo=g[0].get("arreglo") or "", proxima="confirmar el estado del recurso en la consola de AWS"))
            else:
                cves = sorted({h.get("cve") or h["titulo"] for h in g})
                paquetes = sorted({p for h in g for p in (h.get("paquetes") or [])})
                pistas.append(_pista(origen, f"aws-insp-{_slug(que, 16)}-{_huella(origen)}", "aws-inspector", "crítica" if any(h["severidad"] == "CRITICAL" for h in g) else "alta",
                                     f"{len(cves)} vulnerabilidad{'es' if len(cves) > 1 else ''} en {que} ({recurso_corto})",
                                     f"Inspector encontró vulnerabilidades conocidas en {que}, dentro de {recurso}.",
                                     [("deducido", f"Inspector lista {', '.join(cves[:6])}; paquetes: {', '.join(paquetes[:4]) or 'sin detalle'}", recurso),
                                      ("sin-probar", "que el código vulnerable se llame de verdad en ese recurso", "")],
                                     {"cves": cves}, donde=f"AWS {numero} · {recurso}", arreglo=f"Actualizar {que}: {', '.join(paquetes[:3])}" if paquetes else "",
                                     proxima="ubicar de qué repo sale ese recurso y actualizar el paquete"))
    return pistas, sanas


# ── Vercel (todo menos Security Review) ─────────────────────────────────────────────────────

def de_vercel(vc):
    pistas = []
    for h in vc.get("hallazgos", []):
        if ":review:" in h["id"] or h["severidad"] not in GRAVES:
            continue
        detalle = h.get("detalle") or {}
        ejemplos = ", ".join(str(e) for e in (detalle.get("ejemplos") or detalle.get("nombres") or [])[:8])
        pistas.append(_pista(h["id"], f"vercel-{_slug(h['id'].split(':', 2)[-1], 30)}-{_huella(h['id'])}", "vercel", h["severidad"], h["titulo"],
                             "La configuración de Vercel deja algo expuesto o a alguien adentro que quizás no esperabas.",
                             [("observado", "la API de Vercel lo muestra así hoy" + (f": {ejemplos}" if ejemplos else "") + " (nombres, nunca valores)", f"Vercel · {h['recurso']}"),
                              ("sin-probar", "si es intencional: lo confirma el dueño", "")],
                             detalle, donde=f"Vercel · {h['recurso']}", proxima="preguntarle al dueño si es intencional; si no, lo cambia él en Vercel"))
    errores = vc.get("errores") or {}
    equipos = {h["id"].split(":")[1] for h in vc.get("hallazgos", [])}
    sanas = set() if vc.get("error") else {f"vercel:{e}:" for e in equipos if not any(k.startswith(e + ":") for k in errores)}
    return pistas, sanas


def de(ronda):
    """Todas las pistas serias de la ronda y los prefijos de origen cuyas fuentes corrieron bien."""
    pistas, sanas = [], set()
    for fuente, clave in ((de_aguara, "aguara"), (de_radar, "radar"), (de_aws, "aws"), (de_vercel, "vercel")):
        try:
            p, s = fuente(ronda.get(clave) or {})
        except (KeyError, TypeError, ValueError):
            continue   # una fuente con forma rara no tira abajo a las demás
        pistas += p
        sanas |= s
    orden = {s: i for i, s in enumerate(GRAVES)}
    return sorted(pistas, key=lambda p: (orden[p["severidad"]], p["fuente"], p["id"])), sanas
