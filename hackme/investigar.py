"""Investigar: de pista a hallazgo, con evidencia.

Lo que dice un escáner o un modelo es una pista, no un hallazgo. Este módulo abre una
investigación por cada pista seria de la ronda, venga de donde venga (Vercel Security Review,
Aguara, Oktsec Radar, GuardDuty, Security Hub, Inspector, la configuración de Vercel; ver
pistas.py) y junta la evidencia que se puede juntar sin ejecutar nada. También dice qué repo
conviene revisar a fondo en esta ronda (`objetivos`) y deja que el agente abra sus propias
investigaciones con lo que encuentre leyendo (`abrir`). Después el agente (skill, paso 4d) lee ese código, suma lo que vio y decide. Solo una
investigación confirmada puede proponer una acción (acciones.py).

Cada evidencia dice de qué tipo es, para que nadie afirme más de lo que se probó:

  observado    se vio directo: tal archivo, en tal commit, dice esto
  deducido     se concluye de otra cosa: lo afirma un escáner, se infiere de una configuración
  sin-probar   lo que habría que ejecutar para saberlo, y no se ejecutó

Estados: pista -> confirmada | descartada | bloqueada. `arreglada` cuando la fuente deja de
reportarla. Una investigación cerrada se reabre sola si cambia el código que citaba.

Se guarda en $HACKME_PRIVADO/investigaciones/<id>.json. Solo lee: el código se pide a GitHub con
`gh api` (GET), nunca se ejecuta y nunca se prueba nada contra un sistema.
"""
import datetime
import fnmatch
import hashlib
import json
import re
import shutil
import subprocess

from . import pistas, rutas

CARPETA = rutas.PRIVADO / "investigaciones"
CAZA = rutas.PRIVADO / "memoria" / "caza.json"   # cuándo se revisó a fondo cada repo
SEVERIDADES = ("crítica", "alta")   # de ahí para arriba se investiga
TOPE = 12                           # pistas nuevas por ronda: cada una son varias llamadas
ESTADOS = ("pista", "confirmada", "descartada", "bloqueada", "arreglada")
TIPOS = ("observado", "deducido", "sin-probar")
CERRADAS = ("confirmada", "descartada")

# ```ts title="ruta/archivo.ts:10-14"  (así cita Vercel Security Review)
CITA = re.compile(r"```[\w+-]*[ \t]+title=\"([^\"\n]+?):(\d+)(?:-(\d+))?\"[ \t]*\n(.*?)```", re.S)


def _ahora():
    return datetime.datetime.now().isoformat(timespec="minutes")


def _correr(cmd, espera=120):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=espera)
    if r.returncode != 0:
        raise RuntimeError((r.stderr.strip().splitlines() or [f"exit {r.returncode}"])[-1][:200])
    return r.stdout


def _es_secreto(ruta):
    nombre = ruta.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(nombre, patron) for patron in rutas.SECRETOS)


def _lineas(texto):
    return [" ".join(l.split()) for l in texto.splitlines() if l.strip()]


def citas_de(descripcion):
    """Las citas de código de una pista: [{archivo, desde, hasta, sello, _codigo}]."""
    salida = []
    for archivo, desde, hasta, codigo in CITA.findall(descripcion or ""):
        lineas = _lineas(codigo)
        if lineas:
            salida.append({"archivo": archivo, "desde": int(desde), "hasta": int(hasta or desde),
                           "sello": hashlib.sha256("\n".join(lineas).encode()).hexdigest()[:16], "_codigo": lineas})
    return salida


def buscar(lineas, archivo_texto):
    """En qué línea del archivo aparece el bloque citado (ignorando espacios), o None si ya no está."""
    todas = [(n, " ".join(l.split())) for n, l in enumerate(archivo_texto.splitlines(), 1) if l.strip()]
    for i in range(len(todas) - len(lineas) + 1):
        if all(todas[i + k][1] == lineas[k] for k in range(len(lineas))):
            return todas[i][0]
    return None


def leer_github(repo, rama, archivo):
    """El archivo tal como está hoy en la rama, y el commit. Solo GET."""
    sha = _correr(["gh", "api", f"repos/{repo}/commits/{rama}", "--jq", ".sha"]).strip()
    texto = _correr(["gh", "api", "-H", "Accept: application/vnd.github.raw", f"repos/{repo}/contents/{archivo}?ref={sha}"])
    return texto, sha


def detalle_review(slug, hallazgo_id):
    """La vulnerabilidad completa de Vercel Security Review. `inspect` solo lee."""
    salida = _correr(["vercel", "security", "vulnerabilities", "inspect", hallazgo_id, "--json", "--non-interactive", "--scope", slug])
    return json.loads(salida).get("vulnerability") or {}


def _evidencia(tipo, que, donde="", quien="hackme"):
    return {"tipo": tipo, "que": que, "donde": donde, "cuando": _ahora(), "quien": quien}


def verificar_citas(inv):
    """Revisa contra GitHub si el código citado sigue igual. Devuelve la evidencia automática."""
    evidencia, cache = [], {}
    for c in inv["citas"]:
        if _es_secreto(c["archivo"]):
            c["codigo"] = "sin-leer"
            evidencia.append(_evidencia("sin-probar", "la pista cita un archivo de secretos: no se abre", c["archivo"]))
            continue
        try:
            if c["archivo"] not in cache:
                cache[c["archivo"]] = leer_github(inv["repo"], inv["rama"], c["archivo"])
            texto, sha = cache[c["archivo"]]
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
            c["codigo"] = "sin-leer"
            evidencia.append(_evidencia("sin-probar", f"no se pudo leer el archivo citado: {e}", c["archivo"]))
            continue
        linea = buscar(c["_codigo"], texto)
        c["visto_en"] = sha[:12]
        if linea:
            c["codigo"] = "sigue"
            evidencia.append(_evidencia("observado", "el código citado sigue igual en la rama principal",
                                        f"{c['archivo']}:{linea} @ {inv['rama']} {sha[:12]}"))
        else:
            c["codigo"] = "cambió"
            evidencia.append(_evidencia("observado", "el código citado ya no está igual en la rama principal: hay que mirarlo de nuevo",
                                        f"{c['archivo']} @ {inv['rama']} {sha[:12]}"))
    return evidencia


def _archivo(inv_id):
    return CARPETA / f"{inv_id}.json"


def leer(inv_id):
    return json.loads(_archivo(inv_id).read_text())


def guardar(inv):
    CARPETA.mkdir(parents=True, exist_ok=True)
    limpio = {**inv, "citas": [{k: v for k, v in c.items() if not k.startswith("_")} for c in inv.get("citas", [])]}
    limpio["actualizada"] = _ahora()
    _archivo(inv["id"]).write_text(json.dumps(limpio, ensure_ascii=False, indent=1))


def todas():
    return [json.loads(p.read_text()) for p in sorted(CARPETA.glob("*.json"))] if CARPETA.is_dir() else []


def _abrir(h, detalle):
    slug, hallazgo_id = h["id"].split(":")[1], h["id"].rsplit(":", 1)[-1]
    inv = {
        "id": "review-" + hallazgo_id[-10:].lower(), "fuente": "vercel-security-review", "origen": h["id"],
        "repo": h["recurso"], "rama": detalle.get("branchRef") or (h.get("detalle") or {}).get("rama") or "main",
        "titulo": detalle.get("title") or h["titulo"], "severidad": h["severidad"], "clase": detalle.get("vulnerabilityClass"),
        "afirmacion": detalle.get("summary") or "", "arreglo_sugerido": detalle.get("fix") or "",
        "estado": "pista", "evidencia": [], "citas": citas_de(detalle.get("description")), "notas": [],
        "proxima": "leer el código citado y decidir: confirmada, descartada o bloqueada",
        "reabrir_si": "cambia el código citado", "creada": _ahora(),
    }
    inv["evidencia"].append(_evidencia(
        "deducido", f"Vercel Security Review lo marca como {inv['clase']} ({inv['severidad']}); es la lectura de un modelo, no una prueba",
        f"vercel security vulnerabilities inspect {hallazgo_id} --scope {slug}"))
    return inv


def refrescar(inv, detalle):
    """Vuelve a juntar la evidencia automática. Lo que anotó el agente no se toca."""
    inv["citas"] = citas_de(detalle.get("description"))
    propia = [e for e in inv["evidencia"] if e.get("quien") != "hackme" or e["tipo"] == "deducido"]
    inv["evidencia"] = propia + verificar_citas(inv) + [_evidencia(
        "sin-probar", "que se pueda explotar de verdad: no se ejecutó nada, ni en una copia ni en producción")]
    if inv["estado"] in CERRADAS and any(c.get("codigo") == "cambió" for c in inv["citas"]):
        inv["notas"].append(f"{_ahora()}: reabierta, estaba {inv['estado']} y cambió el código citado")
        inv["estado"] = "pista"
    return inv


def correr(ronda):
    """Abre o refresca una investigación por cada pista seria de la ronda."""
    vercel = ronda.get("vercel") or {}
    pistas = [h for h in vercel.get("hallazgos", []) if ":review:" in h["id"] and h["severidad"] in SEVERIDADES]
    orden = {s: i for i, s in enumerate(SEVERIDADES)}
    pistas.sort(key=lambda h: orden[h["severidad"]])
    existentes = {i["origen"]: i for i in todas()}
    salida = {"nuevas": [], "reabiertas": [], "arregladas": [], "errores": {}, "abiertas": []}
    hay_herramientas = bool(shutil.which("vercel") and shutil.which("gh"))
    nuevas = 0
    for h in pistas:
        inv = existentes.get(h["id"])
        if not inv and nuevas >= TOPE:
            continue
        if not hay_herramientas:
            salida["errores"][h["id"]] = "faltan el CLI de vercel o gh: no se puede juntar la evidencia"
            continue
        try:
            detalle = detalle_review(h["id"].split(":")[1], h["id"].rsplit(":", 1)[-1])
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
            salida["errores"][h["id"]] = str(e)[:200]
            continue
        if not inv:
            inv, nuevas = _abrir(h, detalle), nuevas + 1
            salida["nuevas"].append(inv["id"])
        estaba = inv["estado"]
        refrescar(inv, detalle)
        if estaba in CERRADAS and inv["estado"] == "pista":
            salida["reabiertas"].append(inv["id"])
        guardar(inv)
    # Lo que la fuente dejó de listar como abierto: se le pregunta a la fuente antes de darlo por arreglado.
    vivas = {h["id"] for h in vercel.get("hallazgos", []) if ":review:" in h["id"]}
    for origen, inv in existentes.items():
        if ":review:" not in origen or origen in vivas or inv["estado"] == "arreglada" or not hay_herramientas:
            continue
        try:
            detalle = detalle_review(origen.split(":")[1], origen.rsplit(":", 1)[-1])
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired):
            continue   # si la fuente no contesta, no se concluye nada
        if detalle.get("status") and detalle["status"] != "open":
            inv["evidencia"].append(_evidencia("observado", f"la fuente la da por {detalle['status']}",
                                               f"vercel security vulnerabilities inspect {origen.rsplit(':', 1)[-1]}"))
            inv["notas"].append(f"{_ahora()}: {inv['estado']} -> arreglada")
            inv["estado"] = "arreglada"
            guardar(inv)
            salida["arregladas"].append(inv["id"])
    _de_las_demas_fuentes(ronda, existentes, salida)
    orden = {s: n for n, s in enumerate(SEVERIDADES)}
    salida["abiertas"] = sorted(({k: i.get(k) for k in ("id", "fuente", "repo", "donde", "severidad", "estado", "titulo", "proxima")}
                                 for i in todas() if i["estado"] != "arreglada"),
                                key=lambda i: (i["estado"] != "pista", orden.get(i["severidad"], 9), i["id"]))
    salida["objetivos"] = objetivos(ronda)[:5]
    return salida


def _de_las_demas_fuentes(ronda, existentes, salida):
    """Aguara, Radar, AWS y el resto de Vercel: abre, refresca, reabre y cierra con lo que trae la ronda."""
    lista, sanas = pistas.de(ronda)
    vivas = set()
    for p in lista:
        vivas.add(p["origen"])
        evidencia = [_evidencia(t, que, donde) for t, que, donde in p["evidencia"]]
        inv = existentes.get(p["origen"])
        if not inv:
            inv = {**{k: p[k] for k in ("id", "fuente", "origen", "repo", "carpeta", "rama", "donde", "severidad", "titulo", "afirmacion",
                                        "arreglo_sugerido", "sello", "proxima")},
                   "estado": "pista", "evidencia": evidencia, "citas": [], "notas": [],
                   "reabrir_si": "cambia lo que la fuente reporta (archivos, versiones, IPs)", "creada": _ahora()}
            salida["nuevas"].append(inv["id"])
        else:
            inv["evidencia"] = [e for e in inv["evidencia"] if e.get("quien") != "hackme"] + evidencia
            inv.update({k: p[k] for k in ("severidad", "titulo", "donde", "repo", "rama")})
            if inv.get("sello") != p["sello"] and inv["estado"] in CERRADAS + ("arreglada",):
                inv["notas"].append(f"{_ahora()}: reabierta, estaba {inv['estado']} y cambió lo que reporta la fuente")
                inv["estado"] = "pista"
                salida["reabiertas"].append(inv["id"])
            inv["sello"] = p["sello"]
        guardar(inv)
    # Lo que una fuente sana dejó de reportar está arreglado. Si la fuente falló, no se concluye nada.
    for origen, inv in existentes.items():
        if ":review:" in origen or inv.get("fuente") == "agente" or origen in vivas or inv["estado"] == "arreglada":
            continue
        if any(origen.startswith(prefijo) for prefijo in sanas):
            inv["evidencia"].append(_evidencia("observado", "la fuente corrió bien en esta ronda y ya no lo reporta"))
            inv["notas"].append(f"{_ahora()}: {inv['estado']} -> arreglada")
            inv["estado"] = "arreglada"
            guardar(inv)
            salida["arregladas"].append(inv["id"])


def objetivos(ronda):
    """Qué repos conviene revisar a fondo, de más a menos urgente, con el porqué.

    Es la parte proactiva: además de verificar lo que marcan las fuentes, el agente elige un repo
    por ronda y lo lee como lo leería un atacante. El orden sale de las señales de la ronda y de
    hace cuánto no se revisa cada uno.
    """
    aguara = ronda.get("aguara") or {}
    caza = json.loads(CAZA.read_text()) if CAZA.exists() else {}
    carpetas = list(aguara.get("por_repo") or {})
    por_remoto = {(pistas.remoto(c)[0] or "").lower(): c for c in carpetas}   # las de Security Review traen owner/nombre
    abiertas = {}
    for i in todas():
        if i["estado"] in ("pista", "confirmada"):
            carpeta = i.get("carpeta") or por_remoto.get((i.get("repo") or "-").lower())
            if carpeta:
                abiertas[carpeta] = abiertas.get(carpeta, 0) + 1
    hoy = datetime.date.today()
    salida = []
    for carpeta, dato in (aguara.get("por_repo") or {}).items():
        puntos, motivos = 0.0, []
        if dato.get("riesgo"):
            puntos += dato["riesgo"] / 20
            motivos.append(f"riesgo Aguara {dato['riesgo']:g}/100")
        graves = sum(1 for h in aguara.get("importantes", []) if h["repo"] == carpeta)
        if graves:
            puntos += min(graves, 5)
            motivos.append(f"{graves} hallazgos graves de Aguara")
        if carpeta in (aguara.get("secretos_versionados") or {}):
            puntos += 4
            motivos.append("secretos versionados")
        n = abiertas.get(carpeta, 0)
        if n:
            puntos += 2 * min(n, 4)
            motivos.append(f"{n} investigaciones abiertas")
        ultima = caza.get(carpeta)
        dias = (hoy - datetime.date.fromisoformat(ultima)).days if ultima else None
        if dias is None:
            puntos += 4
            motivos.append("nunca se revisó a fondo")
        else:
            puntos += min(dias / 7, 4)
            motivos.append(f"revisado hace {dias} días")
        if dias is not None and dias < 7:
            puntos -= 6   # recién revisado: que le toque a otro
        salida.append({"carpeta": carpeta, "puntos": round(puntos, 1), "motivos": motivos, "ultima_revision": ultima})
    return sorted(salida, key=lambda o: (-o["puntos"], o["carpeta"]))


def cazado(carpeta):
    """Anota que hoy se revisó a fondo ese repo, para que la próxima vez le toque a otro."""
    if not (rutas.GITHUB / carpeta).is_dir():
        raise ValueError(f"no existe la carpeta {carpeta} en {rutas.GITHUB}")
    caza = json.loads(CAZA.read_text()) if CAZA.exists() else {}
    caza[carpeta] = datetime.date.today().isoformat()
    CAZA.parent.mkdir(parents=True, exist_ok=True)
    CAZA.write_text(json.dumps(caza, indent=1, sort_keys=True, ensure_ascii=False))
    return caza[carpeta]


def abrir(carpeta, titulo, severidad, afirmacion):
    """Una investigación que abre el agente por lo que encontró leyendo un repo. Arranca como pista."""
    if not (rutas.GITHUB / carpeta).is_dir():
        raise ValueError(f"no existe la carpeta {carpeta} en {rutas.GITHUB}")
    if severidad not in ("crítica", "alta", "media", "baja") or not titulo or not afirmacion:
        raise ValueError("una investigación lleva --titulo, --afirmacion y --severidad (crítica, alta, media o baja)")
    repo, rama = pistas.remoto(carpeta)
    slug = re.sub(r"[^a-z0-9]+", "-", titulo.lower()).strip("-")[:40].strip("-")
    inv = {"id": f"caza-{re.sub(r'[^a-z0-9]+', '-', carpeta.lower())[:20]}-{slug}", "fuente": "agente", "origen": f"agente:{carpeta}:{slug}",
           "repo": repo, "carpeta": carpeta, "rama": rama, "donde": carpeta, "severidad": severidad, "titulo": titulo, "afirmacion": afirmacion,
           "arreglo_sugerido": "", "estado": "pista", "evidencia": [], "citas": [], "notas": [], "sello": "",
           "proxima": "anotar la evidencia (archivo y línea) y decidir", "reabrir_si": "cambia el código citado", "creada": _ahora()}
    if _archivo(inv["id"]).exists():
        raise ValueError(f"ya existe {inv['id']}: sumale evidencia con anotar")
    guardar(inv)
    return inv


def anotar(inv_id, estado=None, tipo=None, que=None, donde="", proxima=None):
    """Lo que suma el agente después de leer: una evidencia, un cambio de estado o las dos cosas."""
    inv = leer(inv_id)
    if tipo or que:
        if tipo not in TIPOS or not que:
            raise ValueError(f"una evidencia lleva --tipo ({', '.join(TIPOS)}) y --que")
        inv["evidencia"].append(_evidencia(tipo, que, donde, quien="agente"))
    if estado:
        if estado not in ESTADOS:
            raise ValueError(f"estado desconocido: {estado} (van: {', '.join(ESTADOS)})")
        vio = any(e["tipo"] == "observado" and e.get("quien") == "agente" for e in inv["evidencia"])
        if estado == "confirmada" and not vio:
            raise ValueError("para confirmar hace falta al menos una evidencia observada por el agente: leé el código y anotá qué viste")
        if estado in ("descartada", "bloqueada") and not any(e.get("quien") == "agente" for e in inv["evidencia"]):
            raise ValueError(f"para marcarla {estado} anotá por qué (--tipo y --que)")
        inv["notas"].append(f"{_ahora()}: {inv['estado']} -> {estado}")
        inv["estado"] = estado
    if proxima:
        inv["proxima"] = proxima
    guardar(inv)
    return inv


def ficha(inv):
    """La investigación en texto, para leerla sin abrir el JSON."""
    lineas = [f"{inv['id']} · {inv['estado'].upper()} · {inv['severidad']} · {inv.get('fuente', '')} · {inv.get('repo') or inv.get('donde') or ''}", inv["titulo"], "", inv.get("afirmacion", ""), "", "Evidencia:"]
    for e in inv["evidencia"]:
        lineas.append(f"  [{e['tipo']:10}] {e['que']}" + (f"  ({e['donde']})" if e.get("donde") else "") + f"  — {e.get('quien', '?')}")
    if inv.get("arreglo_sugerido"):
        lineas += ["", "Arreglo que sugiere la fuente:", "  " + inv["arreglo_sugerido"]]
    lineas += ["", f"Próximo paso: {inv.get('proxima', '')}", f"Se reabre si: {inv.get('reabrir_si', '')}"]
    return "\n".join(lineas)


def resumen(r):
    por_estado, por_fuente = {}, {}
    for i in r["abiertas"]:
        por_estado[i["estado"]] = por_estado.get(i["estado"], 0) + 1
        por_fuente[i.get("fuente") or "?"] = por_fuente.get(i.get("fuente") or "?", 0) + 1
    lineas = [f"investigaciones: {len(r['abiertas'])} abiertas {por_estado or ''} por fuente {por_fuente or ''}, {len(r['nuevas'])} nuevas, "
              f"{len(r['reabiertas'])} reabiertas, {len(r['arregladas'])} arregladas"
              + "".join(f"  ERROR {k.rsplit(':', 1)[-1][:10]}: {v[:80]}" for k, v in r["errores"].items())]
    if r.get("objetivos"):
        o = r["objetivos"][0]
        lineas.append(f"próximo repo a revisar a fondo: {o['carpeta']} ({'; '.join(o['motivos'])})")
    return "\n".join(lineas)
