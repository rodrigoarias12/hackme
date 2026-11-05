"""Caminos de ataque: cómo llegaría alguien a lo más valioso, armado con la evidencia de la ronda.

No es una lista de controles. Se parte de lo que un atacante quiere (la base de producción, la
cuenta de AWS, los secretos de Vercel, el código) y se arman cadenas concretas con lo que la ronda
ya encontró: cada paso tiene su evidencia (hallazgo de Security Hub, GuardDuty, Vercel, Aguara,
Radar) y cada camino dice qué arreglo lo corta.

Solo junta y arma; no prueba nada contra los sistemas. El agente verifica cada paso, suma caminos
que estas reglas no ven y escribe la auditoría (skill, paso 4d). La memoria recuerda qué caminos
estaban abiertos: avisa cuando se abre uno nuevo y cuando se cierra uno.
"""
import json
import re

from . import rutas

BASE = re.compile(r"(DATABASE|DB_|POSTGRES|PG_|MYSQL|MONGO|REDIS|SUPABASE_SERVICE|CONNECTION_STRING)", re.I)


def _paso(que, evidencia, fuente):
    return {"que": que, "evidencia": evidencia, "fuente": fuente}


def _camino(cid, joya, titulo, pasos, corte, severidad, recorrido=False, fuente=""):
    return {"id": cid, "joya": joya, "titulo": titulo, "pasos": pasos, "corte": corte,
            "severidad": "crítica" if recorrido else severidad, "recorrido": recorrido, "fuente": fuente}


def _aws(ronda):
    """Por cuenta: controles de Security Hub que fallan y tipos de GuardDuty, con sus recursos."""
    cuentas = []
    for c in (ronda.get("aws") or {}).get("cuentas", []):
        if c.get("errores", {}).get("credenciales"):
            continue
        controles, guardduty = {}, {}
        for h in c.get("hallazgos", []):
            if h["servicio"] == "Security Hub" and h.get("control"):
                controles.setdefault(h["control"], []).append(h.get("recurso") or "?")
            elif h["servicio"] == "GuardDuty":
                guardduty.setdefault(h.get("tipo", ""), []).append(h)
        cuentas.append((c.get("cuenta") or c.get("perfil"), controles, guardduty))
    return cuentas


def armar(ronda):
    caminos = []

    # ── AWS ──────────────────────────────────────────────────────────────────────────────────
    for cuenta, ctl, gd in _aws(ronda):
        fuente = f"aws:{cuenta}"
        expuesta = ctl.get("RDS.46", []) + ctl.get("RDS.2", [])
        puertos = ctl.get("EC2.19", []) + ctl.get("EC2.53", []) + ctl.get("EC2.54", [])
        tanteo = sum(len(v) for k, v in gd.items() if k.startswith("Discovery:RDS/") or "RDS/MaliciousIPCaller.FailedLogin" in k)
        entraron = [h for k, v in gd.items() if "RDS/" in k and "SuccessfulLogin" in k for h in v]
        if expuesta or entraron:
            pasos = []
            if expuesta:
                pasos.append(_paso("La base de datos se puede alcanzar desde internet", ", ".join(sorted(set(expuesta)))[:200], "Security Hub RDS.46 / RDS.2"))
            if puertos:
                pasos.append(_paso("Hay security groups con puertos de riesgo abiertos a todo internet", ", ".join(sorted(set(puertos)))[:200], "Security Hub EC2.19"))
            if tanteo:
                pasos.append(_paso("IPs con antecedentes maliciosos ya la encontraron y la tantean", f"{tanteo} hallazgos de GuardDuty", "GuardDuty RDS"))
            if entraron:
                ips = sorted({ip for h in entraron for ip in h.get("ips", [])})
                pasos.append(_paso("Hubo un login exitoso desde una IP maliciosa", f"{len(entraron)} hallazgo(s); IPs {', '.join(ips[:3]) or '?'}", "GuardDuty RDS SuccessfulLogin"))
            else:
                pasos.append(_paso("Falta solo una contraseña débil, reusada o filtrada", "", "deducción"))
            caminos.append(_camino(f"{fuente}:base-desde-internet", "Base de datos de producción",
                                   "Desde internet, directo a la base", pasos,
                                   "Sacar la base de la subred pública y cerrar el puerto a internet; si hubo login sospechoso, rotar la contraseña del usuario",
                                   "alta", recorrido=bool(entraron), fuente=fuente))
        comprometidas = [h for k, v in gd.items() if k.startswith("AttackSequence:IAM") or "CompromisedCredentials" in k
                         or "InstanceCredentialExfiltration" in k for h in v]
        if comprometidas:
            caminos.append(_camino(f"{fuente}:credenciales-aws", "Cuenta de AWS", "Credenciales de AWS en manos de otro",
                                   [_paso("GuardDuty ve credenciales usadas como las usaría un atacante",
                                          "; ".join(h.get("titulo", "")[:90] for h in comprometidas[:2]), "GuardDuty")],
                                   "Confirmar quién fue; si no fue alguien del equipo, desactivar esas claves y revisar CloudTrail",
                                   "alta", recorrido=True, fuente=fuente))
        if "IAM.4" in ctl or "IAM.9" in ctl:
            pasos = []
            if "IAM.4" in ctl:
                pasos.append(_paso("La cuenta root tiene una clave de acceso", "", "Security Hub IAM.4"))
            if "IAM.9" in ctl:
                pasos.append(_paso("La cuenta root no tiene MFA", "", "Security Hub IAM.9"))
            caminos.append(_camino(f"{fuente}:root", "Cuenta de AWS", "Una sola credencial abre toda la cuenta", pasos,
                                   "Borrar la clave de root y activar MFA; trabajar con usuarios IAM", "alta", fuente=fuente))
        elif "IAM.6" in ctl:
            caminos.append(_camino(f"{fuente}:root-mfa-virtual", "Cuenta de AWS", "Root con MFA de celular, no de hardware",
                                   [_paso("Root usa MFA virtual: si roban el celular y la contraseña, entran", "", "Security Hub IAM.6")],
                                   "Llave de seguridad física para root", "media", fuente=fuente))

    # ── Vercel ───────────────────────────────────────────────────────────────────────────────
    vercel = ronda.get("vercel") or {}
    if not vercel.get("error"):
        hs = vercel.get("hallazgos", [])
        por_sufijo = {}
        for h in hs:
            partes = h["id"].split(":")  # vercel:<equipo>:<proyecto>:<chequeo> o vercel:<equipo>:chequeo:<nombre>
            clave = f"chequeo:{partes[3]}" if len(partes) > 3 and partes[2] == "chequeo" else partes[-1]
            por_sufijo.setdefault(clave, []).append(h)
        con_base = [h for h in por_sufijo.get("compartidas", []) if any(BASE.search(v) for v in h["detalle"].get("variables", []))]
        if con_base:
            proyectos = ", ".join(h["recurso"] for h in con_base[:6])
            caminos.append(_camino("vercel:base-por-una-compu", "Base de datos de producción", "Por la compu de cualquier desarrollador",
                                   [_paso("Credenciales de la base de producción también están en development", proyectos, "Vercel variables"),
                                    _paso("`vercel env pull` las deja en un archivo en la compu de cada dev", "", "cómo funciona Vercel"),
                                    _paso("Alcanza con que le roben la compu, un backup o un repo con ese archivo", "", "deducción")],
                                   "Sacar las credenciales de producción de development; cada ambiente con su propia base y usuario",
                                   "alta", fuente="vercel"))
        sin_mfa = [x for h in por_sufijo.get("chequeo:members-no-mfa", []) for x in h["detalle"].get("ejemplos", [])]
        if sin_mfa:
            caminos.append(_camino("vercel:equipo-sin-mfa", "Secretos de producción en Vercel", "Una contraseña robada abre todo el equipo",
                                   [_paso("Miembros del equipo sin MFA", ", ".join(sin_mfa), "vercel security check"),
                                    _paso("Con su contraseña se entra al equipo y se leen o cambian las variables de producción", "", "permisos de Vercel")],
                                   "MFA obligatorio para todo el equipo", "alta", fuente="vercel"))
        tokens = [x for h in por_sufijo.get("chequeo:pats-no-expiration", []) for x in h["detalle"].get("ejemplos", [])]
        if tokens:
            caminos.append(_camino("vercel:token-eterno", "Secretos de producción en Vercel", "Un token filtrado sirve para siempre",
                                   [_paso("Tokens personales sin vencimiento", ", ".join(tokens), "vercel security check")],
                                   "Reemplazarlos por tokens con vencimiento y alcance mínimo", "media", fuente="vercel"))
        nombres = sorted({h["recurso"] for h in por_sufijo.get("publicas", [])} |
                         {x for h in por_sufijo.get("chequeo:env-vars-exposed-web-app-fwk", []) for x in h["detalle"].get("ejemplos", [])})
        if nombres:
            caminos.append(_camino("vercel:secreto-en-el-navegador", "Servicios de terceros", "Abrir la página y leer la clave",
                                   [_paso("Variables con nombre de secreto que se mandan al navegador", ", ".join(nombres[:6]), "Vercel"),
                                    _paso("Cualquiera que abra la app las ve en el JavaScript", "", "cómo funciona el prefijo público")],
                                   "Mover esas claves al servidor y rotarlas", "alta", fuente="vercel"))
        previews = {h["recurso"] for h in por_sufijo.get("previews", [])}
        prod_en_preview = previews & {h["recurso"] for h in por_sufijo.get("compartidas", [])}
        if prod_en_preview:
            caminos.append(_camino("vercel:preview-abierto", "Datos de producción", "Con el link de un preview",
                                   [_paso("Previews sin protección", ", ".join(sorted(prod_en_preview)), "Vercel"),
                                    _paso("Esos previews corren con secretos de producción", "", "Vercel variables")],
                                   "Proteger los previews o no darles secretos de producción", "media", fuente="vercel"))

    # ── Código y dependencias ────────────────────────────────────────────────────────────────
    aguara = ronda.get("aguara") or {}
    for repo, archivos in (aguara.get("secretos_versionados") or {}).items():
        caminos.append(_camino(f"aguara:{repo}:secreto-en-git", "Credenciales", f"Con acceso al repo {repo}",
                               [_paso("Hay archivos de secretos guardados en git", ", ".join(archivos), "git ls-files"),
                                _paso("Quedan en el historial aunque se borren: cualquiera con acceso al repo los tiene", "", "cómo funciona git")],
                               "Rotar esas credenciales y sacarlas del historial", "alta", fuente="aguara"))
    for c in (ronda.get("radar") or {}).get("candidatos", []):
        fuertes = [x for x in c.get("coincidencias", []) if x.get("fuerza") == "version-afectada"]
        if fuertes and c.get("explotacion") == "exploited":
            caminos.append(_camino(f"radar:{c['slug']}", "Servidores y apps", "Una vulnerabilidad que ya se está explotando",
                                   [_paso("Usás una versión afectada", ", ".join(f"{x['nombre']} {x.get('version') or ''} en {x['donde']}" for x in fuertes[:3]), "Radar + OSV"),
                                    _paso("Hay ataques reales usándola" + (" (está en el catálogo KEV de CISA)" if c.get("kev") else ""), c.get("url", ""), "Oktsec Radar")],
                                   c.get("accion") or "Actualizar a la versión corregida", "alta", fuente="radar"))
    return caminos


def correr(ronda):
    """Arma los caminos y los compara con los de la ronda anterior: nuevos, siguen y cerrados."""
    actuales = armar(ronda)
    archivo = rutas.MEMORIA / "caminos-visto.json"
    previos = json.loads(archivo.read_text()) if archivo.exists() else None
    fuentes_ok = {c["fuente"] for c in actuales}
    # Una fuente que no corrió hoy (credenciales vencidas, sin AWS) no puede "cerrar" sus caminos.
    for c in (ronda.get("aws") or {}).get("cuentas", []):
        if not c.get("errores", {}).get("credenciales"):
            fuentes_ok.add(f"aws:{c.get('cuenta') or c.get('perfil')}")
    if not (ronda.get("vercel") or {}).get("error"):
        fuentes_ok.add("vercel")
    fuentes_ok |= {"aguara", "radar"}
    for c in actuales:
        c["estado"] = "línea de base" if previos is None else ("visto" if c["id"] in previos else "nuevo")
    cerrados = [] if previos is None else [
        {"id": cid, **datos} for cid, datos in previos.items()
        if cid not in {c["id"] for c in actuales} and datos.get("fuente") in fuentes_ok]
    memoria = {} if previos is None else {cid: d for cid, d in previos.items() if d.get("fuente") not in fuentes_ok}
    memoria.update({c["id"]: {"titulo": c["titulo"], "joya": c["joya"], "fuente": c["fuente"]} for c in actuales})
    rutas.MEMORIA.mkdir(parents=True, exist_ok=True)
    archivo.write_text(json.dumps(memoria, ensure_ascii=False, indent=0, sort_keys=True))
    orden = {"crítica": 0, "alta": 1, "media": 2}
    actuales.sort(key=lambda c: (orden.get(c["severidad"], 3), c["joya"]))
    return {"abiertos": actuales, "cerrados": cerrados, "primera_corrida": previos is None}


def resumen(r):
    por_sev = {}
    for c in r["abiertos"]:
        por_sev[c["severidad"]] = por_sev.get(c["severidad"], 0) + 1
    nuevos = [c for c in r["abiertos"] if c["estado"] == "nuevo"]
    lineas = [f"caminos: {len(r['abiertos'])} abiertos {por_sev}, {len(nuevos)} nuevos, {len(r['cerrados'])} cerrados"]
    lineas += [f"  {c['severidad']:7} {c['joya']} ← {c['titulo']}" + ("  [YA RECORRIDO]" if c["recorrido"] else "") for c in r["abiertos"]]
    lineas += [f"  cerrado  {c['joya']} ← {c['titulo']}" for c in r["cerrados"]]
    return "\n".join(lineas)
