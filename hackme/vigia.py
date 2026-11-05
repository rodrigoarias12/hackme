"""Vigía: la guardia cada 15 minutos. Avisa por Telegram mientras pasa un ataque.

La ronda diaria ve el estado (qué tenés instalado, qué está mal configurado). El vigía ve lo que
está pasando: alguien barriendo rutas, probando logins, entrando como root a AWS, apagando logs.
Es determinístico (sin IA): lee, cuenta, compara con umbrales y avisa. Cada detección tiene su
fila en docs/detecciones.md con la fuente de la que sale.

De dónde lee, todo en solo lectura:
  - apps: consultas SQL que el dueño escribe en $HACKME_PRIVADO/vigia.json (el esquema de cada
    app es privado, este repo no lo conoce). Corren con `psql` dentro de una transacción READ ONLY
    y con un usuario que debería ser de solo lectura. La conexión vive en
    ~/.config/hackme/vigia.env, nunca en un repo.
  - AWS: CloudTrail (eventos de escritura) y GuardDuty de cualquier severidad para los tipos que
    importan aunque sean "Low" (uso de root, credenciales robadas, logs apagados).

Avisa una vez por clave por día y con un tope diario: quien ataca con un script no puede inundar
el chat ni tapar lo demás. Nunca bloquea nada.
"""
import datetime as dt
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import urllib.parse
from pathlib import Path

from . import avisar, aws, rutas

CONFIG = Path(os.environ.get("HACKME_VIGIA", rutas.PRIVADO / "vigia.json"))
CONEXIONES = Path.home() / ".config" / "hackme" / "vigia.env"
MEMORIA = rutas.PRIVADO / "memoria" / "vigia"

VENTANA_MIN = 15          # cada corrida mira los últimos 15 minutos
VENTANA_AWS_MIN = 30      # CloudTrail llega con hasta ~15 min de atraso: se mira más atrás
TOPE_DIARIO = 25
HISTORIA = 7 * 24 * 4     # una semana de corridas, para la línea de base

# Umbrales. Los marcados [S] salen de la fuente; el resto [M] son un punto de partida
# (docs/detecciones.md). Se pisan por app con "umbrales" en vigia.json.
UMBRALES = {
    "rechazos_404_por_ip": 50,       # A8 [M]
    "rutas_por_ip": 20,              # A8 [M]
    "firewall_piso": 500,            # A11 [M]
    "factor_sobre_base": 3,          # A3, A11 [M]
    "fallos_por_cuenta": 5,          # A1 [M]
    "cuentas_por_ip": 10,            # A2 [M]
    "intentos_por_ip": 20,           # A2 [M]
    "fallos_piso": 20,               # A3 [M]
    "exito_tras_fallos": 5,          # A4 [M]
    "denegados_por_ip": 3,           # A5 [M]
    "dormida_dias": 45,              # E1 [S] CIS Controls 5.3
    "inactiva_dias": 30,             # E1 [M]
    "reciente_dias": 10,             # E1 [M]
    "aws_logins_fallidos": 3,        # B8 [M]
    "aws_denegados_por_actor": 10,   # B9 [M]
}

# A9: lo que pide un escáner y no un cliente legítimo.
RUTA_DE_ESCANER = re.compile(
    r"(/\.env|/\.git/|/\.aws/|/\.svn/|/\.ds_store|/wp-(admin|login|content|includes)|/xmlrpc\.php|phpmyadmin|"
    r"/server-status|/actuator|/cgi-bin/|/vendor/phpunit|/config\.(json|ya?ml|php)|\.php$|\.sql$|/backup)", re.I)
AGENTE_DE_ESCANER = re.compile(
    r"(sqlmap|nikto|nuclei|zgrab|masscan|gobuster|ffuf|dirbuster|dirb/|wpscan|wfuzz|feroxbuster|nmap|acunetix|"
    r"netsparker|openvas|whatweb|jaeles|zmeu|hydra)", re.I)
FIREWALL = {"deny", "challenge", "rate_limit"}

# CIS AWS Foundations v5, sección 4 (CloudWatch.1–14): eventos de escritura que se avisan con ≥ 1.
EVENTOS_AWS = {
    "C1": ("CloudTrail cambiado o apagado", {
        "CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging", "PutEventSelectors"}),
    "C2": ("Permisos de IAM cambiados", {
        "DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy", "PutGroupPolicy", "PutRolePolicy",
        "PutUserPolicy", "CreatePolicy", "DeletePolicy", "CreatePolicyVersion", "DeletePolicyVersion",
        "SetDefaultPolicyVersion", "AttachRolePolicy", "DetachRolePolicy", "AttachUserPolicy",
        "DetachUserPolicy", "AttachGroupPolicy", "DetachGroupPolicy", "UpdateAccountPasswordPolicy",
        "DeleteAccountPasswordPolicy"}),
    "C3": ("Clave KMS deshabilitada o por borrarse", {"DisableKey", "ScheduleKeyDeletion"}),
    "C4": ("Permisos de un bucket S3 cambiados", {
        "PutBucketAcl", "PutBucketPolicy", "PutBucketCors", "PutBucketLifecycle", "PutBucketReplication",
        "DeleteBucketPolicy", "DeleteBucketCors", "DeleteBucketLifecycle", "DeleteBucketReplication",
        "PutPublicAccessBlock", "DeletePublicAccessBlock", "PutAccountPublicAccessBlock"}),
    "C5": ("AWS Config cambiado o apagado", {
        "StopConfigurationRecorder", "DeleteDeliveryChannel", "PutDeliveryChannel", "PutConfigurationRecorder"}),
    "C6": ("Red cambiada (security groups, ACLs, gateways, rutas, VPC)", {
        "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress", "CreateSecurityGroup", "DeleteSecurityGroup", "CreateNetworkAcl",
        "CreateNetworkAclEntry", "DeleteNetworkAcl", "DeleteNetworkAclEntry", "ReplaceNetworkAclEntry",
        "ReplaceNetworkAclAssociation", "CreateCustomerGateway", "DeleteCustomerGateway",
        "AttachInternetGateway", "CreateInternetGateway", "DeleteInternetGateway", "DetachInternetGateway",
        "CreateRoute", "CreateRouteTable", "ReplaceRoute", "ReplaceRouteTableAssociation", "DeleteRouteTable",
        "DeleteRoute", "DisassociateRouteTable", "CreateVpc", "DeleteVpc", "ModifyVpcAttribute",
        "AcceptVpcPeeringConnection", "CreateVpcPeeringConnection", "DeleteVpcPeeringConnection",
        "RejectVpcPeeringConnection"}),
    "C8": ("Un detector de seguridad apagado", {
        "DisableSecurityHub", "DeleteDetector", "DisassociateFromMasterAccount", "StopMonitoringMembers"}),
    "B10": ("Usuario o clave de IAM nueva", {"CreateUser", "CreateLoginProfile", "UpdateLoginProfile", "CreateAccessKey"}),
    "C9": ("Base de datos expuesta o copiada", {
        "CreateDBSnapshot", "CopyDBSnapshot", "ModifyDBSnapshotAttribute", "CreateDBClusterSnapshot"}),
}

# GuardDuty: estos tipos se avisan con cualquier severidad (la ronda diaria solo mira 4+).
GUARDDUTY_SIEMPRE = re.compile(
    r"(RootCredentialUsage|^CredentialAccess:|^Stealth:|^Exfiltration:|^Impact:|^PenTest:|TorIPCaller|"
    r"MaliciousIPCaller|InstanceCredentialExfiltration|BucketAnonymousAccessGranted|BucketPublicAccessGranted|"
    r"ConsoleLoginSuccess)")


def _alerta(clave, deteccion, titulo, detalle):
    return {"clave": clave, "deteccion": deteccion, "titulo": titulo, "detalle": detalle}


def _sobre_base(valor, historia, piso, factor):
    """Pasa el piso y, con una semana de historia, también `factor` veces la mediana."""
    if valor < piso:
        return False
    if len(historia) < 8:
        return True
    return valor > factor * max(statistics.median(historia), 1)


# ── Detecciones (funciones puras: filas -> alertas) ───────────────────────────────────────────


def detectar_accesos(app, filas, u, historia_firewall):
    """A8 barrido de rutas, A9 huella de escáner, A11 pico del firewall.

    Filas: cuando, ip, metodo, ruta, estado, user_agent, waf_accion.
    Devuelve (alertas, total del firewall para la historia).
    """
    por_ip = {}
    firewall = 0
    for f in filas:
        ip = f.get("ip") or "sin-ip"
        d = por_ip.setdefault(ip, {"404": 0, "rutas": set(), "escaner": set(), "agente": None, "firewall": 0})
        estado = f.get("estado") or 0
        ruta = f.get("ruta") or ""
        if estado == 404:
            d["404"] += 1
        if 400 <= estado < 500:
            d["rutas"].add(ruta)
        if RUTA_DE_ESCANER.search(ruta):
            d["escaner"].add(ruta)
        agente = f.get("user_agent") or ""
        if AGENTE_DE_ESCANER.search(agente):
            d["escaner"].add(f"user agent {agente[:60]}")
        d["agente"] = d["agente"] or agente[:80] or None
        if (f.get("waf_accion") or "") in FIREWALL:
            firewall += 1
            d["firewall"] += 1

    alertas = []
    for ip, d in por_ip.items():
        motivos, detecciones = [], []
        if d["404"] >= u["rechazos_404_por_ip"] or len(d["rutas"]) >= u["rutas_por_ip"]:
            motivos.append(f"probó {len(d['rutas'])} rutas distintas que fueron rechazadas ({d['404']} no existen)")
            detecciones.append("A8")
        if d["escaner"]:
            motivos.append("pidió cosas que solo pide un escáner: " + ", ".join(sorted(d["escaner"])[:4]))
            detecciones.append("A9")
        if not motivos:
            continue
        ejemplos = ", ".join(sorted(d["rutas"])[:5])
        alertas.append(_alerta(
            f"{app}:ip:{ip}", "+".join(detecciones), f"{app}: te están escaneando desde {ip}",
            f"En los últimos {VENTANA_MIN} min {' y '.join(motivos)}."
            + (f" Ejemplos: {ejemplos}." if ejemplos else "")
            + (f" El firewall frenó {d['firewall']}." if d["firewall"] else "")
            + (f" Se presenta como: {d['agente']}." if d["agente"] else "")))

    if _sobre_base(firewall, historia_firewall, u["firewall_piso"], u["factor_sobre_base"]):
        ips = sorted(por_ip, key=lambda i: -por_ip[i]["firewall"])[:3]
        alertas.append(_alerta(
            f"{app}:firewall", "A11", f"{app}: el firewall está frenando mucho más de lo normal",
            f"{firewall} pedidos frenados en {VENTANA_MIN} min. Las IPs que más: {', '.join(ips)}."))
    return alertas, firewall


def detectar_logins(app, filas, u, historia_fallos, paises, dominios_propios):
    """A1, A2, A3, A4, A5 y A6 sobre los intentos de entrada.

    Filas: cuando, cuenta, ip, resultado ('ok' | 'fallo' | 'denegado'), pais.
    `paises` es {cuenta: [países vistos]} y se actualiza acá.
    Devuelve (alertas, total de fallos para la historia).
    """
    filas = sorted(filas, key=lambda f: str(f.get("cuando") or ""))
    por_cuenta, por_ip = {}, {}
    fallos_antes_cuenta, fallos_antes_ip = {}, {}
    alertas, total_fallos = [], 0
    for f in filas:
        cuenta = (f.get("cuenta") or "desconocida").lower()
        ip = f.get("ip") or "sin-ip"
        r = f.get("resultado")
        c = por_cuenta.setdefault(cuenta, {"fallos": 0, "ips": set()})
        i = por_ip.setdefault(ip, {"intentos": 0, "cuentas": set(), "denegados": 0, "pais": f.get("pais")})
        if r in ("fallo", "denegado"):
            total_fallos += 1
            c["fallos"] += 1
            c["ips"].add(ip)
            i["intentos"] += 1
            i["cuentas"].add(cuenta)
            fallos_antes_cuenta[cuenta] = fallos_antes_cuenta.get(cuenta, 0) + 1
            fallos_antes_ip[ip] = fallos_antes_ip.get(ip, 0) + 1
        if r == "denegado":
            i["denegados"] += 1
            if any(cuenta.endswith("@" + d.lower()) for d in dominios_propios):
                alertas.append(_alerta(
                    f"{app}:denegado-propio:{cuenta}", "A5", f"{app}: {cuenta} intentó entrar y no tiene acceso",
                    f"Es una cuenta de tu propio dominio. Si la persona ya no trabaja con vos, revisá que no "
                    f"tenga acceso en otro lado. IP {ip}{_pais(f)}."))
        if r == "ok":
            previos = max(fallos_antes_cuenta.get(cuenta, 0), fallos_antes_ip.get(ip, 0))
            if previos >= u["exito_tras_fallos"]:
                alertas.append(_alerta(
                    f"{app}:entro-tras-fallos:{cuenta}", "A4", f"{app}: {cuenta} entró después de {previos} intentos fallidos",
                    f"Desde {ip}{_pais(f)}. Es el patrón de alguien que adivinó: confirmá con la persona."))
            pais = f.get("pais")
            if pais:
                vistos = paises.setdefault(cuenta, [])
                if vistos and pais not in vistos:
                    alertas.append(_alerta(
                        f"{app}:pais:{cuenta}:{pais}", "A6", f"{app}: {cuenta} entró desde un país nuevo ({pais})",
                        f"Antes solo desde {', '.join(vistos)}. IP {ip}. ¿Está de viaje?"))
                if pais not in vistos:
                    vistos.append(pais)

    for cuenta, c in por_cuenta.items():
        if c["fallos"] >= u["fallos_por_cuenta"]:
            alertas.append(_alerta(
                f"{app}:cuenta:{cuenta}", "A1", f"{app}: {c['fallos']} intentos fallidos contra {cuenta}",
                f"En {VENTANA_MIN} min, desde {', '.join(sorted(c['ips'])[:3])}."))
    for ip, i in por_ip.items():
        if len(i["cuentas"]) >= u["cuentas_por_ip"] or i["intentos"] >= u["intentos_por_ip"]:
            alertas.append(_alerta(
                f"{app}:spray:{ip}", "A2", f"{app}: {ip} está probando muchas cuentas",
                f"{i['intentos']} intentos contra {len(i['cuentas'])} cuentas en {VENTANA_MIN} min"
                f"{' (' + i['pais'] + ')' if i['pais'] else ''}. Es password spraying o credential stuffing."))
        elif i["denegados"] >= u["denegados_por_ip"]:
            alertas.append(_alerta(
                f"{app}:denegado:{ip}", "A5", f"{app}: {ip} insiste en entrar sin tener acceso",
                f"{i['denegados']} intentos denegados en {VENTANA_MIN} min con {len(i['cuentas'])} cuentas: "
                f"{', '.join(sorted(i['cuentas'])[:3])}."))
    if _sobre_base(total_fallos, historia_fallos, u["fallos_piso"], u["factor_sobre_base"]) and \
            len(por_ip) >= 5:
        alertas.append(_alerta(
            f"{app}:ola-de-fallos", "A3", f"{app}: ola de intentos fallidos desde muchas IPs",
            f"{total_fallos} intentos fallidos desde {len(por_ip)} IPs en {VENTANA_MIN} min. "
            f"Puede ser credential stuffing repartido."))
    return alertas, total_fallos


def detectar_silencio(app, ultimo, minutos, ahora):
    """C13: la fuente dejó de mandar datos (un drain roto, o alguien que apagó los logs)."""
    if not ultimo:
        return []
    cuando = _fecha(ultimo)
    if cuando is None or (ahora - cuando).total_seconds() < minutos * 60:
        return []
    horas = (ahora - cuando).total_seconds() / 3600
    return [_alerta(f"{app}:silencio", "C13", f"{app}: el registro de accesos dejó de recibir datos",
                    f"El último dato es de hace {horas:.1f} h. O el log drain se rompió, o alguien lo apagó.")]


def detectar_cuentas(app, filas, u, ahora):
    """E1, una vez por día: cuentas dormidas y cuentas que entran y no hacen nada.

    Filas: cuenta, rol, creada, ultimo_login y, si la app la tiene, ultima_accion.
    """
    dormidas, quietas, sin_dato = [], [], 0
    tiene_acciones = any("ultima_accion" in f for f in filas)
    for f in filas:
        login = _fecha(f.get("ultimo_login"))
        if login is None:  # sin dato no es "dormida": no se sabe
            sin_dato += 1
            continue
        if (ahora - login).days >= u["dormida_dias"]:
            dormidas.append(f.get("cuenta"))
        elif tiene_acciones and (ahora - login).days <= u["reciente_dias"]:
            accion = _fecha(f.get("ultima_accion"))
            if accion is None or (ahora - accion).days >= u["inactiva_dias"]:
                quietas.append(f.get("cuenta"))
    alertas = []
    if dormidas:
        alertas.append(_alerta(
            f"{app}:dormidas", "E1", f"{app}: {len(dormidas)} cuentas con acceso que no se usan hace {u['dormida_dias']}+ días",
            "Siguen pudiendo entrar. Si no las necesitan, sacales el rol: " + ", ".join(dormidas[:10])
            + (" …" if len(dormidas) > 10 else "")))
    if quietas:
        alertas.append(_alerta(
            f"{app}:quietas", "E1", f"{app}: {len(quietas)} cuentas entraron en los últimos {u['reciente_dias']} días y no hicieron nada",
            "Entrar sin hacer nada en un mes puede ser alguien mirando con una cuenta que no es suya: "
            + ", ".join(quietas[:10]) + (" …" if len(quietas) > 10 else "")))
    if filas and sin_dato == len(filas):
        alertas.append({**_alerta(
            f"{app}:sin-logins", "E1", f"{app}: la app no guarda los logins exitosos",
            "Ninguna cuenta tiene fecha de último login: no se puede saber quién entró ni detectar cuentas "
            "que entran y no hacen nada. Hay que registrar el login exitoso en la app."), "una_vez": True})
    return alertas


def detectar_cloudtrail(cuenta, eventos, u):
    """B7 root, B8 login a la consola sin MFA o fallido, B9 llamadas denegadas, y los cambios de CIS."""
    grupos, fallidos, denegados = {}, {}, {}
    alertas = []
    for e in eventos:
        nombre = e.get("eventName", "")
        ident = e.get("userIdentity") or {}
        actor = ident.get("arn") or ident.get("userName") or ident.get("type") or "?"
        ip = e.get("sourceIPAddress", "?")
        if ident.get("type") == "AWSService" or e.get("eventType") == "AwsServiceEvent":
            continue
        if ident.get("type") == "Root" and not ident.get("invokedBy"):
            alertas.append(_alerta(
                f"aws:{cuenta}:root:{nombre}", "B7", f"AWS {cuenta}: alguien usó la cuenta root ({nombre})",
                f"Desde {ip}. La root no debería usarse nunca para el día a día. ¿Fuiste vos?"))
        if nombre == "ConsoleLogin":
            resultado = (e.get("responseElements") or {}).get("ConsoleLogin")
            if resultado == "Success" and (e.get("additionalEventData") or {}).get("MFAUsed") != "Yes":
                alertas.append(_alerta(
                    f"aws:{cuenta}:sin-mfa:{actor}", "B8", f"AWS {cuenta}: entraron a la consola sin MFA",
                    f"{actor} desde {ip}."))
            elif resultado == "Failure":
                fallidos.setdefault(ip, []).append(actor)
            continue
        if e.get("errorCode") and re.search(r"(UnauthorizedOperation|AccessDenied)", e["errorCode"]):
            denegados.setdefault(actor, []).append(nombre)
            continue
        if e.get("errorCode"):
            continue
        for det, (titulo, nombres) in EVENTOS_AWS.items():
            if nombre in nombres:
                grupos.setdefault((det, actor), []).append((nombre, ip))
        if e.get("eventSource") == "organizations.amazonaws.com":
            grupos.setdefault(("C7", actor), []).append((nombre, ip))
        if nombre == "ModifyDBInstance" and (e.get("requestParameters") or {}).get("publiclyAccessible") is True:
            grupos.setdefault(("C9", actor), []).append((nombre + " (pública)", ip))

    titulos = {**{d: t for d, (t, _) in EVENTOS_AWS.items()}, "C7": "Cambios en AWS Organizations"}
    for (det, actor), cambios in grupos.items():
        nombres = sorted({n for n, _ in cambios})
        ips = sorted({i for _, i in cambios})
        alertas.append(_alerta(
            f"aws:{cuenta}:{det}:{actor}", det, f"AWS {cuenta}: {titulos[det]}",
            f"{actor} hizo {len(cambios)} cambios: {', '.join(nombres[:6])}. Desde {', '.join(ips[:3])}. "
            "Si no fue alguien del equipo, es grave."))
    for ip, actores in fallidos.items():
        if len(actores) >= u["aws_logins_fallidos"]:
            alertas.append(_alerta(
                f"aws:{cuenta}:login-fallido:{ip}", "B8", f"AWS {cuenta}: {len(actores)} logins fallidos a la consola",
                f"Desde {ip}, con {', '.join(sorted(set(actores))[:3])}."))
    for actor, nombres in denegados.items():
        if len(nombres) >= u["aws_denegados_por_actor"]:
            alertas.append(_alerta(
                f"aws:{cuenta}:denegado:{actor}", "B9", f"AWS {cuenta}: {actor} intenta cosas que no tiene permitidas",
                f"{len(nombres)} llamadas rechazadas: {', '.join(sorted(set(nombres))[:6])}. "
                "Una credencial robada prueba qué puede hacer."))
    return alertas


def detectar_guardduty(cuenta, hallazgos):
    """B7, B11, B12 y C1–C10 desde GuardDuty: severidad 7+ o un tipo de GUARDDUTY_SIEMPRE."""
    # Uno por tipo y recurso: GuardDuty abre un hallazgo por IP, y cinco IPs tanteando la misma
    # base son un solo aviso.
    grupos = {}
    for h in hallazgos:
        tipo, sev = h.get("Type", ""), h.get("Severity", 0)
        if sev < 7 and not GUARDDUTY_SIEMPRE.search(tipo):
            continue
        recurso = h.get("Resource") or {}
        nombre = (recurso.get("RdsDbInstanceDetails") or {}).get("DbInstanceIdentifier") or \
            (recurso.get("AccessKeyDetails") or {}).get("UserName") or recurso.get("ResourceType", "?")
        g = grupos.setdefault((tipo, nombre), {"titulo": h.get("Title", tipo), "sev": 0, "veces": 0,
                                               "ips": set(), "origen": set()})
        g["sev"] = max(g["sev"], sev)
        g["veces"] += (h.get("Service") or {}).get("Count", 1)
        aws._ips(h.get("Service") or {}, g)
    alertas = []
    for (tipo, nombre), g in grupos.items():
        ips = sorted(g["ips"])
        alertas.append(_alerta(
            f"aws:{cuenta}:gd:{tipo}:{nombre}", "GuardDuty", f"AWS {cuenta}: {g['titulo']}",
            f"{tipo} sobre {nombre}, severidad {g['sev']}, {g['veces']} veces"
            + (f" desde {len(ips)} IPs ({', '.join(ips[:4])})" if ips else "")
            + (f", {', '.join(sorted(g['origen'])[:3])}" if g["origen"] else "") + "."))
    return alertas


# ── Lectura ─────────────────────────────────────────────────────────────────────────────────


def _fecha(valor):
    if not valor:
        return None
    if isinstance(valor, dt.datetime):
        return valor if valor.tzinfo else valor.replace(tzinfo=dt.timezone.utc)
    texto = str(valor).replace(" ", "T").replace("Z", "+00:00")
    if re.search(r"[+-]\d\d$", texto):
        texto += ":00"
    try:
        d = dt.datetime.fromisoformat(texto)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def _pais(f):
    return f" ({f['pais']})" if f.get("pais") else ""


def _conexion(nombre):
    """La URL de Postgres, desde el ambiente o vigia.env. Se pasa a psql por variables PG*, no
    por la línea de comandos: así no aparece en `ps`."""
    url = avisar.leer_env(CONEXIONES, (nombre,))[nombre]
    if not url:
        raise RuntimeError(f"falta {nombre} en el ambiente o en {CONEXIONES}")
    p = urllib.parse.urlsplit(url)
    env = {"PGHOST": p.hostname or "", "PGPORT": str(p.port or 5432), "PGDATABASE": p.path.lstrip("/"),
           "PGUSER": urllib.parse.unquote(p.username or ""), "PGPASSWORD": urllib.parse.unquote(p.password or ""),
           "PGCONNECT_TIMEOUT": "10", "PGAPPNAME": "hackme-vigia",
           "PGTZ": "UTC"}  # las columnas `timestamp` sin zona se comparan en UTC, como las guarda la app
    for clave, valor in urllib.parse.parse_qsl(p.query):
        if clave == "sslmode":
            env["PGSSLMODE"] = valor
    env.setdefault("PGSSLMODE", "require")
    return env


def consultar(conexion, sql, desde):
    """Corre una consulta en una transacción READ ONLY y devuelve las filas como dicts."""
    q = sql.replace("{desde}", f"'{desde.isoformat()}'::timestamptz")
    env = {**os.environ, **_conexion(conexion)}
    r = subprocess.run(
        ["psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
         "-c", "SET statement_timeout = '20s'",
         "-c", "BEGIN TRANSACTION READ ONLY",
         "-c", f"SELECT coalesce(json_agg(t), '[]'::json) FROM ({q}) t",
         "-c", "COMMIT"],
        capture_output=True, text=True, timeout=60, env=env)
    if r.returncode != 0:
        # La primera línea del error de psql no lleva la contraseña; se corta por las dudas.
        raise RuntimeError((r.stderr.strip().splitlines() or [f"exit {r.returncode}"])[0][:200])
    # json_agg separa las filas con saltos de línea; con -q psql no imprime nada más.
    salida = r.stdout.strip()
    return json.loads(salida[salida.find("["):]) if "[" in salida else []


def _aws(perfil, region, *args):
    env = dict(os.environ, AWS_REGION=region, AWS_PAGER="")
    if perfil:
        env["AWS_PROFILE"] = perfil
    r = subprocess.run(["aws", *args, "--output", "json"], capture_output=True, text=True, timeout=120, env=env)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip().splitlines()[-1] if r.stderr.strip() else f"exit {r.returncode}")
    return json.loads(r.stdout or "{}")


def leer_aws(perfil, region, desde):
    cuenta = _aws(perfil, region, "sts", "get-caller-identity").get("Account", "?")
    crudos = _aws(perfil, region, "cloudtrail", "lookup-events", "--start-time", desde.isoformat(),
                  "--lookup-attributes", "AttributeKey=ReadOnly,AttributeValue=false",
                  "--max-items", "2000").get("Events", [])
    eventos = []
    for c in crudos:
        try:
            eventos.append(json.loads(c["CloudTrailEvent"]))
        except (KeyError, ValueError):
            pass
    hallazgos = []
    detectores = _aws(perfil, region, "guardduty", "list-detectors").get("DetectorIds", [])
    for det in detectores:
        criterio = json.dumps({"Criterion": {"service.archived": {"Eq": ["false"]},
                                             "updatedAt": {"Gte": int(desde.timestamp() * 1000)}}})
        ids = _aws(perfil, region, "guardduty", "list-findings", "--detector-id", det,
                   "--finding-criteria", criterio, "--max-items", "50").get("FindingIds", [])
        if ids:
            hallazgos += _aws(perfil, region, "guardduty", "get-findings", "--detector-id", det,
                              "--finding-ids", *ids).get("Findings", [])
    return cuenta, eventos, hallazgos


# ── Estado, deduplicación y avisos ──────────────────────────────────────────────────────────


def _cargar(nombre, defecto):
    p = MEMORIA / nombre
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return defecto


def _guardar(nombre, valor):
    MEMORIA.mkdir(parents=True, exist_ok=True)
    (MEMORIA / nombre).write_text(json.dumps(valor, indent=0, sort_keys=True, ensure_ascii=False))


def _notificar_mac(titulo, texto):
    if sys.platform != "darwin" or not shutil.which("osascript"):
        return False
    limpio = lambda s: s.replace("\\", " ").replace('"', "'")[:200]  # noqa: E731
    r = subprocess.run(["osascript", "-e", f'display notification "{limpio(texto)}" with title "{limpio(titulo)}"'],
                       capture_output=True, timeout=10)
    return r.returncode == 0


def correr(enviar=True, ahora=None):
    """Una pasada. Con enviar=False imprime lo que avisaría y no guarda nada."""
    ahora = ahora or dt.datetime.now(dt.timezone.utc)
    hoy = ahora.astimezone().date().isoformat()
    cfg = json.loads(CONFIG.read_text()) if CONFIG.exists() else {"apps": []}
    estado = _cargar("estado.json", {})
    paises = _cargar("paises.json", {})
    alertas, errores, leido = [], {}, []

    def fallo(fuente, e):
        errores[fuente] = str(e)
        racha = estado.setdefault("rachas", {})
        racha[fuente] = racha.get(fuente, 0) + 1
        if racha[fuente] == 3:  # 45 minutos sin poder leer: se avisa una vez
            alertas.append(_alerta(f"error:{fuente}", "C13", f"El vigía no puede leer {fuente}", str(e)[:200]))

    desde = ahora - dt.timedelta(minutes=VENTANA_MIN)
    for app in cfg.get("apps", []):
        nombre = app["nombre"]
        u = {**UMBRALES, **app.get("umbrales", {})}
        hist = estado.setdefault("historia", {}).setdefault(nombre, {"firewall": [], "fallos": []})
        for parte in ("accesos", "logins", "ultimo"):
            if not app.get(parte):
                continue
            fuente = f"{nombre}:{parte}"
            try:
                filas = consultar(app["conexion"], app[parte], desde)
            except (RuntimeError, ValueError, subprocess.TimeoutExpired, OSError) as e:
                fallo(fuente, e)
                continue
            estado.setdefault("rachas", {})[fuente] = 0
            leido.append(f"{fuente} {len(filas)}")
            if parte == "accesos":
                nuevas, total = detectar_accesos(nombre, filas, u, hist["firewall"])
                hist["firewall"] = (hist["firewall"] + [total])[-HISTORIA:]
            elif parte == "logins":
                nuevas, total = detectar_logins(nombre, filas, u, hist["fallos"], paises.setdefault(nombre, {}),
                                                app.get("dominios_propios", []))
                hist["fallos"] = (hist["fallos"] + [total])[-HISTORIA:]
            else:
                nuevas = detectar_silencio(nombre, (filas[0] if filas else {}).get("ultimo"),
                                           app.get("silencio_min", 360), ahora)
            alertas += nuevas
        if app.get("cuentas") and estado.get("cuentas", {}).get(nombre) != hoy:
            try:
                filas = consultar(app["conexion"], app["cuentas"], desde)
                alertas += detectar_cuentas(nombre, filas, u, ahora)
                estado.setdefault("cuentas", {})[nombre] = hoy
                leido.append(f"{nombre}:cuentas {len(filas)}")
            except (RuntimeError, ValueError, subprocess.TimeoutExpired, OSError) as e:
                fallo(f"{nombre}:cuentas", e)

    perfiles = os.environ.get("HACKME_VIGIA_AWS", os.environ.get("HACKME_AWS", "default:us-east-1"))
    if shutil.which("aws") and perfiles:
        desde_aws = ahora - dt.timedelta(minutes=VENTANA_AWS_MIN)
        for par in filter(None, perfiles.split(",")):
            perfil, _, region = par.partition(":")
            fuente = f"aws:{perfil or 'ambiente'}:{region}"
            try:
                cuenta, eventos, hallazgos = leer_aws(perfil, region, desde_aws)
            except (RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
                fallo(fuente, e)
                continue
            estado.setdefault("rachas", {})[fuente] = 0
            leido.append(f"{fuente} {len(eventos)} eventos, {len(hallazgos)} guardduty")
            alertas += detectar_cloudtrail(cuenta, eventos, UMBRALES) + detectar_guardduty(cuenta, hallazgos)

    # IPs conocidas: se nombran en el aviso, pero se avisa igual (root desde la casa de un socio
    # sigue siendo root).
    for ip, quien in cfg.get("ips_conocidas", {}).items():
        patron = re.compile(rf"(?<![\d.]){re.escape(ip)}(?!\.?\d)")  # "1.2.3.4." sí, "1.2.3.45" no
        for a in alertas:
            for campo in ("titulo", "detalle"):
                a[campo] = patron.sub(f"{ip} ({quien})", a[campo])

    # Una vez por clave por día, y con tope. Los días viejos se olvidan.
    avisados = {d: v for d, v in _cargar("avisados.json", {}).items() if d >= (ahora - dt.timedelta(days=2)).date().isoformat()}
    hoy_avisados = avisados.setdefault(hoy, [])
    salen, nuevas = [], []
    una_vez = estado.setdefault("una_vez", [])  # avisos de un dato que falta: se dicen una sola vez
    for a in alertas:
        if a["clave"] in hoy_avisados or a["clave"] in una_vez:
            continue
        if a.get("una_vez"):
            una_vez.append(a["clave"])
        hoy_avisados.append(a["clave"])
        nuevas.append(a)
        if len(hoy_avisados) <= TOPE_DIARIO:
            salen.append(a)
        elif len(hoy_avisados) == TOPE_DIARIO + 1:
            salen.append(_alerta("tope", "-", "Muchas alertas hoy",
                                 f"Se llegó a {TOPE_DIARIO} avisos. Los que siguen quedan en memoria/vigia sin avisar."))
    canal = None
    for a in salen:
        texto = f"🚨 {a['titulo']}\n\n{a['detalle']}\n\n[{a['deteccion']} · hackme vigía]"
        if not enviar:
            print(texto, end="\n\n")
            continue
        ok = avisar.mandar(texto)
        canal = "telegram" if ok else ("mac" if _notificar_mac(a["titulo"], a["detalle"]) else "ninguno")
        a["canal"] = canal

    if enviar:
        MEMORIA.mkdir(parents=True, exist_ok=True)
        with (MEMORIA / f"alertas-{ahora:%Y-%m}.jsonl").open("a") as f:
            for a in nuevas:
                f.write(json.dumps({"cuando": ahora.isoformat(timespec="seconds"), **a}, ensure_ascii=False) + "\n")
        estado["ultima"] = ahora.isoformat(timespec="seconds")
        _guardar("estado.json", estado)
        _guardar("paises.json", paises)
        _guardar("avisados.json", avisados)
    return {"leido": leido, "errores": errores, "alertas": len(nuevas), "avisos": len(salen), "canal": canal}


def resumen(r):
    lineas = [f"vigía: {r['alertas']} alertas, {r['avisos']} avisos" + (f" por {r['canal']}" if r["canal"] else "")]
    lineas += [f"  leído  {x}" for x in r["leido"]]
    lineas += [f"  error  {k}: {v}" for k, v in r["errores"].items()]
    return "\n".join(lineas)
