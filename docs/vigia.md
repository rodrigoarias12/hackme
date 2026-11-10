# Vigía

The 15-minute watch. The daily round sees **state** (what you run, what is misconfigured); the
vigía sees **what is happening**: someone sweeping your routes, trying logins, using the AWS root
account, turning logs off. It is deterministic (no AI): it reads, counts, compares with thresholds
and alerts on Telegram. Every detection is a row in [detecciones.md](detecciones.md) with the
source it comes from.

```
bin/hackme vigia               one pass: read, detect, alert
bin/hackme vigia --sin-avisar  print what it would alert; saves nothing
```

It alerts once per key per day, with a cap of 25 a day, so a script can't flood the chat. It never
blocks anything.

## What it reads

| Source | Detections | How |
|---|---|---|
| Your app's request log (rejected requests, firewall actions) | A8 route sweep, A9 scanner fingerprint, A11 firewall surge | SQL you write, read-only |
| Your app's login events | A1 failures on one account, A2 spraying from one IP, A3 distributed wave, A4 login after failures, A5 denied logins, A6 new country | SQL you write, read-only |
| Last row of the request log | C13 the log went silent | SQL you write, read-only |
| Your app's accounts (once a day) | E1 dormant accounts, accounts that log in and do nothing | SQL you write, read-only |
| AWS CloudTrail (write events, last 30 min) | B7 root use, B8 console login without MFA or failing, B9 denied calls, B10 new IAM user or key, C1–C9 the CIS monitoring list | `aws cloudtrail lookup-events` |
| AWS GuardDuty (updated in the last 30 min) | Severity 7+, and the types that matter at any severity (root, stolen credentials, logs off, exfiltration, Tor and malicious IPs) | `aws guardduty` |

If a source can't be read for 45 minutes in a row, the vigía says so once.

## Your apps: `vigia.json`

Each app's schema is private, so this repo doesn't know it. You write the queries in
`$HACKME_PRIVADO/vigia.json` (or the path in `HACKME_VIGIA`). Every query is optional;
`{desde}` is replaced with the start of the window. Column names are what the vigía expects.

```json
{
  "apps": [
    {
      "nombre": "shop",
      "conexion": "VIGIA_PG_SHOP",
      "dominios_propios": ["example.com"],
      "accesos": "SELECT created_at AS cuando, ip, method AS metodo, path AS ruta, status AS estado, user_agent, waf_action AS waf_accion FROM request_log WHERE created_at > {desde}",
      "ultimo": "SELECT max(created_at) AS ultimo FROM request_log",
      "silencio_min": 360,
      "logins": "SELECT created_at AS cuando, email AS cuenta, ip, CASE WHEN ok THEN 'ok' WHEN denied THEN 'denegado' ELSE 'fallo' END AS resultado, country AS pais FROM login_events WHERE created_at > {desde}",
      "cuentas": "SELECT email AS cuenta, role AS rol, created_at AS creada, last_login_at AS ultimo_login, last_action_at AS ultima_accion FROM users WHERE role <> 'none'",
      "umbrales": { "rutas_por_ip": 30 }
    }
  ],
  "ips_conocidas": { "203.0.113.7": "Ana (home)" }
}
```

- `conexion` is the **name** of a variable holding the Postgres URL. The URL itself goes in the
  environment or in `~/.config/hackme/vigia.env` (`VIGIA_PG_SHOP=postgresql://…`), never in a
  repo. It is passed to `psql` through `PG*` variables, so it doesn't show up in `ps`.
- `dominios_propios`: a denied login from your own domain usually means someone who left.
- `ultima_accion` is optional. Without it, "logs in and does nothing" can't be computed.
- `umbrales` overrides the defaults in `hackme/vigia.py` (`UMBRALES`).
- `ips_conocidas` names IPs in the alerts ("from 203.0.113.7 (Ana (home))"). It never silences an
  alert: root used from a partner's home is still root.

Every query runs inside `BEGIN TRANSACTION READ ONLY` with a 20 s timeout. Use a read-only user
anyway (below): defense in depth.

## Apps that expose their own events

Some apps don't have a database you can query, or keep their logs where hackme can't read them.
They can expose their access events over HTTP instead, and the vigía reads them every pass:

```json
{
  "apps": [
    {
      "nombre": "my-app",
      "eventos_url": "https://api.example.com/api/seguridad/eventos",
      "token": "VIGIA_TOKEN_MY_APP",
      "cuentas_vigiladas": ["you@example.com"]
    }
  ]
}
```

The contract the app implements (Núcleo does):

- `GET <eventos_url>?desde=<ISO 8601>` with `Authorization: Bearer <token>`. The token is its own,
  read-only, and lives in `~/.config/hackme/vigia.env`. Without it configured, the endpoint should
  not exist (404).
- Response: `{"eventos": [{"cuando": "…", "tipo": "pedido-link" | "canje" | "invitacion",
  "resultado": "…", "ip": "…", "email_hash": "…"}]}`, oldest first.
- `email_hash` is `sha256(lowercase email)`, first 16 hex characters. Emails are never sent in
  clear: the vigía hashes `cuentas_vigiladas` the same way to recognize yours.
- `canje:ok` and `invitacion:ok` are successful logins; `pedido-link:enviado` is a login link sent;
  `limite-ip` means the app's own rate limit stopped that IP; anything else is a failed attempt.

What it adds: **A5** someone asked for a login link for one of your accounts, **A6** someone logged
in with it, from an IP that isn't in `ips_conocidas`, and **A2** an IP hit the app's own rate limit
(someone is trying emails on the login). The usual A1–A4 run on the same rows. The vigía keeps a
cursor per app, so each pass reads only what's new.

## Read-only users

Give the vigía the least it needs. If its credentials leak, the attacker can read what you detect,
but can't change anything or read your data.

### Postgres

```sql
-- As an admin, once. Generate the password with: openssl rand -base64 32
CREATE ROLE hackme_lector LOGIN PASSWORD '<generated>' CONNECTION LIMIT 2;
ALTER ROLE hackme_lector SET default_transaction_read_only = on;
ALTER ROLE hackme_lector SET statement_timeout = '20s';
GRANT CONNECT ON DATABASE <db> TO hackme_lector;
GRANT USAGE ON SCHEMA public TO hackme_lector;
-- Only the tables your queries read; for users, only the columns (no tokens, no secrets).
GRANT SELECT ON request_log, login_events TO hackme_lector;
GRANT SELECT (email, role, created_at, last_login_at) ON users TO hackme_lector;
```

### AWS

An IAM user (or role) with only this policy. It reads findings and the management event history;
it can't read S3 objects, databases or secrets, and can't change anything.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "HackmeReadOnly",
      "Effect": "Allow",
      "Action": [
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        "securityhub:GetFindings",
        "inspector2:ListFindings",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

Put its access key in a profile of its own (`aws configure --profile hackme`) and point
hackme at it: `HACKME_VIGIA_AWS=hackme:us-east-1` (and `HACKME_AWS` for the daily
round). Rotate the key every 90 days (CIS AWS 1.13). Don't reuse an admin profile: the vigía runs
unattended every 15 minutes.

## Run it every 15 minutes (macOS)

`~/Library/LaunchAgents/com.hackme.vigia.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.hackme.vigia</string>
  <key>ProgramArguments</key>
  <array><string>/path/to/hackme/bin/hackme</string><string>vigia</string></array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    <key>HACKME_VIGIA_AWS</key><string>hackme:us-east-1</string>
  </dict>
  <key>StartInterval</key><integer>900</integer>
  <key>StandardOutPath</key><string>/tmp/hackme-vigia.log</string>
  <key>StandardErrorPath</key><string>/tmp/hackme-vigia.log</string>
</dict>
</plist>
```

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.hackme.vigia.plist
launchctl bootout gui/$(id -u)/com.hackme.vigia     # to stop it
```

It only runs while the Mac is on. To watch with the laptop closed, run the same command on a
schedule somewhere that is always on (a small server, or a scheduled CI job in the private repo
with the read-only credentials as secrets).

## Memory

`$HACKME_PRIVADO/memoria/vigia/`: `avisados.json` (keys alerted in the last two days),
`estado.json` (one week of counts for the baselines, failure streaks), `paises.json` (countries
seen per account, for A6) and `alertas-YYYY-MM.jsonl` (every alert, for the daily report and the
program metrics).
