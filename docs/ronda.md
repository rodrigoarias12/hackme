# `estado/ronda.json`

What `bin/hackme ronda` leaves for the agent to judge. Field names are in Spanish, like the
code. Everything is regenerated each round; what must persist lives in
`$HACKME_PRIVADO/memoria/<modo>/`.

```jsonc
{
  "fecha": "2026-11-03T20:30",          // local time of the round
  "modo": "todo" | "nube" | "mac",
  "primera_corrida": true,              // Aguara had no previous findings: everything is baseline

  "radar": {
    "radar_actualizado": "2026-11-03T17:00:17Z",   // Radar's own updated_at
    "avisos": 35,                                   // advisories in the feed
    "candidatos": [                                 // only advisories with at least one match
      {
        "slug": "litellm-1-107-0",
        "url": "https://www.oktsec.com/radar/…",    // copy as-is when citing
        "titulo": "…",
        "prioridad": "act_now" | "this_week" | "monitor",
        "tipo": "vulnerability" | "supply_chain" | "platform_breach" | "threat_activity" | …,
        "estado": "nuevo" | "actualizado" | "visto",   // vs. memoria/<modo>/radar-visto.json
        "reportado": "2026-10-21",
        "accion": "…",                              // Radar's recommended action
        "afectado": [{ "product": "…", "range": "…", "fixed_in": ["…"] }],
        "explotacion": "exploited" | …, "parche": "available" | "partial" | …, "kev": false,
        "pasos": ["…"],                             // checklist titles
        "total_coincidencias": 8,
        "coincidencias": [                          // max 40, strongest first
          {
            "fuerza": "version-afectada" | "nombre" | "mencion",
            "tipo": "paquete npm" | "paquete pypi" | "paquete go" | "imagen docker" | "servicio"
                    | "mcp" | "app mac" | "brew" | "extensión cursor" | "runtime" | "npm global"
                    | "documentación",
            "nombre": "litellm",
            "version": ">=1.82.1" | "1.82.1" | null,   // declared spec or locked version
            "donde": "repo/pyproject.toml" | "Mac" | "repo (N archivos, p. ej. …)"
          }
        ]
      }
    ]
  },

  "aguara": {
    "nuevos": [Hallazgo],               // not present in the previous round
    "importantes": [Hallazgo],          // high/critical in the agentic surface or critical credentials
    "paquetes_comprometidos": { "repo": [ … aguara check findings … ] },
    "secretos_versionados": { "repo": [".env.development", …] },   // file names only
    "errores": { "repo": "message" },
    "mac": { "mcp_clientes": { … aguara scan --auto … }, "npm_global": { … aguara check … } },
    "por_repo": { "repo": { "riesgo": 71.9, "hallazgos": 40 } }
  },

  "aws": {
    "primera_corrida": false,
    "cuentas": [
      {
        "perfil": "default", "region": "us-east-1", "cuenta": "123456789012",
        "errores": { "credenciales" | "guardduty" | "securityhub" | "inspector": "message" },
        "hallazgos": [
          {
            "id": "…", "servicio": "GuardDuty" | "Security Hub" | "Inspector",
            "severidad": 8.0 | "HIGH" | "CRITICAL",     // GuardDuty is numeric
            "titulo": "…", "estado": "nuevo" | "actualizado" | "visto" | "línea de base",
            "actualizado": "…",
            // GuardDuty: tipo, recurso, primera, ultima, veces, ips, origen
            // Security Hub: recurso, control, arreglo (URL)
            // Inspector: recurso, cve, arreglo_disponible, paquetes ["name ver -> fixed"]
          }
        ]
      }
    ]
  }
}
```

`vercel` has the same finding shape as `aws`:

```jsonc
"vercel": {
  "primera_corrida": false,
  "dominios": ["app.example.com", …],          // custom production domains seen
  "errores": { "team:paso": "message" },
  "hallazgos": [
    {
      "id": "vercel:<team>:<project>:<check>", "servicio": "Vercel",
      "severidad": "alta" | "media" | "baja" | "info",   // info = context (confirmed members)
      "titulo": "…", "recurso": "<project or team>",
      "detalle": { … },                          // variable NAMES, counts, roles; never values
      "estado": "nuevo" | "actualizado" | "visto" | "línea de base"
    }
  ]
}
```

Checks: pending team access requests and new members, secret-looking variables with a public
prefix, `plain` secrets, production secrets also in `development`, production secrets not
`sensitive`, unprotected previews and disabled firewall on projects with a custom domain, stale
published projects, audit events (`env pull`, variables added, member changes, blocked deploys), and
Vercel's own `vercel security check` (ids `vercel:<team>:chequeo:<check>`: members without MFA, tokens
that never expire, too many owners, unprotected previews, variables exposed to the browser) with
`detalle` = `{cantidad, de, ejemplos, truncado}`; `ejemplos` are labels (user, project, variable name).

`Hallazgo` (Aguara):

```jsonc
{
  "repo": "…", "regla": "CRED_021", "nombre": "Dotenv file exposure",
  "severidad": "crítica" | "alta" | "media" | "baja" | "info",
  "categoria": "credential-leak", "archivo": "path/in/repo", "linea": 110,
  "capa": "agéntica" | "credencial" | "código",   // agéntica = .claude/, skills/, CLAUDE.md, MCP json, workflows…
  "impacto": "review" | …, "arreglo": "…", "nuevo": true
}
```

Matched text is never included: Aguara redacts credential matches and hackme drops the context.

`caminos` (built at the end of the round from all sources):

```jsonc
"caminos": {
  "primera_corrida": false,
  "abiertos": [
    {
      "id": "aws:<account>:base-desde-internet",
      "joya": "Base de datos de producción",      // what the attacker gets
      "titulo": "Desde internet, directo a la base",
      "pasos": [{ "que": "…", "evidencia": "…", "fuente": "Security Hub RDS.46" }],
      "corte": "…",                              // the fix that breaks the chain
      "severidad": "crítica" | "alta" | "media",
      "recorrido": true,                         // someone already walked it
      "estado": "nuevo" | "visto" | "línea de base"
    }
  ],
  "cerrados": [{ "id": "…", "titulo": "…", "joya": "…" }]   // open last round, gone now
}
```

A source that didn't run (expired credentials) never closes its paths.
