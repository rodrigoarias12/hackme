# Centinela

Un agente de seguridad que todos los días cruza [Oktsec Radar](https://www.oktsec.com/radar)
(avisos de seguridad curados por [Oktsec](https://www.oktsec.com)) con **todo** lo que corrés:
tus repos, tu Mac y tu cuenta de AWS. Le pasa [Aguara](https://github.com/garagon/aguara) a
cada repo y te avisa por Telegram solo lo que te toca. No bloquea nada.

```
bin/centinela ronda
  ├─ inventario   cada carpeta de ~/Documents/GitHub + la Mac
  │               (paquetes npm/PyPI/Go, imágenes Docker, actions, MCP, servicios,
  │                apps, brew, extensiones de Cursor/VS Code, runtimes)
  ├─ aguara       espejo liviano (sin secretos, deps ni builds) → scan con --monitor
  │               + check de paquetes comprometidos sobre el repo real
  │               + aviso de archivos de secretos versionados en git (solo nombres)
  ├─ radar        items.json de Radar × inventario → candidatos con fuerza
  │               (version-afectada / nombre / mencion)
  └─ aws          lo que encontraron GuardDuty, Security Hub e Inspector (solo lectura)
        ↓
  estado/ronda.json
        ↓
  el agente (tarea/SKILL.md): juzga cada candidato contra el rango afectado, escribe el
  informe en el repo privado y avisa por Telegram si hay algo nuevo
```

## Dónde corre

| | Nube de Claude (rutina diaria) | Mac (tarea local) |
|---|---|---|
| Repos | los que están en GitHub | las carpetas sin remoto |
| Mac (apps, brew, Node, MCP) | — | sí |
| AWS | si el ambiente tiene credenciales de solo lectura | perfiles locales |
| Corre con la Mac apagada | sí | no |

La nube prepara la sesión con `bin/preparar-nube`: baja Aguara del release oficial y
verifica el checksum.

## Configurar

- **Repo privado** para informes y memoria: `CENTINELA_PRIVADO` (por defecto
  `~/Documents/GitHub/centinela-privado`). Nunca hagas público ese repo.
- **Telegram:** creá un bot con @BotFather y poné `TELEGRAM_BOT_TOKEN` y `TELEGRAM_CHAT_ID`
  en `~/.config/centinela/telegram.env` (local) y en las variables del ambiente de la nube.
- **AWS:** `CENTINELA_AWS="perfil:region,…"` (por defecto `default:us-east-1`). En la nube,
  usá un usuario IAM de solo lectura (GuardDuty, Security Hub, Inspector).
- **Aguara** v0.28+ (`go install github.com/garagon/aguara/cmd/aguara@latest`).

Reglas para agentes: [CLAUDE.md](CLAUDE.md).
