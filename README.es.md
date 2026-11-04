# Centinela

[English](README.md)

Un agente de seguridad que corre todos los días sobre **todo lo que corrés**: tus repos, tu Mac y
tu cuenta de AWS. Cruza los avisos de [Oktsec Radar](https://www.oktsec.com/radar) con tu
inventario real, le pasa [Aguara](https://github.com/garagon/aguara) a cada repo, lee lo que
encontraron GuardDuty, Security Hub e Inspector, y te avisa solo lo nuevo que te toca. No bloquea
ni arregla nada: mira, compara y avisa.

## Usarlo con tu agente

```bash
git clone https://github.com/rodrigoarias12/centinela
cd centinela
bin/centinela doctor        # te dice qué falta
bin/centinela init          # crea el repo privado de informes (git local)
npx skills add rodrigoarias12/centinela   # el skill, para Claude Code, Codex, Cursor, Gemini CLI…
```

Después pedile a tu agente *"corré la ronda de Centinela"*. Los agentes que trabajen en este repo
leen primero [AGENTS.md](AGENTS.md): reglas, configuración y la forma de la salida
([docs/ronda.md](docs/ronda.md)).

Para que sea diaria, programá el mismo pedido:
- **Tarea local de Claude Code** (`CENTINELA_MODO=mac`): ve tu Mac, las carpetas sin remoto y los
  perfiles locales de AWS.
- **Rutina en la nube de Claude** (`CENTINELA_MODO=nube`): ve tus repos de GitHub y corre con la
  compu apagada. Se prepara sola con `bin/preparar-nube`.

## Requisitos

- Python 3.11+ (solo biblioteca estándar), git, rsync.
- [Aguara](https://github.com/garagon/aguara) v0.28+: `go install github.com/garagon/aguara/cmd/aguara@latest`.
- Opcional: AWS CLI con un perfil de solo lectura.
- Opcional: un bot de Telegram (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` en
  `~/.config/centinela/telegram.env` o en el ambiente).

## Reglas de base

- Solo observa. Nunca modifica nada fuera de sus dos repos.
- Los informes y la memoria viven en un **repo privado aparte**. Este repo es solo código.
- Los archivos de secretos nunca se copian ni se abren; si alguno está versionado, se avisa por
  nombre.
- Radar es una selección editorial y Aguara un escáner de patrones: que no aparezca algo no prueba
  que estés a salvo.

## Créditos

Construido sobre el open source de [Oktsec](https://www.oktsec.com), de Gus Aragón:
[Radar](https://www.oktsec.com/radar) y [Aguara](https://github.com/garagon/aguara). Apache 2.0.
