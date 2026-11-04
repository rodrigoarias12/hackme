# Centinela

[Español](README.es.md)

A security agent that runs every day over **everything you run**: your repos, your Mac and your
AWS account. It cross-matches [Oktsec Radar](https://www.oktsec.com/radar) advisories against your
real inventory, scans every repo with [Aguara](https://github.com/garagon/aguara), reads what AWS
GuardDuty, Security Hub and Inspector found, and tells you only what is new and affects you.
It blocks nothing and fixes nothing: it looks, compares and reports.

```
bin/centinela ronda
  ├─ inventario   every folder in ~/Documents/GitHub + the Mac
  │               (npm/PyPI/Go packages, Docker images, Actions, MCP configs, services,
  │                apps, brew, Cursor/VS Code extensions, runtimes)
  ├─ aguara       secret-free mirror → scan with --monitor
  │               + compromised-package check on the real repo
  │               + secret files committed to git (names only)
  ├─ radar        Radar's items.json × inventory → candidates with a match strength
  │               (version-afectada / nombre / mencion)
  └─ aws          GuardDuty, Security Hub and Inspector findings (read only)
        ↓
  estado/ronda.json  (docs/ronda.md)
        ↓
  the agent (skills/centinela/SKILL.md) judges each candidate against the affected range,
  writes the report in a private repo and notifies you on Telegram if something is new
```

## Use it with your agent

Centinela is a CLI plus a skill. Any coding agent can drive it.

```bash
git clone https://github.com/rodrigoarias12/centinela
cd centinela
bin/centinela doctor        # tells you what's missing
bin/centinela init          # creates the private repo for reports (local git)
```

Then give your agent the skill:

```bash
npx skills add rodrigoarias12/centinela   # Claude Code, Codex, Cursor, Gemini CLI, …
```

and ask it to *"run the Centinela round"*. Agents working on this repo should read
[AGENTS.md](AGENTS.md) first: hard rules, configuration and the output contract.

To make it daily, schedule the same prompt: a Claude Code scheduled task on your machine
(`CENTINELA_MODO=mac`) and/or a Claude cloud routine over your GitHub repos (`CENTINELA_MODO=nube`;
the session prepares itself with `bin/preparar-nube`).

| | Cloud routine | Local task |
|---|---|---|
| Repos | the ones on GitHub | folders without a remote |
| Mac (apps, brew, runtimes, MCP) | — | yes |
| AWS | if the environment has read-only credentials | local profiles |
| Runs with your laptop off | yes | no |

## Requirements

- Python 3.11+ (stdlib only), git, rsync.
- [Aguara](https://github.com/garagon/aguara) v0.28+: `go install github.com/garagon/aguara/cmd/aguara@latest`.
- Optional: AWS CLI with a read-only profile (GuardDuty, Security Hub, Inspector).
- Optional: a Telegram bot (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` in
  `~/.config/centinela/telegram.env` or the environment).

## Ground rules

- Observe only. Nothing outside Centinela's own two repos is modified, ever.
- Reports and memory live in a **separate private repo**. This repo is only code.
- Secret files are never copied or opened; committed ones are reported by name.
- Radar is an editorial selection and Aguara a pattern scanner: not showing up doesn't prove
  you're safe.

## Credits

Built on [Oktsec](https://www.oktsec.com)'s open source work by Gus Aragón:
[Radar](https://www.oktsec.com/radar) and [Aguara](https://github.com/garagon/aguara).
Apache 2.0.
