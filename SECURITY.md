# Security

hackme is a security agent, so reports about hackme itself matter twice.

## Reporting a vulnerability

Please report it privately: open the **Security** tab of this repository and choose
**Report a vulnerability**. Don't open a public issue for it.

Include what you found, how to reproduce it and what an attacker gains. You'll get an answer
within a week.

## What counts

- A way to make hackme write, change or block something. It is built to only read
  ([AGENTS.md](AGENTS.md) has the rules).
- A way to make it print or send a secret value: an `.env` file, a variable's value, a token.
- Content in a scanned repo, advisory or log that makes the agent follow instructions
  (prompt injection that gets past the rules and the skill).
- A detection that can be silenced or flooded from the outside.

## What doesn't

- Detections marked as not built yet in [docs/detecciones.md](docs/detecciones.md).
- Default thresholds being public. They are a starting point: set your own in your private
  `vigia.json` (see [docs/vigia.md](docs/vigia.md)).
- Aguara flagging this repo for reading its own config files (`~/.config/hackme/*.env`) and for
  mentioning `.env` in the docs. That is how it gets its Telegram and app tokens; they never
  live in a repo.
