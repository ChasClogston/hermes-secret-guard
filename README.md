# Secret Guard

**Safe key entry and leak prevention for Hermes Agent.**

Agents need API keys. Today the easy way to give Hermes one is to paste it into chat, where it
lands in the transcript, the session store, memory and the model provider's logs. And once a key
is on the machine, one `printenv` from the agent, or one read of a `.env` file, puts it back in
front of a model.

Secret Guard closes both ends.

- **Keys come in through a hidden dialog, never through chat.** Ask Hermes to add a key; it opens
  a native macOS dialog, the value goes straight into your keychain, and Hermes sees only a name,
  a fingerprint and a length. The `secret_request` tool has no value parameter, so there is
  nothing for the model to fill in.
- **Keys can't come back out.** Tool calls that would read a secret file, run a secrets helper or
  ask the keychain to print a value are blocked before they run. Every registered value is scrubbed
  from anything the model sees, including output from commands no filename rule could predict.
- **A key pasted into chat anyway never reaches a model.** The turn is stopped, the message is
  stored as a placeholder, and you're told to rotate the key.

## What it looks like

```
you:     add my Groq key
hermes:  [a "Secret Guard" dialog opens on your Mac; you paste the key and click Save]
         GROQ_API_KEY is stored in the keychain (fingerprint 3f9a…, 56 chars).

you:     run perl -ne 'print' notes.txt
hermes:  service key: [secret:GROQ_API_KEY redacted]

you:     show me what's in ~/.hermes/.env
hermes:  Secret Guard blocked that: it reads a secret-shaped file (.env).
```

Measured against a real agent in a test profile, with a prefix-less canary key that Hermes's
built-in regexes don't recognise:

| Attempt | Without Secret Guard | With Secret Guard |
|---|---|---|
| `perl` prints a file holding the key | key in the reply and in 2 stored rows | `[secret:… redacted]`, 0 stored rows |
| `cat` a `.env` file | runs | blocked before it runs |
| `security find-generic-password -w` | runs | blocked |
| key pasted into chat | sent to the model | turn stopped, nothing stored |

## Install

```
hermes plugins install ChasClogston/hermes-secret-guard
hermes plugins enable secret-guard --no-allow-tool-override
hermes tools enable secret_guard          # if your profile restricts toolsets
```

Plugins are per profile; install in each profile that should be guarded.

## Commands

| Command | Does |
|---|---|
| `hermes secret add ENV_VAR [--scope all\|default-only]` | Dialog entry. Prints name, fingerprint, length. |
| `hermes secret list` | Names, scopes, fingerprints. Never values. |
| `hermes secret verify ENV_VAR` | Recomputes the fingerprint from the keychain. |
| `hermes secret remove ENV_VAR --yes` | Deletes the keychain item and registry entry. |
| `hermes secret wire PROFILE\|all` | Points a profile's `secrets.command` at the generated helper. |
| `hermes secret import SCRIPT` | Registers keys named in an existing `emit "service" "ENV"` keychain helper. Reads names only; never runs it. |
| `hermes secret doctor` | Read-only health check. Exit 1 on problems. |

## How keys reach your profiles

Secret Guard generates one helper, `<hermes root>/secret_guard/emit-secrets.sh`, and wires each
profile's `secrets.command` to it. The script holds service and variable names only; values are
read from the keychain at startup.

Each secret has a scope:

- `all`: every profile gets it.
- `default-only`: only the root profile. Telegram, Discord and Slack bot tokens are forced to
  this scope. If a second profile resolves the same bot credential, the multiplex gateway refuses
  to multiplex and silently falls back to standalone. `doctor` catches a profile wired to the
  wrong scope (for example one cloned from the root) and `wire` repairs it.

## The three layers

1. **Path gate** (`pre_tool_call`, fails closed). Blocks a reader (`cat`, `grep`, `python -c`,
   `perl`, `cp`, …) pointed at a secret-shaped file (`*.env`, `*token*`, `*secret*`,
   `*credential*`, `*.pem`, `id_rsa`, `auth.json`, Hermes `config.yaml`), `read_file` on the same,
   running any secrets helper, `security find-*-password -w/-g`, `security dump-keychain`, a bare
   `env`/`printenv`, and `openclaw mcp show` (prints stored headers unmasked).
2. **Value redaction.** Every registered value is pushed into Hermes's own model-egress scrub, the
   same exact-value registry Hermes uses for browser-vault passwords. That registry applies even
   when `security.redact_secrets` is off. Backup `transform_*` hooks scrub tool results, terminal
   output and replies too; if a backup hook itself fails, it withholds the output instead of
   passing it through.
3. **Inbound block** (`pre_llm_call`). An exact registered value, or a string shaped like a known
   key (`sk-`, `ghp_`, `xoxb-`, `AKIA`, `AIza`, Telegram bot tokens, …), stops the turn before any
   inference.

## Disclosures

What Secret Guard does on your machine, so you can decide before installing:

- **No network calls.** Nothing leaves the machine. No telemetry.
- **Shell commands.** `/usr/bin/security` (create, update and read keychain items this plugin
  manages) and `/usr/bin/osascript` (the hidden-input dialog). Both run only from
  `hermes secret` commands you type or from the `secret_request` tool when you ask Hermes to add
  a key.
- **Stored credentials.** Keys you enter are stored in your login keychain as generic passwords
  named `hermes-<env-var>`. The plugin's own registry
  (`<hermes home>/secret_guard/registry.json`, mode 600) holds names, scopes and SHA-256
  fingerprints, never values.
- **Reads outside its own data.** Inside the agent, values come only through Hermes's
  `get_secret()`, i.e. what Hermes already resolved for the active profile; the agent process
  never reads the keychain. The `hermes secret` CLI reads the keychain items this plugin created,
  to confirm a write and for `verify` / `doctor` / `import` (fingerprints only). `import` reads the
  service and variable names in a helper script you point it at; it never runs the script.
- **Writes outside its own data.** `hermes secret wire` edits a profile's `config.yaml` to set
  `secrets.command`, after saving a timestamped backup next to it. The generated helper lives at
  `<hermes root>/secret_guard/emit-secrets.sh` and is run by Hermes at startup.
- **Blocking.** The `pre_tool_call` hook refuses some terminal and file-tool calls (see *The three
  layers*). It fails closed: if the check errors, the tool call is refused.
- **Unattended runs.** The dialog gives up after 5 minutes and the tool returns a plain error, so
  cron and gateway runs never hang on it.
- **No background processes.**

## Honest limits

Secret Guard reduces exposure. It is not a sandbox and it does not certify anything.

- **What it can't see:** logging done by MCP servers or child processes outside Hermes; a value
  split across two outputs or partly echoed; images and screenshots; backups taken before a value
  was scrubbed.
- **The path gate matches patterns.** It will block some harmless files (`tokens.txt`) and can be
  routed around by a determined agent. Value redaction is the layer that doesn't depend on guessing.
- **A key pasted into a messaging app has already left your machine.** Secret Guard keeps it from
  the model and the session store; rotate it anyway.
- **The dialog appears on the Mac Hermes runs on,** not on your phone, and can't show while the
  Mac is locked or asleep. From Telegram, Hermes tells you this before it asks.
- **macOS only** in this version (Keychain + `osascript`). Values with whitespace, quotes or
  backslashes, or longer than about 3,900 characters, are refused; `security -i` can't carry them.
- Value redaction uses `agent.redact.register_vault_redaction_value`, a module function rather
  than a documented plugin API (`hermes plugins validate` warns on it). If an update removes it,
  the plugin's own `transform_*` hooks still scrub tool results, terminal output and replies, and
  `doctor` reports the change.

## Tests

```
cd <plugin folder>
PYTHONPATH=~/.hermes/hermes-agent ~/.hermes/hermes-agent/venv/bin/python tests/test_guard.py
```

Self-contained: a throwaway `HERMES_HOME`, a throwaway keychain and a random canary, removed at
the end. Every rule has a block case and an allow case.

## Origin

Built for the Hermes Agent Plugin Hackathon (November 2026) from a working setup on two production
Macs: a hidden-dialog keychain intake tool, keychain-backed `secrets.command` helpers, and a shell
guard written after real key exposures. Secret Guard moves those into Hermes, where the hook system
closes gaps a shell guard can't reach.

## License

MIT. See [LICENSE](LICENSE).
