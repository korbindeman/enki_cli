# Enki CLI

Link your machine to [Enki](https://enki.works) over a persistent WebSocket connection. Enki gets access to your filesystem, shell, installed toolchains, and Claude Code — scoped to what you allow.

## Install

```sh
curl -fsSL https://enki.works/install.sh | bash
```

## Usage

```sh
# Authenticate (opens browser for passkey login)
enki login

# Check login status and detected capabilities
enki status

# Start the link
enki link

# Limit which capabilities are advertised
enki link --capabilities fs,shell

# Keep the link alive by preventing system sleep
enki link --persistent
```

## Capabilities

The CLI auto-detects what it can offer:

| Capability | Filter key | What it provides |
|---|---|---|
| Filesystem | `fs` | Read, write, edit, search, copy, move, trash files |
| Shell | `shell` | Run shell commands |
| Toolchain | `toolchain` | Detected dev tools (rustc, node, python, go, etc.) |
| PDF | `pdf` | Markdown-to-PDF conversion |
| Claude Code | `claude_code` | Claude Code sessions via ACP (requires `claude` on PATH) |

Combine filter keys with `--capabilities` to limit what's exposed:

```sh
enki link --capabilities fs,shell,toolchain
```

## Configuration

Credentials are stored in `~/.enki/credentials.json` (owner-only permissions).

| Variable | Default | Purpose |
|---|---|---|
| `ENKI_SERVER_URL` | `https://enki.works` | Server endpoint |
| `ENKI_WEB_URL` | `https://enki.works` | Web app (for auth) |
| `ENKI_INSTALL_DIR` | `~/.local/bin` | Install location |
