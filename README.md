# Keyroh

A decentralized, end-to-end encrypted password manager with P2P sync.

Vault data is replicated across devices using [iroh-docs](https://github.com/n0-computer/iroh).  
Every entry is encrypted with AES-256-GCM before it leaves the device. The master password never leaves the machine.

## Features

- **E2E encryption** — AES-256-GCM per entry, Argon2id key derivation
- **P2P sync** — devices sync directly via iroh; no central server required
- **TUI** — interactive terminal interface with live sync status
- **CLI** — scriptable interface with session token support
- **TOTP** — built-in TOTP code generation with countdown

## Building

```sh
cargo build --release
```

Binaries will be at `target/release/keyroh-cli` (CLI) and `target/release/keyroh-tui` (TUI).

## Quick start

### Initialize a new vault

```sh
keyroh-cli init
```

### Add an entry

```sh
keyroh-cli add --name GitHub --username alice --password s3cr3t --uri https://github.com
```

### List and search

```sh
keyroh-cli list
keyroh-cli search github
```

### Show an entry

```sh
keyroh-cli show <id>
```

## Session token

`unlock` decrypts the master key and prints a session token. Export it to avoid
re-entering the password on every command:

```sh
export KEYROH_SESSION=$(keyroh-cli unlock)

keyroh-cli list
keyroh-cli add ...
```

Alternatively set `KEYROH_PASSWORD` to have the CLI read the password from the
environment without a prompt.

## Multi-device sync

On the **source device** (must be unlocked):

```sh
keyroh-cli export-keys   # prints a sync ticket
```

On the **new device**:

```sh
keyroh-cli import-keys --ticket <ticket>
keyroh-cli unlock
```

The two devices will sync over iroh's P2P relay. Once the initial sync completes
both vaults are identical and stay in sync as entries are added or edited.

> **Keep the ticket secret** — it grants full write access to the vault replica.

## TUI

```sh
keyroh-tui
```

| Key | Action |
|-----|--------|
| `j` / `k` | Navigate list |
| `/` | Search |
| `a` | Add entry |
| `e` | Edit selected |
| `d` | Delete selected |
| `f` | Toggle favorite |
| `p` | Reveal / hide passwords |
| `y` | Copy password to clipboard |
| `r` | Refresh list |
| `s` | Sync status (node ID, relay, peers, ticket) |
| `q` | Quit |

## Data directory

Vault data is stored in `~/.config/keyroh` by default.

Override with the `KEYROH_DATA_DIR` environment variable or the `--dir` flag on the CLI.

## Crate layout

```
keyroh-core   — encryption, iroh integration, vault manager, event stream
keyroh-cli    — command-line interface (clap)
keyroh-tui    — terminal UI (ratatui + crossterm)
```
