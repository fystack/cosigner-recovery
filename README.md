# Fystack Recovery

Offline desktop app to reconstruct an MPC wallet's private keys from threshold shares.
Built with [Wails](https://wails.io) (Go backend + React/TS frontend).

> ⚠️ Reconstructing a key materializes the full private key and defeats the wallet's
> threshold security. Run only offline, on an air-gapped machine, for recovery or migration.

## Supported share formats

| Format | Extension | Unlock with | Source |
|---|---|---|---|
| RSA export bundle | `.enc` | RSA private key (PEM) | `mpcium-sdk` export-share |
| Passphrase share | `.mshare` | 6-word passphrase | `cosigner-mobile` recovery export |

Both decrypt to tss-lib share data, then Lagrange interpolation reconstructs the
ECDSA and EdDSA keys, each verified against the wallet's public key.

## Flow

1. **Add & unlock shares** — add each participant's file, unlock with its RSA key or passphrase. Needs ≥2 shares per protocol.
2. **Recover** — confirm, then combine the shares.
3. **Result** — reveal / copy (clipboard auto-clears) / export the ECDSA + EdDSA keys.

## CLI

The same recovery engine (`internal/recovery`) is also exposed as a headless CLI,
so GUI and CLI never diverge.

```bash
go build -o build/bin/recover-cli ./cmd/recover-cli

recover-cli [--json] \
  --share wallet.enc    --rsa-key recipient_priv.pem \
  --share cos11.mshare  --passphrase "six-word-phrase"
```

Each `--share` is followed by its secret: `--rsa-key` for `.enc` bundles,
`--passphrase` for `.mshare` files. Prints ECDSA/EdDSA private keys, derived
addresses, and verification status. Needs at least 2 shares per protocol.

## Develop

```bash
wails dev      # hot-reload dev
wails build    # produce build/bin/recovery.app
go test ./internal/recovery/   # backend recovery tests
```

## Build & distribute

Recovery users usually don't have a Go/Node toolchain, so ship a prebuilt binary.

**macOS** (build on macOS + Xcode):
```bash
wails build -platform darwin/universal   # Intel + Apple Silicon .app
```
Unsigned `.app` triggers Gatekeeper. Either sign + notarize with an Apple
Developer ID, or tell users to right-click → Open once.

**Windows**:
```bash
wails build -platform windows/amd64 -nsis   # .exe installer
```
Sign with a code-signing cert to avoid SmartScreen. macOS/Linux can
cross-compile the Windows build; a macOS `.app` must be built on macOS.

**Air-gapped handoff** (this is a key-recovery tool):
- Build on a clean machine, then publish a checksum with the binary:
  ```bash
  shasum -a 256 build/bin/recovery.app/Contents/MacOS/recovery
  ```
- Have users verify the checksum and disconnect from the network before opening.

Requires Go, Node, and the [Wails CLI](https://wails.io/docs/gettingstarted/installation).
`mpcium-sdk` is a normal module dependency; `tss-lib` and `agl/ed25519` use
`replace` in `go.mod` to point at the Fystack forks.
