package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprint(os.Stderr, `
recover-cli — reconstruct wallet keys from threshold shares (offline only)

Usage:
  recover-cli [--json] \
    --share <file.enc>    --rsa-key <priv.pem> \
    --share <file.mshare> --passphrase "six-word-phrase" \
    [--share ... ]

Each --share is followed by its secret: --rsa-key for .enc bundles,
--passphrase for .mshare files. Needs at least 2 shares per protocol.

HD-MPC wallets (child wallets derived from the master):
  --hd-bundle <hd-paths.enc>   derivation-path bundle exported with the master share
  --hd-rsa-key <priv.pem>      RSA key for the bundle (default: first --rsa-key)
  --children-out <file>        write all child keys (.csv for batch import, else JSON)
  --sign-eddsa <batch.json>    sign messages with EdDSA child keys; batch is a JSON array
                               of {"wallet_id"|"address": "...", "message_hex": "..."}
  --sign-out <file>            write signatures (default: stdout)
  --keystore-dir <dir>         write ECDSA keys as MetaMask-compatible keystore (v3) files
  --keystore-password-file <f> file whose first line is the keystore password
  --children-in <file>         skip recovery: sign with a child-keys JSON exported from the
                               Recovery app (no shares needed), together with --sign-eddsa
`)
}
