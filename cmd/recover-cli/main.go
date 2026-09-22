// Command recover-cli reconstructs a wallet's ECDSA/EdDSA private keys from
// threshold share files, using the same engine as the desktop app.
//
// WARNING: this materializes the raw private key and defeats the threshold
// security of the wallet. Run only offline, on an air-gapped machine.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"recovery/internal/recovery"
)

type entry struct {
	share      string
	rsaKeyPath string
	passphrase string
}

func main() {
	entries, asJSON, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		usage()
		os.Exit(2)
	}
	if len(entries) < 2 {
		fmt.Fprintln(os.Stderr, "error: need at least 2 shares")
		usage()
		os.Exit(2)
	}

	session := recovery.NewSession()
	for _, e := range entries {
		raw, rerr := os.ReadFile(e.share)
		if rerr != nil {
			fatal(rerr)
		}
		info, aerr := session.AddShare(raw)
		if aerr != nil {
			fatal(fmt.Errorf("%s: %w", e.share, aerr))
		}
		secret := e.passphrase
		if info.NeedsRSAKey {
			if e.rsaKeyPath == "" {
				fatal(fmt.Errorf("%s is an RSA bundle; provide --rsa-key", e.share))
			}
			pem, perr := os.ReadFile(e.rsaKeyPath)
			if perr != nil {
				fatal(perr)
			}
			secret = string(pem)
		} else if info.NeedsPass && e.passphrase == "" {
			fatal(fmt.Errorf("%s is passphrase-protected; provide --passphrase", e.share))
		}
		if _, uerr := session.UnlockShare(info.ID, secret); uerr != nil {
			fatal(fmt.Errorf("%s: %w", e.share, uerr))
		}
		fmt.Fprintf(os.Stderr, "unlocked %s (%s, participant %s)\n", e.share, info.Format, info.ParticipantID)
	}

	keys, err := session.Recover()
	if err != nil {
		fatal(err)
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(keys)
		return
	}
	for _, k := range keys {
		fmt.Printf("\n[%s]\n", k.Protocol)
		fmt.Printf("  private_key_hex: %s\n", k.PrivateKeyHex)
		if k.Address != "" {
			fmt.Printf("  %s: %s\n", k.AddressLabel, k.Address)
		}
		fmt.Printf("  public_key: %s\n", k.PublicKeyHex)
		fmt.Printf("  verified: %v · test_signed: %v\n", k.Verified, k.TestSigned)
		if k.Note != "" {
			fmt.Printf("  note: %s\n", k.Note)
		}
	}
}

func parseArgs(args []string) ([]entry, bool, error) {
	var entries []entry
	var asJSON bool
	cur := -1
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "--share":
			i++
			if i >= len(args) {
				return nil, false, fmt.Errorf("--share needs a value")
			}
			entries = append(entries, entry{share: args[i]})
			cur = len(entries) - 1
		case "--rsa-key":
			i++
			if cur < 0 || i >= len(args) {
				return nil, false, fmt.Errorf("--rsa-key must follow a --share")
			}
			entries[cur].rsaKeyPath = args[i]
		case "--passphrase":
			i++
			if cur < 0 || i >= len(args) {
				return nil, false, fmt.Errorf("--passphrase must follow a --share")
			}
			entries[cur].passphrase = args[i]
		case "-h", "--help":
			usage()
			os.Exit(0)
		default:
			return nil, false, fmt.Errorf("unknown argument: %s", args[i])
		}
	}
	return entries, asJSON, nil
}

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
`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
