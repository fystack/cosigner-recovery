package main

import (
	"encoding/json"
	"fmt"
	"os"

	"recovery/internal/recovery"
)

func runFromShares(entries []entry, opts options) {
	if len(entries) < 2 {
		fmt.Fprintln(os.Stderr, "error: need at least 2 shares")
		usage()
		os.Exit(2)
	}
	keys, err := recoverKeys(entries)
	if err != nil {
		fatal(err)
	}
	switch {
	case opts.hdBundle != "":
		runHD(keys, entries, opts)
	case opts.asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(keys)
	default:
		printKeys(keys)
	}
}

func recoverKeys(entries []entry) ([]*recovery.CombinedKey, error) {
	session := recovery.NewSession()
	for _, e := range entries {
		if err := addAndUnlock(session, e); err != nil {
			return nil, err
		}
	}
	return session.Recover()
}

func addAndUnlock(session *recovery.Session, e entry) error {
	raw, err := os.ReadFile(e.share)
	if err != nil {
		return err
	}
	info, err := session.AddShare(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", e.share, err)
	}
	secret, err := shareSecret(e, info)
	if err != nil {
		return err
	}
	if _, err := session.UnlockShare(info.ID, secret); err != nil {
		return fmt.Errorf("%s: %w", e.share, err)
	}
	fmt.Fprintf(os.Stderr, "unlocked %s (%s, participant %s)\n", e.share, info.Format, info.ParticipantID)
	return nil
}

func shareSecret(e entry, info recovery.ShareInfo) (string, error) {
	switch {
	case info.NeedsRSAKey:
		if e.rsaKeyPath == "" {
			return "", fmt.Errorf("%s is an RSA bundle; provide --rsa-key", e.share)
		}
		pem, err := os.ReadFile(e.rsaKeyPath)
		return string(pem), err
	case info.NeedsPass && e.passphrase == "":
		return "", fmt.Errorf("%s is passphrase-protected; provide --passphrase", e.share)
	default:
		return e.passphrase, nil
	}
}

func printKeys(keys []*recovery.CombinedKey) {
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
