package main

import (
	"fmt"
	"os"
	"strings"

	"recovery/internal/recovery"
)

func runHD(keys []*recovery.CombinedKey, entries []entry, opts options) {
	bundle, err := openHDBundle(entries, opts)
	if err != nil {
		fatal(err)
	}
	children, err := recovery.DeriveChildren(bundle, keys)
	if err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "derived %d child keys for %d protocol(s)\n", len(children), len(keys))

	if opts.childrenOut != "" {
		if err := recovery.WriteChildKeys(opts.childrenOut, children); err != nil {
			fatal(err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", opts.childrenOut)
	}
	runChildOutputs(opts, children)
}

func openHDBundle(entries []entry, opts options) (*recovery.HDBundle, error) {
	rsaPath := opts.hdRSAKey
	if rsaPath == "" {
		for _, e := range entries {
			if e.rsaKeyPath != "" {
				rsaPath = e.rsaKeyPath
				break
			}
		}
	}
	if rsaPath == "" {
		return nil, fmt.Errorf("--hd-bundle needs --hd-rsa-key (or an --rsa-key on a share)")
	}
	raw, err := os.ReadFile(opts.hdBundle)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(rsaPath)
	if err != nil {
		return nil, err
	}
	return recovery.OpenHDBundle(raw, pem)
}

func runChildOutputs(opts options, children []recovery.ChildKey) {
	if opts.keystoreDir != "" {
		if err := writeKeystores(opts, children); err != nil {
			fatal(err)
		}
	}
	if opts.signBatch != "" {
		if err := signBatch(opts, children); err != nil {
			fatal(err)
		}
	}
}

func writeKeystores(opts options, children []recovery.ChildKey) error {
	if opts.keystorePw == "" {
		return fmt.Errorf("--keystore-dir needs --keystore-password-file")
	}
	raw, err := os.ReadFile(opts.keystorePw)
	if err != nil {
		return err
	}
	password := strings.TrimRight(string(raw), "\r\n")
	n, err := recovery.WriteKeystores(opts.keystoreDir, password, children)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %d keystore files to %s\n", n, opts.keystoreDir)
	return nil
}
