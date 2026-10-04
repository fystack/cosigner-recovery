// Command recover-cli reconstructs a wallet's ECDSA/EdDSA private keys from
// threshold share files, using the same engine as the desktop app.
//
// WARNING: this materializes the raw private key and defeats the threshold
// security of the wallet. Run only offline, on an air-gapped machine.
package main

import (
	"fmt"
	"os"

	"recovery/internal/recovery"
)

func main() {
	entries, opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		usage()
		os.Exit(2)
	}
	switch {
	case isSolanaMode(opts):
		if err := runSolana(opts); err != nil {
			fatal(err)
		}
	case opts.childrenIn != "":
		runFromChildrenFile(opts)
	default:
		runFromShares(entries, opts)
	}
}

func runFromChildrenFile(opts options) {
	if opts.signBatch == "" && opts.keystoreDir == "" {
		fatal(fmt.Errorf("--children-in needs --sign-eddsa and/or --keystore-dir"))
	}
	children, err := recovery.ReadChildKeys(opts.childrenIn)
	if err != nil {
		fatal(err)
	}
	runChildOutputs(opts, children)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
