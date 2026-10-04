package main

import (
	"fmt"
	"os"
)

type entry struct {
	share      string
	rsaKeyPath string
	passphrase string
}

type options struct {
	asJSON      bool
	hdBundle    string
	hdRSAKey    string
	childrenOut string
	childrenIn  string
	keystoreDir string
	keystorePw  string

	rpc          string
	send         bool
	yes          bool
	planOut      string
	signedOut    string
	solAddresses string
	solPlan      string
	solSignPlan  string
	solBroadcast string
	solSweep     string
	signBatch    string
	signOut      string
}

func (o *options) valueFlags() map[string]*string {
	return map[string]*string{
		"--rpc":                    &o.rpc,
		"--plan-out":               &o.planOut,
		"--signed-out":             &o.signedOut,
		"--sol-addresses":          &o.solAddresses,
		"--sol-plan":               &o.solPlan,
		"--sol-sign-plan":          &o.solSignPlan,
		"--sol-broadcast":          &o.solBroadcast,
		"--sol-sweep":              &o.solSweep,
		"--hd-bundle":              &o.hdBundle,
		"--hd-rsa-key":             &o.hdRSAKey,
		"--children-out":           &o.childrenOut,
		"--children-in":            &o.childrenIn,
		"--keystore-dir":           &o.keystoreDir,
		"--keystore-password-file": &o.keystorePw,
		"--sign-eddsa":             &o.signBatch,
		"--sign-out":               &o.signOut,
	}
}

func parseArgs(args []string) ([]entry, options, error) {
	var entries []entry
	var opts options
	valueFlags := opts.valueFlags()

	for i := 0; i < len(args); i++ {
		flag := args[i]
		next := func() (string, bool) {
			i++
			if i >= len(args) {
				return "", false
			}
			return args[i], true
		}
		lastShare := func() *entry {
			if len(entries) == 0 {
				return nil
			}
			return &entries[len(entries)-1]
		}

		switch flag {
		case "--json":
			opts.asJSON = true
		case "--send":
			opts.send = true
		case "--yes":
			opts.yes = true
		case "-h", "--help":
			usage()
			os.Exit(0)
		case "--share":
			v, ok := next()
			if !ok {
				return nil, options{}, fmt.Errorf("--share needs a value")
			}
			entries = append(entries, entry{share: v})
		case "--rsa-key", "--passphrase":
			v, ok := next()
			share := lastShare()
			if share == nil || !ok {
				return nil, options{}, fmt.Errorf("%s must follow a --share", flag)
			}
			if flag == "--rsa-key" {
				share.rsaKeyPath = v
			} else {
				share.passphrase = v
			}
		default:
			dst, known := valueFlags[flag]
			if !known {
				return nil, options{}, fmt.Errorf("unknown argument: %s", flag)
			}
			v, ok := next()
			if !ok {
				return nil, options{}, fmt.Errorf("%s needs a value", flag)
			}
			*dst = v
		}
	}
	return entries, opts, nil
}
