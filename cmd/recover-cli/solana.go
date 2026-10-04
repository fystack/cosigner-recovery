package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"recovery/internal/recovery"
	"recovery/internal/solana"
)

const defaultRPC = "https://api.mainnet-beta.solana.com"

func isSolanaMode(o options) bool {
	return o.solPlan != "" || o.solSignPlan != "" || o.solBroadcast != "" || o.solSweep != ""
}

func readJSONFile(path string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func writeJSONOutput(path string, v any) error {
	out := os.Stdout
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func rpcClient(o options) *solana.Client {
	if o.rpc == "" {
		return solana.NewClient(defaultRPC)
	}
	return solana.NewClient(o.rpc)
}

func solanaWallets(o options, children []recovery.ChildKey) ([]solana.Wallet, error) {
	var wallets []solana.Wallet
	if o.solAddresses != "" {
		var raw []json.RawMessage
		if err := readJSONFile(o.solAddresses, &raw); err != nil {
			return nil, fmt.Errorf("--sol-addresses must be a JSON array: %w", err)
		}
		for _, item := range raw {
			var addr string
			if json.Unmarshal(item, &addr) == nil {
				wallets = append(wallets, solana.Wallet{Address: addr})
				continue
			}
			var w struct {
				WalletID string `json:"wallet_id"`
				Address  string `json:"address"`
			}
			if err := json.Unmarshal(item, &w); err != nil || w.Address == "" {
				return nil, fmt.Errorf("--sol-addresses entries must be an address or {wallet_id, address}")
			}
			wallets = append(wallets, solana.Wallet{ID: w.WalletID, Address: w.Address})
		}
		return wallets, nil
	}
	for _, c := range children {
		if c.Protocol == recovery.ProtocolEdDSA {
			wallets = append(wallets, solana.Wallet{ID: c.WalletID, Address: c.Address})
		}
	}
	if len(wallets) == 0 {
		return nil, fmt.Errorf("no Solana wallets: pass --children-in or --sol-addresses")
	}
	return wallets, nil
}

func printPlanSummary(p *solana.Plan) {
	fmt.Fprintf(os.Stderr, "destination: %s\n", p.To)
	for i, tx := range p.Txs {
		fmt.Fprintf(os.Stderr, "  [%d] %s  %s\n", i+1, tx.Signer, tx.Description)
	}
	for _, n := range p.Notes {
		fmt.Fprintf(os.Stderr, "  note: %s\n", n)
	}
	fmt.Fprintf(os.Stderr, "%d transactions; blockhash expires in about 60-90 seconds after planning\n", len(p.Txs))
}

func confirmDestination(to string, yes bool) error {
	if yes {
		return nil
	}
	fmt.Fprintf(os.Stderr, "Type the destination address to confirm sending: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.TrimSpace(line) != to {
		return fmt.Errorf("destination not confirmed, nothing was sent")
	}
	return nil
}

func scalarsByAddress(children []recovery.ChildKey) map[string]string {
	scalars := map[string]string{}
	for _, c := range children {
		if c.Protocol == recovery.ProtocolEdDSA {
			scalars[c.Address] = c.PrivateKeyHex
		}
	}
	return scalars
}

func runSolana(opts options) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	var children []recovery.ChildKey
	if opts.childrenIn != "" {
		var err error
		if children, err = recovery.ReadChildKeys(opts.childrenIn); err != nil {
			return err
		}
	}

	switch {
	case opts.solBroadcast != "":
		var signed solana.Signed
		if err := readJSONFile(opts.solBroadcast, &signed); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%d signed transactions to %s\n", len(signed.Txs), signed.To)
		if !opts.send {
			fmt.Fprintln(os.Stderr, "dry run: pass --send to broadcast")
			return nil
		}
		if err := confirmDestination(signed.To, opts.yes); err != nil {
			return err
		}
		return solana.Broadcast(ctx, rpcClient(opts), &signed, func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) })

	case opts.solSignPlan != "":
		var plan solana.Plan
		if err := readJSONFile(opts.solSignPlan, &plan); err != nil {
			return err
		}
		if len(children) == 0 {
			return fmt.Errorf("--sol-sign-plan needs --children-in")
		}
		printPlanSummary(&plan)
		signed, err := solana.SignPlan(&plan, scalarsByAddress(children))
		if err != nil {
			return err
		}
		return writeJSONOutput(opts.signedOut, signed)

	case opts.solPlan != "":
		wallets, err := solanaWallets(opts, children)
		if err != nil {
			return err
		}
		plan, err := solana.BuildPlan(ctx, rpcClient(opts), opts.solPlan, wallets)
		if err != nil {
			return err
		}
		printPlanSummary(plan)
		return writeJSONOutput(opts.planOut, plan)

	default:
		wallets, err := solanaWallets(opts, children)
		if err != nil {
			return err
		}
		client := rpcClient(opts)
		plan, err := solana.BuildPlan(ctx, client, opts.solSweep, wallets)
		if err != nil {
			return err
		}
		printPlanSummary(plan)
		if len(plan.Txs) == 0 {
			return fmt.Errorf("nothing to sweep")
		}
		if !opts.send {
			fmt.Fprintln(os.Stderr, "dry run: pass --send to sign and broadcast")
			return nil
		}
		if err := confirmDestination(plan.To, opts.yes); err != nil {
			return err
		}
		signed, err := solana.SignPlan(plan, scalarsByAddress(children))
		if err != nil {
			return err
		}
		return solana.Broadcast(ctx, client, signed, func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) })
	}
}
