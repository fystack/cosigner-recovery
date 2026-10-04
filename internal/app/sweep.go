package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"recovery/internal/recovery"
	"recovery/internal/solana"
)

const planMaxAge = 50 * time.Second

var childKeysFilters = []runtime.FileFilter{{DisplayName: "Child keys (*.json)", Pattern: "*.json"}, allFiles}

type sweepState struct {
	mu   sync.Mutex
	keys []recovery.ChildKey
	plan *solana.Plan
}

type SweepWalletView struct {
	WalletID string `json:"walletId"`
	Name     string `json:"name"`
	Address  string `json:"address"`
}

type SweepKeysInfo struct {
	Loaded  bool              `json:"loaded"`
	Wallets []SweepWalletView `json:"wallets"`
}

type SweepTxView struct {
	Name        string `json:"name"`
	Signer      string `json:"signer"`
	Description string `json:"description"`
}

type SweepPlanView struct {
	To    string        `json:"to"`
	Txs   []SweepTxView `json:"txs"`
	Notes []string      `json:"notes"`
}

type SweepResult struct {
	Log   []string `json:"log"`
	Error string   `json:"error"`
}

func (s *sweepState) infoLocked() SweepKeysInfo {
	info := SweepKeysInfo{Loaded: len(s.keys) > 0, Wallets: []SweepWalletView{}}
	for _, k := range s.keys {
		info.Wallets = append(info.Wallets, SweepWalletView{WalletID: k.WalletID, Name: k.Name, Address: k.Address})
	}
	return info
}

func (a *App) SweepKeys() SweepKeysInfo {
	a.sweep.mu.Lock()
	defer a.sweep.mu.Unlock()
	return a.sweep.infoLocked()
}

// LoadSweepKeys picks a child-keys JSON exported from the recovery flow and keeps its Solana keys in memory.
func (a *App) LoadSweepKeys() (SweepKeysInfo, error) {
	path, err := a.pickFile("Select the child keys file", childKeysFilters...)
	if err != nil || path == "" {
		return a.SweepKeys(), err
	}
	all, err := recovery.ReadChildKeys(path)
	if err != nil {
		return SweepKeysInfo{}, errors.New("not a child keys file exported from Fystack Recovery")
	}
	var keys []recovery.ChildKey
	for _, k := range all {
		if k.Protocol == recovery.ProtocolEdDSA && k.PrivateKeyHex != "" && k.Address != "" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return SweepKeysInfo{}, errors.New("the file has no Solana (EdDSA) keys")
	}
	a.sweep.mu.Lock()
	defer a.sweep.mu.Unlock()
	a.sweep.keys, a.sweep.plan = keys, nil
	return a.sweep.infoLocked(), nil
}

// SweepScan reads balances on-chain and builds the transfer plan; nothing is signed or sent.
func (a *App) SweepScan(to, rpcURL string) (SweepPlanView, error) {
	a.sweep.mu.Lock()
	defer a.sweep.mu.Unlock()
	if len(a.sweep.keys) == 0 {
		return SweepPlanView{}, errors.New("load the child keys file first")
	}
	wallets := make([]solana.Wallet, 0, len(a.sweep.keys))
	for _, k := range a.sweep.keys {
		wallets = append(wallets, solana.Wallet{ID: k.WalletID, Name: k.Name, Address: k.Address})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client := solana.NewClient(rpcOrDefault(rpcURL))
	plan, err := solana.BuildPlan(ctx, client, to, wallets)
	if err != nil {
		return SweepPlanView{}, err
	}
	a.sweep.plan = plan
	view := SweepPlanView{To: plan.To, Txs: []SweepTxView{}, Notes: plan.Notes}
	if view.Notes == nil {
		view.Notes = []string{}
	}
	names := map[string]string{}
	for _, k := range a.sweep.keys {
		names[k.Address] = k.Name
	}
	for _, tx := range plan.Txs {
		view.Txs = append(view.Txs, SweepTxView{Name: names[tx.Signer], Signer: tx.Signer, Description: tx.Description})
	}
	return view, nil
}

func rpcOrDefault(url string) string {
	if url == "" {
		return "https://api.mainnet-beta.solana.com"
	}
	return url
}

func (a *App) signSweepLocked() (*solana.Signed, error) {
	if a.sweep.plan == nil || len(a.sweep.plan.Txs) == 0 {
		return nil, errors.New("scan first, there is nothing to sign")
	}
	scalars := map[string]string{}
	for _, k := range a.sweep.keys {
		scalars[k.Address] = k.PrivateKeyHex
	}
	return solana.SignPlan(a.sweep.plan, scalars)
}

// SweepSend signs the scanned plan and broadcasts it; confirmTo must repeat the destination address.
func (a *App) SweepSend(confirmTo, rpcURL string) (SweepResult, error) {
	a.sweep.mu.Lock()
	defer a.sweep.mu.Unlock()
	if a.sweep.plan == nil || confirmTo != a.sweep.plan.To {
		return SweepResult{}, errors.New("the typed address does not match the destination")
	}
	if created, err := time.Parse(time.RFC3339, a.sweep.plan.CreatedAt); err == nil && time.Since(created) > planMaxAge {
		a.sweep.plan = nil
		return SweepResult{}, errors.New("the scan expired (blockhashes last about a minute), scan again and send right away")
	}
	signed, err := a.signSweepLocked()
	if err != nil {
		return SweepResult{}, err
	}
	result := SweepResult{Log: []string{}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	logf := func(f string, args ...any) {
		line := fmt.Sprintf(f, args...)
		result.Log = append(result.Log, line)
		runtime.EventsEmit(a.ctx, "sweep:log", line)
	}
	if err := solana.Broadcast(ctx, solana.NewClient(rpcOrDefault(rpcURL)), signed, logf); err != nil {
		result.Error = err.Error()
	}
	a.sweep.plan = nil
	return result, nil
}

// SweepSaveSigned signs the plan and writes it to a file for broadcasting on another machine.
func (a *App) SweepSaveSigned() (string, error) {
	a.sweep.mu.Lock()
	defer a.sweep.mu.Unlock()
	signed, err := a.signSweepLocked()
	if err != nil {
		return "", err
	}
	path, err := a.pickSavePath("Save the signed transactions", "signed-sweep.json")
	if err != nil {
		return "", err
	}
	raw, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, raw, 0o600)
}

func (a *App) ResetSweep() {
	a.sweep.mu.Lock()
	defer a.sweep.mu.Unlock()
	a.sweep.keys, a.sweep.plan = nil, nil
}
