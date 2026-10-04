package solana

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	txFeeLamports  = 5000
	tokenAcctSpace = 165
	planVersion    = 1
)

type Wallet struct {
	ID      string
	Name    string
	Address string
}

type PlannedTx struct {
	Wallet      string `json:"wallet"`
	Signer      string `json:"signer"`
	Description string `json:"description"`
	Message     string `json:"message"`
}

type Plan struct {
	Version              int         `json:"version"`
	To                   string      `json:"to"`
	Blockhash            string      `json:"blockhash"`
	LastValidBlockHeight uint64      `json:"lastValidBlockHeight"`
	CreatedAt            string      `json:"createdAt"`
	Txs                  []PlannedTx `json:"txs"`
	Notes                []string    `json:"notes,omitempty"`
}

type SignedTx struct {
	Wallet      string `json:"wallet"`
	Signer      string `json:"signer"`
	Description string `json:"description"`
	Signature   string `json:"signature"`
	Tx          string `json:"tx"`
}

type Signed struct {
	Version              int        `json:"version"`
	To                   string     `json:"to"`
	LastValidBlockHeight uint64     `json:"lastValidBlockHeight"`
	Txs                  []SignedTx `json:"txs"`
}

type pendingTx struct {
	wallet  Wallet
	owner   PublicKey
	ixs     []Instruction
	descs   []string
	spent   uint64
	refund  uint64
	hasBase bool
}

func (p *pendingTx) fits(extra []Instruction) bool {
	all := append(append([]Instruction(nil), p.ixs...), extra...)
	return len(CompileMessage(p.owner, [32]byte{}, all))+1+64 <= maxTxSize
}

// BuildPlan scans each wallet on-chain and plans transfers of every SPL token, then all SOL, to `to`.
func BuildPlan(ctx context.Context, c *Client, to string, wallets []Wallet) (*Plan, error) {
	toPK, err := ParseAddress(to)
	if err != nil {
		return nil, err
	}
	ataRent, err := c.GetRentExemption(ctx, tokenAcctSpace)
	if err != nil {
		return nil, err
	}

	plan := &Plan{Version: planVersion, To: to, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	var pending []*pendingTx
	ataKnown := map[PublicKey]bool{}

	ensureATA := func(ata PublicKey) (bool, error) {
		if known, ok := ataKnown[ata]; ok {
			return known, nil
		}
		exists, err := c.AccountExists(ctx, ata.String())
		ataKnown[ata] = exists
		return exists, err
	}

	for _, w := range wallets {
		owner, err := ParseAddress(w.Address)
		if err != nil {
			return nil, err
		}
		if owner == toPK {
			plan.Notes = append(plan.Notes, fmt.Sprintf("%s: is the destination, skipped", short(w)))
			continue
		}
		balance, err := c.GetBalance(ctx, w.Address)
		if err != nil {
			return nil, err
		}
		var tokens []TokenAccount
		for _, program := range []PublicKey{TokenProgram, Token2022Program} {
			accts, err := c.GetTokenAccounts(ctx, w.Address, program)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, accts...)
		}
		if balance == 0 && len(tokens) == 0 {
			plan.Notes = append(plan.Notes, fmt.Sprintf("%s: empty", short(w)))
			continue
		}

		bal := balance
		cur := &pendingTx{wallet: w, owner: owner}
		finalize := func() {
			if len(cur.ixs) == 0 {
				return
			}
			bal = bal - cur.spent + cur.refund
			pending = append(pending, cur)
			cur = &pendingTx{wallet: w, owner: owner}
		}

		for _, ta := range tokens {
			if ta.Frozen {
				plan.Notes = append(plan.Notes, fmt.Sprintf("%s: token account %s is frozen, skipped", short(w), ta.Address))
				continue
			}
			mint, err := ParseAddress(ta.Mint)
			if err != nil {
				return nil, err
			}
			source, err := ParseAddress(ta.Address)
			if err != nil {
				return nil, err
			}
			var group []Instruction
			var desc string
			var rent uint64
			if ta.Amount > 0 {
				ata := FindATA(toPK, mint, ta.Program)
				exists, err := ensureATA(ata)
				if err != nil {
					return nil, err
				}
				group = append(group, CreateATAIdempotent(owner, ata, toPK, mint, ta.Program))
				if !exists {
					rent = ataRent
					ataKnown[ata] = true
				}
				group = append(group, TokenTransferChecked(ta.Program, source, mint, ata, owner, ta.Amount, ta.Decimals))
				desc = fmt.Sprintf("token %s amount %d (raw)", ta.Mint, ta.Amount)
			} else {
				desc = fmt.Sprintf("close empty token account of %s", ta.Mint)
			}
			group = append(group, TokenCloseAccount(ta.Program, source, owner, owner))

			if len(cur.ixs) > 0 && !cur.fits(group) {
				finalize()
			}
			cost := rent
			if !cur.hasBase {
				cost += txFeeLamports
			}
			if cur.spent+cost > bal {
				plan.Notes = append(plan.Notes, fmt.Sprintf("%s: not enough SOL for fees/rent, skipped %s", short(w), desc))
				continue
			}
			cur.ixs = append(cur.ixs, group...)
			cur.descs = append(cur.descs, desc)
			cur.spent += cost
			cur.refund += ta.Lamports
			cur.hasBase = true
		}
		finalize()

		if bal > txFeeLamports {
			pending = append(pending, &pendingTx{
				wallet: w, owner: owner,
				ixs:   []Instruction{SystemTransfer(owner, toPK, bal-txFeeLamports)},
				descs: []string{fmt.Sprintf("%s SOL", formatSOL(bal-txFeeLamports))},
			})
		} else if bal > 0 {
			plan.Notes = append(plan.Notes, fmt.Sprintf("%s: %d lamports left, not enough to pay a fee", short(w), bal))
		}
	}

	blockhash, lastValid, err := c.GetLatestBlockhash(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := decodeBase58(blockhash)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("invalid blockhash from RPC")
	}
	var bh [32]byte
	copy(bh[:], raw)
	plan.Blockhash, plan.LastValidBlockHeight = blockhash, lastValid

	for _, p := range pending {
		plan.Txs = append(plan.Txs, PlannedTx{
			Wallet:      p.wallet.ID,
			Signer:      p.wallet.Address,
			Description: strings.Join(p.descs, "; "),
			Message:     base64.StdEncoding.EncodeToString(CompileMessage(p.owner, bh, p.ixs)),
		})
	}
	return plan, nil
}

func short(w Wallet) string {
	if w.Name != "" {
		return w.Name
	}
	if w.ID != "" {
		return w.ID
	}
	return w.Address
}

func formatSOL(lamports uint64) string {
	s := fmt.Sprintf("%d.%09d", lamports/1e9, lamports%1e9)
	return strings.TrimRight(strings.TrimRight(s, "0"), ".")
}
