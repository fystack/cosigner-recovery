package solana

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"recovery/internal/recovery"
)

// Validate re-checks that every message only moves funds to plan.To, so a plan file
// from an untrusted (online) machine is safe to sign offline.
func Validate(plan *Plan) error {
	if plan.Version != planVersion {
		return fmt.Errorf("unsupported plan version %d", plan.Version)
	}
	toPK, err := ParseAddress(plan.To)
	if err != nil {
		return err
	}
	for i, tx := range plan.Txs {
		raw, err := base64.StdEncoding.DecodeString(tx.Message)
		if err != nil {
			return fmt.Errorf("tx %d: bad message encoding", i)
		}
		if err := validateMessage(raw, tx.Signer, toPK, plan.Blockhash); err != nil {
			return fmt.Errorf("tx %d (%s): %w", i, tx.Wallet, err)
		}
	}
	return nil
}

func validateMessage(raw []byte, signer string, to PublicKey, blockhash string) error {
	pm, err := ParseMessage(raw)
	if err != nil {
		return err
	}
	payer, err := ParseAddress(signer)
	if err != nil {
		return err
	}
	if pm.NumSigners != 1 || len(pm.Keys) == 0 || pm.Keys[0] != payer {
		return errors.New("fee payer does not match the signer")
	}
	if recovery.Base58Encode(pm.Blockhash[:]) != blockhash {
		return errors.New("blockhash does not match the plan")
	}
	if len(pm.Instructions) == 0 {
		return errors.New("no instructions")
	}
	isToken := func(p PublicKey) bool { return p == TokenProgram || p == Token2022Program }
	for _, ix := range pm.Instructions {
		switch {
		case ix.Program == SystemProgram:
			if len(ix.Data) != 12 || binary.LittleEndian.Uint32(ix.Data) != 2 || len(ix.Accounts) != 2 ||
				ix.Accounts[0] != payer || ix.Accounts[1] != to {
				return errors.New("unexpected system instruction")
			}
		case isToken(ix.Program):
			if len(ix.Data) == 0 {
				return errors.New("empty token instruction")
			}
			switch ix.Data[0] {
			case 12:
				if len(ix.Accounts) != 4 || ix.Accounts[3] != payer || ix.Accounts[2] != FindATA(to, ix.Accounts[1], ix.Program) {
					return errors.New("token transfer does not go to the destination")
				}
			case 9:
				if len(ix.Accounts) != 3 || ix.Accounts[1] != payer || ix.Accounts[2] != payer {
					return errors.New("unexpected token close instruction")
				}
			default:
				return fmt.Errorf("unexpected token instruction %d", ix.Data[0])
			}
		case ix.Program == AssociatedProgram:
			if !bytes.Equal(ix.Data, []byte{1}) || len(ix.Accounts) != 6 || ix.Accounts[0] != payer ||
				ix.Accounts[2] != to || !isToken(ix.Accounts[5]) ||
				ix.Accounts[1] != FindATA(to, ix.Accounts[3], ix.Accounts[5]) {
				return errors.New("unexpected associated token account instruction")
			}
		default:
			return fmt.Errorf("instruction for unknown program %s", ix.Program)
		}
	}
	return nil
}
