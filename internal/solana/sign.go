package solana

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"recovery/internal/recovery"
)

// SignPlan signs every transaction; scalars maps a signer address to its EdDSA scalar hex.
func SignPlan(plan *Plan, scalars map[string]string) (*Signed, error) {
	if err := Validate(plan); err != nil {
		return nil, err
	}
	signed := &Signed{Version: planVersion, To: plan.To, LastValidBlockHeight: plan.LastValidBlockHeight}
	for i, tx := range plan.Txs {
		scalar, ok := scalars[tx.Signer]
		if !ok {
			return nil, fmt.Errorf("tx %d: no key for signer %s in the keys file", i, tx.Signer)
		}
		msg, _ := base64.StdEncoding.DecodeString(tx.Message)
		sig, err := recovery.SignEdDSA(scalar, msg)
		if err != nil {
			return nil, err
		}
		pub, _ := decodeBase58(tx.Signer)
		if !ed25519.Verify(pub, msg, sig) {
			return nil, fmt.Errorf("tx %d: signature does not verify for %s", i, tx.Signer)
		}
		wire := append(putCompact(nil, 1), sig...)
		wire = append(wire, msg...)
		signed.Txs = append(signed.Txs, SignedTx{
			Wallet: tx.Wallet, Signer: tx.Signer, Description: tx.Description,
			Signature: recovery.Base58Encode(sig), Tx: base64.StdEncoding.EncodeToString(wire),
		})
	}
	return signed, nil
}
