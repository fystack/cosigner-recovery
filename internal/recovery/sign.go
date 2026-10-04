package recovery

import (
	"crypto/sha512"
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/v3/crypto"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

// SignEdDSA signs msg with a reconstructed group scalar and returns a standard
// RFC 8032 signature (R || S), verifiable by any ed25519 implementation.
func SignEdDSA(scalarHex string, msg []byte) ([]byte, error) {
	curve := tss.Edwards()
	order := curve.Params().N
	a, err := scalarFromHex(scalarHex)
	if err != nil {
		return nil, err
	}
	a.Mod(a, order)
	if a.Sign() == 0 {
		return nil, errors.New("zero scalar")
	}
	defer a.SetInt64(0)

	pub := crypto.ScalarBaseMult(curve, a)
	pubBytes := edwards.NewPublicKey(pub.X(), pub.Y()).Serialize()

	nonceHash := sha512.New()
	nonceHash.Write([]byte("fystack-recovery-eddsa-nonce"))
	nonceHash.Write(a.FillBytes(make([]byte, 32)))
	nonceHash.Write(msg)
	r := new(big.Int).SetBytes(nonceHash.Sum(nil))
	r.Mod(r, order)
	if r.Sign() == 0 {
		return nil, errors.New("degenerate nonce")
	}
	defer r.SetInt64(0)

	rPoint := crypto.ScalarBaseMult(curve, r)
	rBytes := edwards.NewPublicKey(rPoint.X(), rPoint.Y()).Serialize()

	challenge := sha512.New()
	challenge.Write(rBytes)
	challenge.Write(pubBytes)
	challenge.Write(msg)
	k := new(big.Int).SetBytes(reverse(challenge.Sum(nil)))
	k.Mod(k, order)

	s := new(big.Int).Mul(k, a)
	s.Add(s, r)
	s.Mod(s, order)

	sig := make([]byte, 64)
	copy(sig[:32], rBytes)
	copy(sig[32:], reverse(s.FillBytes(make([]byte, 32))))
	return sig, nil
}

func reverse(in []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		out[len(in)-1-i] = b
	}
	return out
}

// Base58Encode exposes the address/signature base58 encoding (Solana style).
func Base58Encode(in []byte) string { return base58Encode(in) }
