package recovery

import (
	"math/big"

	"github.com/bnb-chain/tss-lib/v3/crypto"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"golang.org/x/crypto/sha3"
)

// ethereumAddress derives the EIP-55 checksummed address from a secp256k1 point.
func ethereumAddress(pub *crypto.ECPoint) string {
	raw := make([]byte, 64)
	pub.X().FillBytes(raw[:32])
	pub.Y().FillBytes(raw[32:])
	h := sha3.NewLegacyKeccak256()
	h.Write(raw)
	addr := h.Sum(nil)[12:]
	return "0x" + eip55(addr)
}

func eip55(addr []byte) string {
	const hexdigits = "0123456789abcdef"
	lower := make([]byte, 40)
	for i, b := range addr {
		lower[i*2] = hexdigits[b>>4]
		lower[i*2+1] = hexdigits[b&0x0f]
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(lower)
	hash := h.Sum(nil)
	out := make([]byte, 40)
	for i, c := range lower {
		if c >= 'a' && c <= 'f' && (hash[i/2]>>(4-(i%2)*4))&0x0f >= 8 {
			out[i] = c - 32
		} else {
			out[i] = c
		}
	}
	return string(out)
}

// solanaAddress derives the base58 address from an edwards25519 point.
func solanaAddress(pub *crypto.ECPoint) string {
	epub := edwards.NewPublicKey(pub.X(), pub.Y())
	return base58Encode(epub.Serialize())
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(input []byte) string {
	x := new(big.Int).SetBytes(input)
	radix := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var out []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, radix, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for _, b := range input {
		if b != 0 {
			break
		}
		out = append(out, base58Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}
