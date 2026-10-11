package recovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"github.com/bnb-chain/tss-lib/v3/crypto"
	ecdsaKeygen "github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	eddsaKeygen "github.com/bnb-chain/tss-lib/v3/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

const (
	ProtocolECDSA = "ECDSA"
	ProtocolEdDSA = "EdDSA"
)

type CombinedKey struct {
	Protocol      string `json:"protocol"`
	PrivateKeyHex string `json:"privateKeyHex"`
	PublicKeyHex  string `json:"publicKeyHex"`
	Address       string `json:"address"`
	AddressLabel  string `json:"addressLabel"`
	Note          string `json:"note"`
	Verified      bool   `json:"verified"`
	TestSigned    bool   `json:"testSigned"`
}

func normalizeProtocol(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "ecdsa":
		return ProtocolECDSA
	case "eddsa":
		return ProtocolEdDSA
	default:
		return strings.ToUpper(strings.TrimSpace(p))
	}
}

type shareData struct {
	shareID *big.Int
	xi      *big.Int
	pub     *crypto.ECPoint
	parties int
}

// protocolSpec holds what differs between ECDSA and EdDSA when combining shares.
type protocolSpec struct {
	name      string
	curve     elliptic.Curve
	parse     func(blob []byte) (shareData, error)
	testSign  func(priv *big.Int, pub *crypto.ECPoint) bool
	address   func(pub *crypto.ECPoint) string
	addrLabel string
	note      string
}

var protocolSpecs = map[string]protocolSpec{
	ProtocolECDSA: {
		name:  ProtocolECDSA,
		curve: tss.S256(),
		parse: func(blob []byte) (shareData, error) {
			var d ecdsaKeygen.LocalPartySaveData
			if err := json.Unmarshal(blob, &d); err != nil {
				return shareData{}, errors.New("invalid ECDSA share data")
			}
			return shareData{d.ShareID, d.Xi, d.ECDSAPub, len(d.Ks)}, nil
		},
		testSign:  func(priv *big.Int, pub *crypto.ECPoint) bool { return testSignECDSA(tss.S256(), priv, pub) },
		address:   ethereumAddress,
		addrLabel: "Ethereum / EVM address",
	},
	ProtocolEdDSA: {
		name:  ProtocolEdDSA,
		curve: tss.Edwards(),
		parse: func(blob []byte) (shareData, error) {
			var d eddsaKeygen.LocalPartySaveData
			if err := json.Unmarshal(blob, &d); err != nil {
				return shareData{}, errors.New("invalid EdDSA share data")
			}
			return shareData{d.ShareID, d.Xi, d.EDDSAPub, len(d.Ks)}, nil
		},
		testSign:  testSignEdDSA,
		address:   solanaAddress,
		addrLabel: "Solana address",
		note:      "Reconstructed group scalar, not a 32-byte ed25519 seed.",
	},
}

// ErrInsufficientShares means the shares interpolated to a key that doesn't match the wallet's public key,
// which happens when fewer than threshold+1 distinct participants were supplied.
var ErrInsufficientShares = errors.New("not enough shares to reach the signing threshold")

// partyCount returns the total number of participants recorded in a share blob, or 0 if unknown.
func partyCount(protocolName string, blob []byte) int {
	spec, ok := protocolSpecs[normalizeProtocol(protocolName)]
	if !ok {
		return 0
	}
	d, err := spec.parse(blob)
	if err != nil {
		return 0
	}
	return d.parties
}

// combine reconstructs a wallet's private key from any number (>= threshold+1) of decrypted share JSON blobs.
func combine(protocolName string, shareBlobs [][]byte) (*CombinedKey, error) {
	spec, ok := protocolSpecs[normalizeProtocol(protocolName)]
	if !ok {
		return nil, errors.New("unsupported protocol: " + protocolName)
	}
	return spec.combine(shareBlobs)
}

func (p protocolSpec) combine(blobs [][]byte) (*CombinedKey, error) {
	order := p.curve.Params().N
	xs := make([]*big.Int, 0, len(blobs))
	shares := make([]*big.Int, 0, len(blobs))
	var pub *crypto.ECPoint
	seen := map[string]bool{}
	for _, blob := range blobs {
		d, err := p.parse(blob)
		if err != nil {
			return nil, err
		}
		if d.xi == nil || d.shareID == nil {
			return nil, errors.New(p.name + " share missing Xi/ShareID")
		}
		// The same participant's share may arrive via several files (e.g. .enc and .mshare).
		if seen[d.shareID.String()] {
			continue
		}
		seen[d.shareID.String()] = true
		xs = append(xs, d.shareID)
		shares = append(shares, d.xi)
		if d.pub != nil {
			pub = d.pub
		}
	}
	priv, err := lagrange(xs, shares, order)
	if err != nil {
		return nil, err
	}
	defer priv.SetInt64(0)

	res := &CombinedKey{Protocol: p.name, PrivateKeyHex: hex.EncodeToString(priv.FillBytes(make([]byte, 32))), Note: p.note}
	if pub == nil {
		return res, nil
	}

	computed := crypto.ScalarBaseMult(p.curve, priv)
	res.Verified = computed.X().Cmp(pub.X()) == 0 && computed.Y().Cmp(pub.Y()) == 0
	res.PublicKeyHex = hex.EncodeToString(elliptic.MarshalCompressed(p.curve, pub.X(), pub.Y()))
	if !res.Verified {
		return res, ErrInsufficientShares
	}
	res.TestSigned = p.testSign(priv, pub)
	res.Address = p.address(pub)
	res.AddressLabel = p.addrLabel
	return res, nil
}

// lagrange reconstructs f(0) = secret from points (xs[i], shares[i]) mod order.
func lagrange(xs, shares []*big.Int, order *big.Int) (*big.Int, error) {
	if len(xs) < 2 {
		return nil, errors.New("need at least 2 shares to reconstruct")
	}
	secret := big.NewInt(0)
	for i := range xs {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j := range xs {
			if i == j {
				continue
			}
			num.Mul(num, xs[j])
			num.Mod(num, order)
			diff := new(big.Int).Sub(xs[j], xs[i])
			diff.Mod(diff, order)
			den.Mul(den, diff)
			den.Mod(den, order)
		}
		denInv := new(big.Int).ModInverse(den, order)
		if denInv == nil {
			return nil, errors.New("duplicate ShareID among inputs")
		}
		lambda := new(big.Int).Mul(num, denInv)
		lambda.Mod(lambda, order)
		term := new(big.Int).Mul(shares[i], lambda)
		term.Mod(term, order)
		secret.Add(secret, term)
		secret.Mod(secret, order)
	}
	return secret, nil
}

func testSignECDSA(curve elliptic.Curve, priv *big.Int, pub *crypto.ECPoint) bool {
	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: pub.X(), Y: pub.Y()},
		D:         priv,
	}
	hash := sha256.Sum256([]byte("mpcium recovery test"))
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return false
	}
	return ecdsa.VerifyASN1(&key.PublicKey, hash[:], sig)
}

func testSignEdDSA(priv *big.Int, pub *crypto.ECPoint) bool {
	sk, _, err := edwards.PrivKeyFromScalar(priv.FillBytes(make([]byte, 32)))
	if err != nil {
		return false
	}
	msg := []byte("mpcium recovery test")
	r, s, err := edwards.Sign(sk, msg)
	if err != nil {
		return false
	}
	return edwards.Verify(sk.PubKey(), msg, r, s)
}
