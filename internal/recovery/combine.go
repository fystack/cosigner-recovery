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

// combine reconstructs a wallet's private key from t+1 decrypted share JSON blobs.
func combine(protocolName string, shareBlobs [][]byte) (*CombinedKey, error) {
	switch normalizeProtocol(protocolName) {
	case ProtocolECDSA:
		return combineECDSA(shareBlobs)
	case ProtocolEdDSA:
		return combineEdDSA(shareBlobs)
	default:
		return nil, errors.New("unsupported protocol: " + protocolName)
	}
}

func combineECDSA(blobs [][]byte) (*CombinedKey, error) {
	curve := tss.S256()
	order := curve.Params().N
	xs := make([]*big.Int, 0, len(blobs))
	shares := make([]*big.Int, 0, len(blobs))
	var pub *crypto.ECPoint
	for _, blob := range blobs {
		var d ecdsaKeygen.LocalPartySaveData
		if err := json.Unmarshal(blob, &d); err != nil {
			return nil, errors.New("invalid ECDSA share data")
		}
		if d.Xi == nil || d.ShareID == nil {
			return nil, errors.New("ECDSA share missing Xi/ShareID")
		}
		xs = append(xs, d.ShareID)
		shares = append(shares, d.Xi)
		if d.ECDSAPub != nil {
			pub = d.ECDSAPub
		}
	}
	priv, err := lagrange(xs, shares, order)
	if err != nil {
		return nil, err
	}
	defer priv.SetInt64(0)

	buf := make([]byte, 32)
	priv.FillBytes(buf)
	res := &CombinedKey{Protocol: ProtocolECDSA, PrivateKeyHex: hex.EncodeToString(buf)}

	if pub != nil {
		computed := crypto.ScalarBaseMult(curve, priv)
		res.Verified = computed.X().Cmp(pub.X()) == 0 && computed.Y().Cmp(pub.Y()) == 0
		res.PublicKeyHex = hex.EncodeToString(elliptic.MarshalCompressed(curve, pub.X(), pub.Y()))
		res.TestSigned = res.Verified && testSignECDSA(curve, priv, pub)
		if res.Verified {
			res.Address = ethereumAddress(pub)
			res.AddressLabel = "Ethereum / EVM address"
		} else {
			return res, errors.New("reconstructed ECDSA key does not match public key")
		}
	}
	return res, nil
}

func combineEdDSA(blobs [][]byte) (*CombinedKey, error) {
	curve := tss.Edwards()
	order := curve.Params().N
	xs := make([]*big.Int, 0, len(blobs))
	shares := make([]*big.Int, 0, len(blobs))
	var pub *crypto.ECPoint
	for _, blob := range blobs {
		var d eddsaKeygen.LocalPartySaveData
		if err := json.Unmarshal(blob, &d); err != nil {
			return nil, errors.New("invalid EdDSA share data")
		}
		if d.Xi == nil || d.ShareID == nil {
			return nil, errors.New("EdDSA share missing Xi/ShareID")
		}
		xs = append(xs, d.ShareID)
		shares = append(shares, d.Xi)
		if d.EDDSAPub != nil {
			pub = d.EDDSAPub
		}
	}
	priv, err := lagrange(xs, shares, order)
	if err != nil {
		return nil, err
	}
	defer priv.SetInt64(0)

	buf := make([]byte, 32)
	priv.FillBytes(buf)
	res := &CombinedKey{Protocol: ProtocolEdDSA, PrivateKeyHex: hex.EncodeToString(buf)}

	if pub != nil {
		computed := crypto.ScalarBaseMult(curve, priv)
		res.Verified = computed.X().Cmp(pub.X()) == 0 && computed.Y().Cmp(pub.Y()) == 0
		res.PublicKeyHex = hex.EncodeToString(elliptic.MarshalCompressed(curve, pub.X(), pub.Y()))
		res.TestSigned = res.Verified && testSignEdDSA(priv, pub)
		res.Note = "Reconstructed group scalar, not a 32-byte ed25519 seed."
		if res.Verified {
			res.Address = solanaAddress(pub)
			res.AddressLabel = "Solana address"
		} else {
			return res, errors.New("reconstructed EdDSA key does not match public key")
		}
	}
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
