package recovery

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v3/crypto"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"recovery/internal/ckd"
	"recovery/internal/envelope"
)

const hdRecoveryFormat = "fystack-hd-recovery-v1"

type HDChild struct {
	WalletID        string   `json:"wallet_id"`
	Name            string   `json:"name"`
	DerivationIndex uint32   `json:"derivation_index"`
	DerivationPath  []uint32 `json:"derivation_path"`
}

type HDBundle struct {
	Format               string    `json:"format"`
	MasterWalletID       string    `json:"master_wallet_id"`
	KeyID                string    `json:"key_id"`
	CKDVersion           string    `json:"ckd_version"`
	Threshold            uint32    `json:"threshold"`
	ChainCode            string    `json:"chain_code"`
	MasterPublicKeyECDSA string    `json:"master_public_key_ecdsa,omitempty"`
	MasterPublicKeyEDDSA string    `json:"master_public_key_eddsa,omitempty"`
	Children             []HDChild `json:"children"`
}

type ChildKey struct {
	WalletID       string   `json:"walletId"`
	Name           string   `json:"name"`
	DerivationPath []uint32 `json:"derivationPath"`
	Protocol       string   `json:"protocol"`
	PrivateKeyHex  string   `json:"privateKeyHex"`
	PublicKeyHex   string   `json:"publicKeyHex"`
	Address        string   `json:"address"`
	AddressLabel   string   `json:"addressLabel"`
	Note           string   `json:"note,omitempty"`
}

type hdBundleFile struct {
	Format   string `json:"format"`
	Envelope string `json:"envelope"`
}

const hdBundleFileFormat = "fystack-hd-recovery-bundle-v1"

func LooksLikeHDBundle(raw []byte) bool {
	var f hdBundleFile
	return json.Unmarshal(raw, &f) == nil && f.Format == hdBundleFileFormat
}

func OpenHDBundle(raw []byte, rsaKeyPEM []byte) (*HDBundle, error) {
	var f hdBundleFile
	if err := json.Unmarshal(raw, &f); err != nil || f.Format != hdBundleFileFormat || f.Envelope == "" {
		return nil, errors.New("not a Fystack HD derivation bundle")
	}
	priv, err := loadRSAPrivateKey(rsaKeyPEM)
	if err != nil {
		return nil, err
	}
	return openHDEnvelope(f.Envelope, priv)
}

func openHDEnvelope(sealed string, priv *rsa.PrivateKey) (*HDBundle, error) {
	plain, err := envelope.Open([]byte(sealed), priv)
	if err != nil {
		return nil, errors.New("decrypt HD bundle failed: wrong RSA key or corrupted file")
	}
	defer wipe(plain)
	var b HDBundle
	if err := json.Unmarshal(plain, &b); err != nil {
		return nil, errors.New("invalid HD bundle content")
	}
	if b.Format != hdRecoveryFormat {
		return nil, fmt.Errorf("unsupported HD bundle format %q", b.Format)
	}
	return &b, nil
}

// childScheme captures everything that differs between the ECDSA and EdDSA derivations.
type childScheme struct {
	curve        elliptic.Curve
	label        string
	note         string
	masterPublic func(b *HDBundle, master *CombinedKey) ([]byte, error)
	derive       func(masterPub []byte, chainCode string, path []uint32) (pub, delta []byte, err error)
	serialize    func(p *crypto.ECPoint) []byte
	address      func(derivedPub []byte, p *crypto.ECPoint) string
	decorate     func(entry *ChildKey, masterPub []byte)
}

var childSchemes = map[string]childScheme{
	ProtocolECDSA: {
		curve: tss.S256(),
		label: "Ethereum / EVM address",
		masterPublic: func(_ *HDBundle, master *CombinedKey) ([]byte, error) {
			return hex.DecodeString(master.PublicKeyHex)
		},
		derive: func(masterPub []byte, chainCode string, path []uint32) ([]byte, []byte, error) {
			r, err := ckd.DeriveSecp256k1(masterPub, chainCode, path)
			if err != nil {
				return nil, nil, err
			}
			return r.PublicKey, r.Delta, nil
		},
		serialize: func(p *crypto.ECPoint) []byte { return elliptic.MarshalCompressed(tss.S256(), p.X(), p.Y()) },
		address:   func(_ []byte, p *crypto.ECPoint) string { return ethereumAddress(p) },
	},
	ProtocolEdDSA: {
		curve: tss.Edwards(),
		label: "Solana address",
		note:  "Group scalar, not a 32-byte ed25519 seed; sign with recover-cli --sign-eddsa.",
		masterPublic: func(b *HDBundle, _ *CombinedKey) ([]byte, error) {
			if b.MasterPublicKeyEDDSA == "" {
				return nil, errors.New("HD bundle has no EdDSA master public key")
			}
			return hex.DecodeString(b.MasterPublicKeyEDDSA)
		},
		derive: func(masterPub []byte, chainCode string, path []uint32) ([]byte, []byte, error) {
			r, err := ckd.DeriveEd25519(masterPub, chainCode, path)
			if err != nil {
				return nil, nil, err
			}
			return r.PublicKey, r.Delta, nil
		},
		serialize: func(p *crypto.ECPoint) []byte { return edwards.NewPublicKey(p.X(), p.Y()).Serialize() },
		address:   func(derivedPub []byte, _ *crypto.ECPoint) string { return base58Encode(derivedPub) },
		decorate: func(entry *ChildKey, masterPub []byte) {
			entry.PublicKeyHex = hex.EncodeToString(masterPub)
			entry.Address = base58Encode(masterPub)
			entry.AddressLabel = "Solana address"
		},
	},
}

// DeriveChildren returns the master entry followed by every child key, per protocol.
func DeriveChildren(b *HDBundle, masters []*CombinedKey) ([]ChildKey, error) {
	var out []ChildKey
	for _, m := range masters {
		scheme, ok := childSchemes[m.Protocol]
		if !ok {
			return nil, fmt.Errorf("unsupported protocol %q for child derivation", m.Protocol)
		}
		keys, err := deriveChildren(b, m, scheme)
		if err != nil {
			return nil, err
		}
		out = append(out, keys...)
	}
	return out, nil
}

func deriveChildren(b *HDBundle, master *CombinedKey, scheme childScheme) ([]ChildKey, error) {
	order := scheme.curve.Params().N
	masterPub, err := scheme.masterPublic(b, master)
	if err != nil {
		return nil, err
	}
	masterPriv, err := scalarFromHex(master.PrivateKeyHex)
	if err != nil {
		return nil, err
	}

	keys := make([]ChildKey, 0, len(b.Children)+1)
	entry := masterEntry(b, master)
	if scheme.decorate != nil {
		scheme.decorate(&entry, masterPub)
	}
	keys = append(keys, entry)
	for _, child := range b.Children {
		derivedPub, delta, err := scheme.derive(masterPub, b.ChainCode, child.DerivationPath)
		if err != nil {
			return nil, fmt.Errorf("derive %s: %w", child.WalletID, err)
		}
		priv := new(big.Int).Add(masterPriv, new(big.Int).SetBytes(delta))
		priv.Mod(priv, order)

		point := crypto.ScalarBaseMult(scheme.curve, priv)
		if !bytes.Equal(scheme.serialize(point), derivedPub) {
			return nil, fmt.Errorf("child %s: derived key does not match expected public key", child.WalletID)
		}
		keys = append(keys, ChildKey{
			WalletID:       child.WalletID,
			Name:           child.Name,
			DerivationPath: child.DerivationPath,
			Protocol:       master.Protocol,
			PrivateKeyHex:  hex.EncodeToString(priv.FillBytes(make([]byte, 32))),
			PublicKeyHex:   hex.EncodeToString(derivedPub),
			Address:        scheme.address(derivedPub, point),
			AddressLabel:   scheme.label,
			Note:           scheme.note,
		})
		priv.SetInt64(0)
	}
	return keys, nil
}

func masterEntry(b *HDBundle, master *CombinedKey) ChildKey {
	return ChildKey{
		WalletID:       b.MasterWalletID,
		Name:           "master",
		DerivationPath: []uint32{},
		Protocol:       master.Protocol,
		PrivateKeyHex:  master.PrivateKeyHex,
		PublicKeyHex:   master.PublicKeyHex,
		Address:        master.Address,
		AddressLabel:   master.AddressLabel,
		Note:           master.Note,
	}
}

func scalarFromHex(h string) (*big.Int, error) {
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) == 0 {
		return nil, errors.New("invalid master private key")
	}
	return new(big.Int).SetBytes(raw), nil
}
