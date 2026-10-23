package ckd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	tssckd "github.com/bnb-chain/tss-lib/v3/crypto/ckd"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

const hardenedKeyStart = uint32(0x80000000)

type Result struct {
	PublicKey []byte
	Delta     []byte
}

func DeriveSecp256k1(masterPublicKey []byte, chainCodeHex string, path []uint32) (*Result, error) {
	chainCode, err := validate(chainCodeHex, path)
	if err != nil {
		return nil, err
	}
	master, err := btcec.ParsePubKey(masterPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ckd: decode master public key: %w", err)
	}
	curve := btcec.S256()
	parent := extendedKey(curve, master.X(), master.Y(), chainCode)
	delta, child, err := tssckd.DeriveChildKeyFromHierarchy(path, parent, curve.Params().N, curve)
	if err != nil {
		return nil, fmt.Errorf("ckd: derive child: %w", err)
	}
	var childX, childY btcec.FieldVal
	if childX.SetByteSlice(child.PublicKey.X.Bytes()) || childY.SetByteSlice(child.PublicKey.Y.Bytes()) {
		return nil, errors.New("ckd: child public key coordinate overflow")
	}
	return &Result{PublicKey: btcec.NewPublicKey(&childX, &childY).SerializeCompressed(), Delta: delta.Bytes()}, nil
}

func DeriveEd25519(masterPublicKey []byte, chainCodeHex string, path []uint32) (*Result, error) {
	chainCode, err := validate(chainCodeHex, path)
	if err != nil {
		return nil, err
	}
	master, err := edwards.ParsePubKey(masterPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ckd: decode master public key: %w", err)
	}
	curve := tss.Edwards()
	parent := extendedKey(curve, master.X, master.Y, chainCode)
	delta, child, err := tssckd.DeriveChildKeyFromHierarchy(path, parent, curve.Params().N, curve)
	if err != nil {
		return nil, fmt.Errorf("ckd: derive child: %w", err)
	}
	return &Result{PublicKey: edwards.NewPublicKey(child.PublicKey.X, child.PublicKey.Y).Serialize(), Delta: delta.Bytes()}, nil
}

func validate(chainCodeHex string, path []uint32) ([]byte, error) {
	if len(path) == 0 {
		return nil, errors.New("ckd: derivation path is empty")
	}
	for _, index := range path {
		if index >= hardenedKeyStart {
			return nil, fmt.Errorf("ckd: hardened derivation is unsupported: %d", index)
		}
	}
	chainCode, err := hex.DecodeString(chainCodeHex)
	if err != nil {
		return nil, fmt.Errorf("ckd: decode chain code: %w", err)
	}
	if len(chainCode) != 32 {
		return nil, fmt.Errorf("ckd: invalid chain code length: %d", len(chainCode))
	}
	return chainCode, nil
}

func extendedKey(curve elliptic.Curve, x, y *big.Int, chainCode []byte) *tssckd.ExtendedKey {
	return &tssckd.ExtendedKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		ChainCode: append([]byte(nil), chainCode...),
		ParentFP:  []byte{0, 0, 0, 0},
		Version:   chaincfg.MainNetParams.HDPrivateKeyID[:],
	}
}
