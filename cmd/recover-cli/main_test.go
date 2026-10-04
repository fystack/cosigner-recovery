package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/bnb-chain/tss-lib/v3/crypto"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"

	"recovery/internal/recovery"
)

func TestSignBatchFromChildrenFile(t *testing.T) {
	curve := tss.Edwards()
	var children []recovery.ChildKey
	for _, id := range []string{"w1", "w2"} {
		scalar := make([]byte, 32)
		rand.Read(scalar)
		scalar[0] &= 0x0f
		point := crypto.ScalarBaseMult(curve, new(big.Int).SetBytes(scalar))
		pub := edwards.NewPublicKey(point.X(), point.Y()).Serialize()
		children = append(children, recovery.ChildKey{
			WalletID: id, Protocol: recovery.ProtocolEdDSA,
			PrivateKeyHex: hex.EncodeToString(scalar), PublicKeyHex: hex.EncodeToString(pub),
			Address: recovery.Base58Encode(pub),
		})
	}

	dir := t.TempDir()
	msg := []byte("tx message")
	batch, _ := json.Marshal([]signRequest{
		{WalletID: "w1", MessageHex: hex.EncodeToString(msg)},
		{Address: children[1].Address, MessageHex: hex.EncodeToString(msg)},
	})
	batchPath := filepath.Join(dir, "batch.json")
	outPath := filepath.Join(dir, "sigs.json")
	os.WriteFile(batchPath, batch, 0o600)

	if err := signBatch(options{signBatch: batchPath, signOut: outPath}, children); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(outPath)
	var results []signResult
	if err := json.Unmarshal(raw, &results); err != nil || len(results) != 2 {
		t.Fatalf("results: %v %d", err, len(results))
	}
	for i, r := range results {
		pub, _ := hex.DecodeString(children[i].PublicKeyHex)
		sig, _ := hex.DecodeString(r.SignatureHex)
		if !ed25519.Verify(pub, msg, sig) {
			t.Fatalf("signature %d does not verify", i)
		}
	}
}
