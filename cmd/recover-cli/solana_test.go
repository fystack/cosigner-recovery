package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/bnb-chain/tss-lib/v3/crypto"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"

	"recovery/internal/recovery"
	"recovery/internal/solana"
)

func solanaTestKey(id string) recovery.ChildKey {
	scalar := make([]byte, 32)
	rand.Read(scalar)
	scalar[0] &= 0x0f
	p := crypto.ScalarBaseMult(tss.Edwards(), new(big.Int).SetBytes(scalar))
	pub := edwards.NewPublicKey(p.X(), p.Y()).Serialize()
	return recovery.ChildKey{
		WalletID: id, Protocol: recovery.ProtocolEdDSA,
		PrivateKeyHex: hex.EncodeToString(scalar), PublicKeyHex: hex.EncodeToString(pub), Address: recovery.Base58Encode(pub),
	}
}

func TestSolanaThreeStepFlow(t *testing.T) {
	k1, k2 := solanaTestKey("w1"), solanaTestKey("w2")
	to := solanaTestKey("dest").Address
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		var result any
		switch req.Method {
		case "getBalance":
			result = map[string]any{"value": 1_000_000}
		case "getTokenAccountsByOwner":
			result = map[string]any{"value": []any{}}
		case "getLatestBlockhash":
			result = map[string]any{"value": map[string]any{"blockhash": solanaTestKey("bh").Address, "lastValidBlockHeight": 1}}
		case "sendTransaction":
			sent = append(sent, req.Params[0].(string))
			result = "sig" + string(rune('A'+len(sent)))
		case "getSignatureStatuses":
			result = map[string]any{"value": []any{map[string]any{"err": nil, "confirmationStatus": "confirmed"}}}
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
	defer srv.Close()

	dir := t.TempDir()
	keysPath := filepath.Join(dir, "keys.json")
	raw, _ := json.Marshal([]recovery.ChildKey{k1, k2})
	os.WriteFile(keysPath, raw, 0o600)
	addrsPath := filepath.Join(dir, "addrs.json")
	raw, _ = json.Marshal([]string{k1.Address, k2.Address})
	os.WriteFile(addrsPath, raw, 0o600)
	planPath := filepath.Join(dir, "plan.json")
	signedPath := filepath.Join(dir, "signed.json")

	if err := runSolana(options{solPlan: to, solAddresses: addrsPath, planOut: planPath, rpc: srv.URL}); err != nil {
		t.Fatalf("plan: %v", err)
	}
	if err := runSolana(options{solSignPlan: planPath, childrenIn: keysPath, signedOut: signedPath}); err != nil {
		t.Fatalf("sign-plan: %v", err)
	}
	if err := runSolana(options{solBroadcast: signedPath, rpc: srv.URL}); err != nil || len(sent) != 0 {
		t.Fatalf("broadcast without --send must not send: err=%v sent=%d", err, len(sent))
	}
	if err := runSolana(options{solBroadcast: signedPath, rpc: srv.URL, send: true, yes: true}); err != nil {
		t.Fatalf("broadcast: %v", err)
	}
	if len(sent) != 2 {
		t.Fatalf("sent %d txs, want 2", len(sent))
	}
	for i, b64 := range sent {
		wire, _ := base64.StdEncoding.DecodeString(b64)
		pub, _ := hex.DecodeString([]string{k1.PublicKeyHex, k2.PublicKeyHex}[i])
		if !ed25519.Verify(pub, wire[65:], wire[1:65]) {
			t.Fatalf("broadcast tx %d has an invalid signature", i)
		}
	}

	var plan solana.Plan
	planRaw, _ := os.ReadFile(planPath)
	json.Unmarshal(planRaw, &plan)
	plan.To = solanaTestKey("attacker").Address
	bad, _ := json.Marshal(plan)
	badPath := filepath.Join(dir, "bad.json")
	os.WriteFile(badPath, bad, 0o600)
	if err := runSolana(options{solSignPlan: badPath, childrenIn: keysPath, signedOut: filepath.Join(dir, "x.json")}); err == nil {
		t.Fatal("a plan whose messages do not match its destination must not be signed")
	}

	if err := runSolana(options{solSweep: to, childrenIn: keysPath, rpc: srv.URL}); err != nil || len(sent) != 2 {
		t.Fatalf("sweep dry run must not send: err=%v sent=%d", err, len(sent))
	}
}
