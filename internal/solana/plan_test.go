package solana

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/bnb-chain/tss-lib/v3/crypto"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

type testWallet struct {
	Wallet
	scalarHex string
}

func newTestWallet(t *testing.T, id string) testWallet {
	t.Helper()
	scalar := make([]byte, 32)
	rand.Read(scalar)
	scalar[0] &= 0x0f
	p := crypto.ScalarBaseMult(tss.Edwards(), new(big.Int).SetBytes(scalar))
	pub := edwards.NewPublicKey(p.X(), p.Y()).Serialize()
	var pk PublicKey
	copy(pk[:], pub)
	return testWallet{Wallet: Wallet{ID: id, Address: pk.String()}, scalarHex: hex.EncodeToString(scalar)}
}

func randomAddress() string {
	var p PublicKey
	rand.Read(p[:])
	return p.String()
}

type fakeChain struct {
	balances map[string]uint64
	tokens   map[string][]map[string]any
}

func (f *fakeChain) server(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		var result any
		switch req.Method {
		case "getBalance":
			result = map[string]any{"value": f.balances[req.Params[0].(string)]}
		case "getMinimumBalanceForRentExemption":
			result = 2039280
		case "getAccountInfo":
			result = map[string]any{"value": nil}
		case "getLatestBlockhash":
			result = map[string]any{"value": map[string]any{"blockhash": randomAddress(), "lastValidBlockHeight": 1000}}
		case "getTokenAccountsByOwner":
			program := req.Params[1].(map[string]any)["programId"].(string)
			list := []map[string]any{}
			if program == TokenProgram.String() {
				list = f.tokens[req.Params[0].(string)]
			}
			result = map[string]any{"value": list}
		default:
			t.Errorf("unexpected method %s", req.Method)
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
}

func tokenEntry(account, mint string, amount string, lamports uint64) map[string]any {
	return map[string]any{
		"pubkey": account,
		"account": map[string]any{
			"lamports": lamports,
			"data": map[string]any{"parsed": map[string]any{"info": map[string]any{
				"mint": mint, "state": "initialized",
				"tokenAmount": map[string]any{"amount": amount, "decimals": 6},
			}}},
		},
	}
}

func buildTestPlan(t *testing.T) (*Plan, []testWallet, string) {
	w1, w2 := newTestWallet(t, "w1"), newTestWallet(t, "w2")
	to := randomAddress()
	mint := randomAddress()
	chain := &fakeChain{
		balances: map[string]uint64{w1.Address: 50_000_000, w2.Address: 3_000_000},
		tokens: map[string][]map[string]any{
			w1.Address: {tokenEntry(randomAddress(), mint, "1500000", 2039280), tokenEntry(randomAddress(), randomAddress(), "0", 2039280)},
		},
	}
	srv := chain.server(t)
	t.Cleanup(srv.Close)
	plan, err := BuildPlan(context.Background(), NewClient(srv.URL), to, []Wallet{w1.Wallet, w2.Wallet})
	if err != nil {
		t.Fatal(err)
	}
	return plan, []testWallet{w1, w2}, to
}

func TestPlanValidateSignAndTamper(t *testing.T) {
	plan, wallets, to := buildTestPlan(t)
	if len(plan.Txs) != 3 {
		t.Fatalf("want 3 txs (w1 tokens, w1 SOL, w2 SOL), got %d: %+v", len(plan.Txs), plan.Txs)
	}
	if err := Validate(plan); err != nil {
		t.Fatalf("valid plan rejected: %v", err)
	}

	scalars := map[string]string{wallets[0].Address: wallets[0].scalarHex, wallets[1].Address: wallets[1].scalarHex}
	signed, err := SignPlan(plan, scalars)
	if err != nil {
		t.Fatal(err)
	}
	for i, tx := range signed.Txs {
		wire, _ := base64.StdEncoding.DecodeString(tx.Tx)
		sig, msg := wire[1:65], wire[65:]
		pub, _ := decodeBase58(tx.Signer)
		if wire[0] != 1 || !ed25519.Verify(pub, msg, sig) {
			t.Fatalf("tx %d: bad wire format or signature", i)
		}
	}

	solTx, _ := base64.StdEncoding.DecodeString(plan.Txs[1].Message)
	pm, err := ParseMessage(solTx)
	if err != nil || len(pm.Instructions) != 1 {
		t.Fatalf("SOL tx parse: %v", err)
	}
	wantLamports := uint64(50_000_000 - txFeeLamports - 2039280 + 2*2039280 - txFeeLamports)
	if got := binary.LittleEndian.Uint64(pm.Instructions[0].Data[4:]); got != wantLamports {
		t.Fatalf("w1 SOL sweep = %d, want %d", got, wantLamports)
	}
	lastTx, _ := base64.StdEncoding.DecodeString(plan.Txs[2].Message)
	pm2, _ := ParseMessage(lastTx)
	if got := binary.LittleEndian.Uint64(pm2.Instructions[0].Data[4:]); got != 3_000_000-txFeeLamports {
		t.Fatalf("w2 SOL sweep = %d", got)
	}

	tampered := *plan
	tampered.Txs = append([]PlannedTx(nil), plan.Txs...)
	tampered.To = randomAddress()
	if err := Validate(&tampered); err == nil {
		t.Fatal("plan with a different destination must be rejected")
	}

	raw, _ := base64.StdEncoding.DecodeString(plan.Txs[2].Message)
	toPK, _ := ParseAddress(to)
	evil := randomAddress()
	evilPK, _ := ParseAddress(evil)
	idx := strings.Index(string(raw), string(toPK[:]))
	if idx < 0 {
		t.Fatal("destination not found in message")
	}
	copy(raw[idx:idx+32], evilPK[:])
	bad := *plan
	bad.Txs = append([]PlannedTx(nil), plan.Txs...)
	bad.Txs[2].Message = base64.StdEncoding.EncodeToString(raw)
	if err := Validate(&bad); err == nil {
		t.Fatal("message redirected to another address must be rejected")
	}

	if path := os.Getenv("DUMP_PLAN"); path != "" {
		data, _ := json.Marshal(map[string]any{"plan": plan, "wallets": []string{wallets[0].Address, wallets[1].Address}})
		os.WriteFile(path, data, 0o600)
	}
}
