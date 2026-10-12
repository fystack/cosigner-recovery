package recovery

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/bnb-chain/tss-lib/v3/crypto"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

func recoveredFixtureSession(t *testing.T) (*Session, []*CombinedKey) {
	t.Helper()
	s := NewSession()
	rsaInfo, err := s.AddShare(read(t, "rsa-bundle.enc"))
	if err != nil {
		t.Fatal(err)
	}
	msInfo, err := s.AddShare(read(t, "cos11.mshare"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UnlockShare(rsaInfo.ID, string(read(t, "recipient_priv.pem"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UnlockShare(msInfo.ID, testPassphrase); err != nil {
		t.Fatal(err)
	}
	keys, err := s.Recover()
	if err != nil {
		t.Fatal(err)
	}
	return s, keys
}

func keyFor(t *testing.T, keys []*CombinedKey, proto string) *CombinedKey {
	t.Helper()
	for _, k := range keys {
		if k.Protocol == proto {
			return k
		}
	}
	t.Fatalf("no %s key recovered", proto)
	return nil
}

func edwardsPublicKeyHex(t *testing.T, k *CombinedKey) string {
	t.Helper()
	d, err := scalarFromHex(k.PrivateKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	p := crypto.ScalarBaseMult(tss.Edwards(), d)
	return hex.EncodeToString(edwards.NewPublicKey(p.X(), p.Y()).Serialize())
}

func TestSessionDerivesChildKeysFromFixture(t *testing.T) {
	s, _ := recoveredFixtureSession(t)

	info, err := s.AddHDFile(read(t, hdBundleFixture), hdBundleFixture)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Pending || info.Loaded {
		t.Fatalf("expected pending bundle, got %+v", info)
	}
	if info, err = s.UnlockHD(read(t, "recipient_priv.pem")); err != nil {
		t.Fatal(err)
	}
	if !info.Loaded || info.ChildCount != len(fixtureChildren) {
		t.Fatalf("unexpected HD info %+v", info)
	}

	got, err := s.DeriveChildKeys()
	if err != nil {
		t.Fatal(err)
	}
	var want []ChildKey
	if err := json.Unmarshal(read(t, hdGoldenFixture), &want); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("want %d keys, got %d", len(want), len(got))
	}
	for _, g := range got {
		w, ok := findChild(want, g.WalletID, g.Protocol)
		if !ok {
			t.Fatalf("unexpected key %s %s", g.Name, g.Protocol)
		}
		if g.Name != w.Name || g.PrivateKeyHex != w.PrivateKeyHex || g.PublicKeyHex != w.PublicKeyHex || g.Address != w.Address {
			t.Errorf("%s %s differs from the reference: got %s want %s", g.Name, g.Protocol, g.Address, w.Address)
		}
	}
}
