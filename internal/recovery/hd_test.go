package recovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bnb-chain/tss-lib/v3/crypto"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

func randomEdMaster(t *testing.T) (*big.Int, []byte) {
	t.Helper()
	curve := tss.Edwards()
	d, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil || d.Sign() == 0 {
		t.Fatal("scalar")
	}
	p := crypto.ScalarBaseMult(curve, d)
	return d, edwards.NewPublicKey(p.X(), p.Y()).Serialize()
}

func TestEdDSAChildKeysSignStandardSignatures(t *testing.T) {
	masterPriv, masterPub := randomEdMaster(t)
	chain := make([]byte, 32)
	rand.Read(chain)
	bundle := &HDBundle{
		ChainCode:            hex.EncodeToString(chain),
		MasterPublicKeyEDDSA: hex.EncodeToString(masterPub),
		Children: []HDChild{
			{WalletID: "w0", DerivationPath: []uint32{0}},
			{WalletID: "w1", DerivationPath: []uint32{1}},
			{WalletID: "w9", DerivationPath: []uint32{9}},
		},
	}
	master := &CombinedKey{Protocol: ProtocolEdDSA, PrivateKeyHex: hex.EncodeToString(masterPriv.FillBytes(make([]byte, 32)))}

	children, err := DeriveChildren(bundle, []*CombinedKey{master})
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 4 || children[0].Name != "master" {
		t.Fatalf("want master + 3 children, got %d", len(children))
	}
	msg := []byte("solana transaction message")
	for _, c := range children {
		sig, err := SignEdDSA(c.PrivateKeyHex, msg)
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := hex.DecodeString(c.PublicKeyHex)
		if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			t.Fatalf("child %s: signature does not verify with std ed25519", c.WalletID)
		}
	}
}

func TestChildKeysFileRoundTrip(t *testing.T) {
	keys := []ChildKey{{WalletID: "w1", Name: "a", DerivationPath: []uint32{1}, Protocol: ProtocolEdDSA, PrivateKeyHex: "aa", Address: "addr"}}
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := WriteChildKeys(path, keys); err != nil {
		t.Fatal(err)
	}
	got, err := ReadChildKeys(path)
	if err != nil || len(got) != 1 || got[0].WalletID != "w1" || got[0].PrivateKeyHex != "aa" {
		t.Fatalf("round trip failed: %v %+v", err, got)
	}
}

func TestECDSAChildKeysMatchDerivedPublicKeys(t *testing.T) {
	_, keys := recoveredFixtureSession(t)
	master := keyFor(t, keys, ProtocolECDSA)
	bundle := &HDBundle{ChainCode: hex.EncodeToString(make([]byte, 32)), Children: fixtureChildren}

	children, err := DeriveChildren(bundle, []*CombinedKey{master})
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != len(fixtureChildren)+1 || children[0].Name != "master" {
		t.Fatalf("want master + %d children, got %d", len(fixtureChildren), len(children))
	}
	seen := map[string]bool{}
	for _, c := range children {
		if c.Protocol != ProtocolECDSA || len(c.PrivateKeyHex) != 64 || !strings.HasPrefix(c.Address, "0x") {
			t.Fatalf("malformed child %+v", c)
		}
		if seen[c.Address] {
			t.Fatalf("duplicate address %s", c.Address)
		}
		seen[c.Address] = true
	}
}

func TestDeriveChildrenRejectsWrongMasterKey(t *testing.T) {
	_, keys := recoveredFixtureSession(t)
	for _, proto := range []string{ProtocolECDSA, ProtocolEdDSA} {
		master := *keyFor(t, keys, proto)
		master.PrivateKeyHex = hex.EncodeToString(make([]byte, 31)) + "01"
		bundle := &HDBundle{
			ChainCode:            hex.EncodeToString(make([]byte, 32)),
			MasterPublicKeyEDDSA: edwardsPublicKeyHex(t, keyFor(t, keys, ProtocolEdDSA)),
			Children:             fixtureChildren,
		}
		if _, err := DeriveChildren(bundle, []*CombinedKey{&master}); err == nil {
			t.Fatalf("%s: expected mismatch error for a wrong master key", proto)
		}
	}
}

func TestEdDSAChildrenNeedMasterPublicKey(t *testing.T) {
	_, keys := recoveredFixtureSession(t)
	bundle := &HDBundle{ChainCode: hex.EncodeToString(make([]byte, 32)), Children: fixtureChildren}
	if _, err := DeriveChildren(bundle, []*CombinedKey{keyFor(t, keys, ProtocolEdDSA)}); err == nil {
		t.Fatal("expected error when the bundle has no EdDSA master public key")
	}
}

func TestOpenHDBundle(t *testing.T) {
	raw := read(t, hdBundleFixture)
	if !LooksLikeHDBundle(raw) || LooksLikeHDBundle(read(t, "rsa-bundle.enc")) {
		t.Fatal("LooksLikeHDBundle misclassified the fixtures")
	}

	b, err := OpenHDBundle(raw, read(t, "recipient_priv.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Format != hdRecoveryFormat || len(b.Children) != len(fixtureChildren) || b.Children[2].Name != "treasury" {
		t.Fatalf("unexpected bundle %+v", b)
	}

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)})
	if _, err := OpenHDBundle(raw, otherPEM); err == nil {
		t.Fatal("expected failure with the wrong RSA key")
	}
	if _, err := OpenHDBundle(read(t, "rsa-bundle.enc"), read(t, "recipient_priv.pem")); err == nil {
		t.Fatal("expected failure for a non-HD file")
	}
}

func TestSessionHDGuards(t *testing.T) {
	s := NewSession()
	if _, err := s.AddHDFile(read(t, "rsa-bundle.enc"), "x.enc"); err == nil {
		t.Fatal("expected AddHDFile to reject a non-HD file")
	}
	if _, err := s.UnlockHD(read(t, "recipient_priv.pem")); err == nil {
		t.Fatal("expected UnlockHD to need a file first")
	}
	if _, err := s.DeriveChildKeys(); err == nil {
		t.Fatal("expected DeriveChildKeys to need an unlocked bundle")
	}

	if _, err := s.AddHDFile(read(t, hdBundleFixture), hdBundleFixture); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UnlockHD(read(t, "recipient_priv.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeriveChildKeys(); err == nil {
		t.Fatal("expected DeriveChildKeys to need recovered master keys")
	}

	s.RemoveHD()
	if info := s.HDInfo(); info.Loaded || info.Pending || info.FileName != "" {
		t.Fatalf("RemoveHD left state behind: %+v", info)
	}
}

func TestDeriveChildrenRejectsUnknownProtocol(t *testing.T) {
	bundle := &HDBundle{ChainCode: hex.EncodeToString(make([]byte, 32)), Children: fixtureChildren}
	if _, err := DeriveChildren(bundle, []*CombinedKey{{Protocol: "SCHNORR"}}); err == nil {
		t.Fatal("expected an error for an unsupported protocol")
	}
}
