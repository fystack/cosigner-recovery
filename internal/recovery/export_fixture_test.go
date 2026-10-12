package recovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, dir, name string) []byte {
	t.Helper()
	return read(t, filepath.Join(dir, name))
}

func expectedChildren(t *testing.T, dir, name string) []ChildKey {
	t.Helper()
	var keys []ChildKey
	if err := json.Unmarshal(fixture(t, dir, name), &keys); err != nil {
		t.Fatal(err)
	}
	return keys
}

func findChild(keys []ChildKey, walletID, protocol string) (ChildKey, bool) {
	for _, k := range keys {
		if k.WalletID == walletID && k.Protocol == protocol {
			return k, true
		}
	}
	return ChildKey{}, false
}

func addAndUnlockRSA(t *testing.T, s *Session, dir, file string) ShareInfo {
	t.Helper()
	info, err := s.AddShare(fixture(t, dir, file))
	if err != nil {
		t.Fatalf("add %s: %v", file, err)
	}
	if info, err = s.UnlockShare(info.ID, string(fixture(t, exportDir, "test_priv.pem"))); err != nil {
		t.Fatalf("unlock %s: %v", file, err)
	}
	return info
}

func exportSetSession(t *testing.T) *Session {
	t.Helper()
	s := NewSession()
	addAndUnlockRSA(t, s, exportDir, "share-cosigner.enc")
	addAndUnlockRSA(t, s, exportDir, "share-hd1.enc")
	return s
}

func TestExportSetRecoversFystackMasterKeys(t *testing.T) {
	s := exportSetSession(t)
	if st := s.Status(); st.PartyCounts[ProtocolECDSA] < 2 || st.PartyCounts[ProtocolEdDSA] < 2 {
		t.Fatalf("want party counts from share data, got %+v", st.PartyCounts)
	}
	keys, err := s.Recover()
	if err != nil {
		t.Fatal(err)
	}
	want := expectedChildren(t, exportDir, "child-keys.json")
	if len(keys) != 2 {
		t.Fatalf("want ECDSA and EdDSA keys, got %d", len(keys))
	}
	for _, k := range keys {
		expected, ok := findChild(want, fx.export.id, k.Protocol)
		if !ok {
			t.Fatalf("no expected %s master", k.Protocol)
		}
		if !k.Verified || !k.TestSigned {
			t.Errorf("%s: not verified/test-signed", k.Protocol)
		}
		if k.PrivateKeyHex != expected.PrivateKeyHex || k.Address != expected.Address {
			t.Errorf("%s master differs from the reference: got %s", k.Protocol, k.Address)
		}
	}
}

func TestExportSetDerivesFystackChildKeys(t *testing.T) {
	s := exportSetSession(t)
	if _, err := s.Recover(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddHDFile(fixture(t, exportDir, "hd-paths-hd1.enc"), "hd-paths-hd1.enc"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UnlockHD(fixture(t, exportDir, "test_priv.pem")); err != nil {
		t.Fatal(err)
	}
	got, err := s.DeriveChildKeys()
	if err != nil {
		t.Fatal(err)
	}

	want := expectedChildren(t, exportDir, "child-keys.json")
	if len(got) != len(want) {
		t.Fatalf("want %d keys, got %d", len(want), len(got))
	}
	for _, g := range got {
		w, ok := findChild(want, g.WalletID, g.Protocol)
		if !ok {
			t.Fatalf("unexpected key %s %s", g.Name, g.Protocol)
		}
		if g.Name != w.Name || g.PrivateKeyHex != w.PrivateKeyHex || g.Address != w.Address ||
			len(g.DerivationPath) != len(w.DerivationPath) {
			t.Errorf("%s %s differs from the reference: got %s want %s", g.Name, g.Protocol, g.Address, w.Address)
		}
	}
}

func TestExportSetKeystoresMatchFystackAddresses(t *testing.T) {
	s := exportSetSession(t)
	if _, err := s.Recover(); err != nil {
		t.Fatal(err)
	}
	s.AddHDFile(fixture(t, exportDir, "hd-paths-hd1.enc"), "hd")
	if _, err := s.UnlockHD(fixture(t, exportDir, "test_priv.pem")); err != nil {
		t.Fatal(err)
	}
	children, err := s.DeriveChildKeys()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	n, err := WriteKeystores(dir, "test-password-123", children)
	if err != nil || n != 3 {
		t.Fatalf("want 3 keystores, got %d (%v)", n, err)
	}
	written := keystoreAddresses(t, dir)
	expected := keystoreAddresses(t, filepath.Join(fixtureDir, exportDir))
	if len(expected) != 3 {
		t.Fatalf("fixture should hold 3 keystores, got %d", len(expected))
	}
	for addr := range expected {
		if !written[addr] {
			t.Errorf("no keystore written for Fystack address %s", addr)
		}
	}
}

func keystoreAddresses(t *testing.T, dir string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "keystore-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var ks struct {
			Address string `json:"address"`
		}
		if err := json.Unmarshal(raw, &ks); err != nil || ks.Address == "" {
			t.Fatalf("%s: bad keystore", f)
		}
		out[strings.ToLower(ks.Address)] = true
	}
	return out
}

func TestSingleShareCannotRecover(t *testing.T) {
	s := NewSession()
	info := addAndUnlockRSA(t, s, ws2Dir, "share-cosigner.enc")
	if info.WalletID != fx.ws2.id || info.ParticipantID != ws2Participant {
		t.Fatalf("unexpected share info %+v", info)
	}
	if st := s.Status(); st.UnlockedCounts[ProtocolECDSA] != 1 || st.UnlockedCounts[ProtocolEdDSA] != 1 {
		t.Fatalf("want 1 share per protocol, got %+v", st.UnlockedCounts)
	}
	if _, err := s.Recover(); err == nil || !strings.Contains(err.Error(), "at least 2") {
		t.Fatalf("want a need-2-shares error, got %v", err)
	}
}

func TestSharesFromDifferentWalletsAreRejected(t *testing.T) {
	s := NewSession()
	addAndUnlockRSA(t, s, ws2Dir, "share-cosigner.enc")
	addAndUnlockRSA(t, s, exportDir, "share-cosigner.enc")
	if !s.Status().WalletMismatch {
		t.Fatal("expected WalletMismatch")
	}
	if _, err := s.Recover(); err == nil || !strings.Contains(err.Error(), "different wallets") {
		t.Fatalf("want a different-wallets error, got %v", err)
	}
}

func TestSameShareCannotBeAddedTwice(t *testing.T) {
	s := NewSession()
	raw := fixture(t, exportDir, "share-cosigner.enc")
	if _, err := s.AddShare(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddShare(raw); err == nil {
		t.Fatal("expected a duplicate-share error")
	}
}

func TestChildListFromAnotherWalletIsRejected(t *testing.T) {
	s := exportSetSession(t)
	if _, err := s.Recover(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddHDFile(read(t, hdBundleFixture), hdBundleFixture); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UnlockHD(read(t, "recipient_priv.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeriveChildKeys(); err == nil || !strings.Contains(err.Error(), "different master wallet") {
		t.Fatalf("want a different-master-wallet error, got %v", err)
	}
}

func TestChildListNeedsItsOwnRSAKey(t *testing.T) {
	s := NewSession()
	if _, err := s.AddHDFile(fixture(t, exportDir, "hd-paths-hd1.enc"), "hd-paths-hd1.enc"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UnlockHD(read(t, "recipient_priv.pem")); err == nil {
		t.Fatal("expected failure with an unrelated RSA key")
	}
	if info := s.HDInfo(); info.Loaded || !info.Pending {
		t.Fatalf("bundle should stay pending, got %+v", info)
	}
}

func TestWallet2ChildKeysFileIsSweepable(t *testing.T) {
	keys, err := ReadChildKeys(filepath.Join(fixtureDir, ws2Dir, "child-keys-hd.json"))
	if err != nil {
		t.Fatal(err)
	}
	var solana []ChildKey
	for _, k := range keys {
		if k.Protocol == ProtocolEdDSA && k.PrivateKeyHex != "" && k.Address != "" {
			solana = append(solana, k)
		}
	}
	if len(solana) != 2 || solana[0].Name != "master" || solana[1].Name != "bbil" {
		t.Fatalf("want master and bbil Solana keys, got %+v", solana)
	}
}
