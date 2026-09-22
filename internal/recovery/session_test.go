package recovery

import (
	"os"
	"path/filepath"
	"testing"
)

const testPassphrase = "wait-industry-bring-nasty-wonder-cousin"

func read(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

func TestRecoverFromMixedFormats(t *testing.T) {
	s := NewSession()

	rsaBundleRaw := read(t, "rsa-bundle.enc")
	rsaInfo, err := s.AddShare(rsaBundleRaw)
	if err != nil {
		t.Fatalf("add rsa bundle: %v", err)
	}
	if rsaInfo.Format != FormatRSABundle || !rsaInfo.NeedsRSAKey {
		t.Fatalf("expected rsa bundle, got %+v", rsaInfo)
	}

	msRaw := read(t, "cos11.mshare")
	msInfo, err := s.AddShare(msRaw)
	if err != nil {
		t.Fatalf("add mshare: %v", err)
	}
	if msInfo.Format != FormatMShare || !msInfo.NeedsPass {
		t.Fatalf("expected mshare, got %+v", msInfo)
	}

	rsaKey := string(read(t, "recipient_priv.pem"))
	if _, err := s.UnlockShare(rsaInfo.ID, rsaKey); err != nil {
		t.Fatalf("unlock rsa: %v", err)
	}
	if _, err := s.UnlockShare(msInfo.ID, testPassphrase); err != nil {
		t.Fatalf("unlock mshare: %v", err)
	}

	st := s.Status()
	if st.WalletMismatch {
		t.Fatal("unexpected wallet mismatch")
	}
	if st.UnlockedCounts[ProtocolECDSA] != 2 || st.UnlockedCounts[ProtocolEdDSA] != 2 {
		t.Fatalf("expected 2 shares per protocol, got %+v", st.UnlockedCounts)
	}

	keys, err := s.Recover()
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	for _, k := range keys {
		if !k.Verified || !k.TestSigned {
			t.Fatalf("%s not verified/signed: %+v", k.Protocol, k)
		}
		if len(k.PrivateKeyHex) != 64 {
			t.Fatalf("%s bad private key hex length %d", k.Protocol, len(k.PrivateKeyHex))
		}
		if k.Address == "" {
			t.Fatalf("%s missing address", k.Protocol)
		}
		if k.Protocol == ProtocolECDSA && k.Address != "0x902821DDBe31FC933e713d766D3B953d37635644" {
			t.Fatalf("ECDSA address mismatch: %s", k.Address)
		}
	}
}

func TestUnlockWrongPassphrase(t *testing.T) {
	s := NewSession()
	info, err := s.AddShare(read(t, "cos11.mshare"))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := s.UnlockShare(info.ID, "wrong-wrong-wrong-passphrase"); err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestUnlockWrongRSAKey(t *testing.T) {
	s := NewSession()
	info, err := s.AddShare(read(t, "rsa-bundle.enc"))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := s.UnlockShare(info.ID, "-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----"); err == nil {
		t.Fatal("expected error for invalid RSA key")
	}
}
