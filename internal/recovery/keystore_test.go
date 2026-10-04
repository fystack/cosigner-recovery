package recovery

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

const (
	testKeystorePriv = "afc4a81cafff0293e42da40e55d32830b738eb2fbec289b8ae503b1a2dadb700"
	testKeystoreAddr = "0x7A61e7bF55589667f573516d6e4eF6D4C9F6FD9a"
)

func TestKeystoreV3RoundTrip(t *testing.T) {
	raw, err := BuildKeystoreV3(testKeystorePriv, testKeystoreAddr, "pw-123")
	if err != nil {
		t.Fatal(err)
	}
	var ks keystoreV3
	if err := json.Unmarshal(raw, &ks); err != nil {
		t.Fatal(err)
	}
	if ks.Version != 3 || ks.Address != strings.ToLower(strings.TrimPrefix(testKeystoreAddr, "0x")) {
		t.Fatalf("unexpected header: %+v", ks)
	}
	salt, _ := hex.DecodeString(ks.Crypto.KDFParams.Salt)
	iv, _ := hex.DecodeString(ks.Crypto.CipherParams.IV)
	ciphertext, _ := hex.DecodeString(ks.Crypto.CipherText)

	derived, err := scrypt.Key([]byte("pw-123"), salt, ks.Crypto.KDFParams.N, ks.Crypto.KDFParams.R, ks.Crypto.KDFParams.P, 32)
	if err != nil {
		t.Fatal(err)
	}
	mac := sha3.NewLegacyKeccak256()
	mac.Write(derived[16:32])
	mac.Write(ciphertext)
	if hex.EncodeToString(mac.Sum(nil)) != ks.Crypto.MAC {
		t.Fatal("MAC mismatch")
	}
	block, _ := aes.NewCipher(derived[:16])
	plain := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(plain, ciphertext)
	if hex.EncodeToString(plain) != testKeystorePriv {
		t.Fatal("decrypted key mismatch")
	}
}

func TestWriteKeystoresSkipsEdDSA(t *testing.T) {
	dir := t.TempDir()
	keys := []ChildKey{
		{Name: "child 1", Protocol: ProtocolECDSA, PrivateKeyHex: testKeystorePriv, Address: testKeystoreAddr},
		{Name: "child 1", Protocol: ProtocolEdDSA, PrivateKeyHex: testKeystorePriv, Address: "sol"},
	}
	n, err := WriteKeystores(dir, "pw", keys)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "keystore-child_1-*.json"))
	if len(files) != 1 {
		t.Fatalf("files=%v", files)
	}
	if info, _ := os.Stat(files[0]); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v", info.Mode())
	}
}
