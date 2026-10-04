package recovery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

const (
	keystoreScryptN = 262144
	keystoreScryptR = 8
	keystoreScryptP = 1
)

type keystoreCipherParams struct {
	IV string `json:"iv"`
}

type keystoreKDFParams struct {
	DKLen int    `json:"dklen"`
	N     int    `json:"n"`
	P     int    `json:"p"`
	R     int    `json:"r"`
	Salt  string `json:"salt"`
}

type keystoreCrypto struct {
	Cipher       string               `json:"cipher"`
	CipherText   string               `json:"ciphertext"`
	CipherParams keystoreCipherParams `json:"cipherparams"`
	KDF          string               `json:"kdf"`
	KDFParams    keystoreKDFParams    `json:"kdfparams"`
	MAC          string               `json:"mac"`
}

type keystoreV3 struct {
	Address string         `json:"address"`
	Crypto  keystoreCrypto `json:"crypto"`
	ID      string         `json:"id"`
	Version int            `json:"version"`
}

// BuildKeystoreV3 encrypts a secp256k1 private key as a Web3 Secret Storage v3 file
// (importable into MetaMask and other EVM wallets).
func BuildKeystoreV3(privateKeyHex, address, password string) ([]byte, error) {
	priv, err := hex.DecodeString(privateKeyHex)
	if err != nil || len(priv) != 32 {
		return nil, errors.New("private key must be 32 bytes of hex")
	}
	if password == "" {
		return nil, errors.New("password is required")
	}
	salt := make([]byte, 32)
	iv := make([]byte, 16)
	id := make([]byte, 16)
	for _, b := range [][]byte{salt, iv, id} {
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
	}
	derived, err := scrypt.Key([]byte(password), salt, keystoreScryptN, keystoreScryptR, keystoreScryptP, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived[:16])
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(priv))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, priv)

	mac := sha3.NewLegacyKeccak256()
	mac.Write(derived[16:32])
	mac.Write(ciphertext)

	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])

	return json.MarshalIndent(keystoreV3{
		Address: strings.ToLower(strings.TrimPrefix(address, "0x")),
		Crypto: keystoreCrypto{
			Cipher:       "aes-128-ctr",
			CipherText:   hex.EncodeToString(ciphertext),
			CipherParams: keystoreCipherParams{IV: hex.EncodeToString(iv)},
			KDF:          "scrypt",
			KDFParams: keystoreKDFParams{
				DKLen: 32, N: keystoreScryptN, P: keystoreScryptP, R: keystoreScryptR, Salt: hex.EncodeToString(salt),
			},
			MAC: hex.EncodeToString(mac.Sum(nil)),
		},
		ID:      uuid,
		Version: 3,
	}, "", "  ")
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// WriteKeystores writes one keystore file per ECDSA key into dir and returns how many were written.
func WriteKeystores(dir, password string, keys []ChildKey) (int, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	count := 0
	for _, k := range keys {
		if k.Protocol != ProtocolECDSA {
			continue
		}
		raw, err := BuildKeystoreV3(k.PrivateKeyHex, k.Address, password)
		if err != nil {
			return count, fmt.Errorf("%s: %w", k.Name, err)
		}
		name := unsafeFileChars.ReplaceAllString(k.Name, "_")
		file := fmt.Sprintf("keystore-%s-%s.json", name, strings.ToLower(strings.TrimPrefix(k.Address, "0x")))
		if err := os.WriteFile(filepath.Join(dir, file), raw, 0o600); err != nil {
			return count, err
		}
		count++
	}
	if count == 0 {
		return 0, errors.New("no ECDSA keys to export")
	}
	return count, nil
}
