package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// Format is also the RSA-OAEP label; it must match the exporter byte for byte.
const Format = "mpcium-export-v1"

const minRSABits = 2048

type Envelope struct {
	Format     string `json:"format"`
	KEM        string `json:"kem"`
	Cipher     string `json:"cipher"`
	EncKey     string `json:"enc_key"`
	Nonce      string `json:"nonce"`
	AAD        string `json:"aad"`
	Ciphertext string `json:"ciphertext"`
}

func Open(data []byte, priv *rsa.PrivateKey) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	if env.Format != Format {
		return nil, fmt.Errorf("unexpected envelope format %q", env.Format)
	}
	encKey, err := base64.StdEncoding.DecodeString(env.EncKey)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, []byte(Format))
	if err != nil {
		return nil, err
	}
	defer zero(aesKey)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, []byte(env.AAD))
}

// Build is only used to produce fixtures in tests.
func Build(blob, recipientPubKeyPEM []byte, aad string) ([]byte, error) {
	pub, err := parseRSAPublicKeyPEM(recipientPubKeyPEM)
	if err != nil {
		return nil, err
	}
	if pub.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("recipient RSA key too small: %d bits (min %d)", pub.N.BitLen(), minRSABits)
	}
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}
	defer zero(aesKey)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, blob, []byte(aad))
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, []byte(Format))
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{
		Format:     Format,
		KEM:        "RSA-OAEP-SHA256",
		Cipher:     "AES-256-GCM",
		EncKey:     base64.StdEncoding.EncodeToString(encKey),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		AAD:        aad,
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
}

func parseRSAPublicKeyPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("recipient public key is not valid PEM")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("recipient public key is not RSA")
	}
	if rsaKey, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return rsaKey, nil
	}
	return nil, fmt.Errorf("failed to parse recipient RSA public key (expected PKIX or PKCS1 PEM)")
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
