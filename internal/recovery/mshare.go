package recovery

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	mshareFormat        = "fystack-wallet-share-v1"
	argon2Time          = 3
	argon2MemoryKiB     = 64 * 1024
	argon2Threads       = 4
	argon2KeyLen        = 32
	mshareSaltLen       = 16
	mshareNonceLen      = 12
	mshareMinPassLen    = 12
	mshareMaxPassLen    = 128
	mshareMaxBundleSize = 10 * 1024 * 1024
)

type mshareKDFParams struct {
	Name      string `json:"name"`
	MemoryKiB uint32 `json:"memory_kib"`
	Time      uint32 `json:"time"`
	Threads   uint8  `json:"threads"`
}

type mshareContextEntry struct {
	Protocol             string `json:"protocol"`
	JointPublicKeyBase64 string `json:"joint_public_key_base64"`
}

type mshareContext struct {
	WorkspaceID   string               `json:"workspace_id"`
	WalletID      string               `json:"wallet_id"`
	ParticipantID string               `json:"participant_id"`
	DeviceID      string               `json:"device_id"`
	Shares        []mshareContextEntry `json:"shares"`
}

type mshareEnvelope struct {
	Format     string          `json:"format"`
	KDF        mshareKDFParams `json:"kdf"`
	Salt       string          `json:"salt"`
	Nonce      string          `json:"nonce"`
	Context    mshareContext   `json:"context"`
	Ciphertext string          `json:"ciphertext"`
}

// protectedHeader must serialize identically to the writer's to reproduce the AAD.
type mshareProtectedHeader struct {
	Format  string          `json:"format"`
	KDF     mshareKDFParams `json:"kdf"`
	Salt    string          `json:"salt"`
	Nonce   string          `json:"nonce"`
	Context mshareContext   `json:"context"`
}

type msharePayload struct {
	Shares []mshareShare `json:"shares"`
}

type mshareShare struct {
	WalletID             string `json:"wallet_id"`
	Protocol             string `json:"protocol"`
	JointPublicKeyBase64 string `json:"joint_public_key_base64"`
	ShareBlobBase64      string `json:"share_blob_base64"`
}

func looksLikeMShare(raw []byte) bool {
	var probe struct {
		Format string `json:"format"`
	}
	return json.Unmarshal(raw, &probe) == nil && probe.Format == mshareFormat
}

// openMShare decrypts a passphrase-protected wallet recovery share bundle.
func openMShare(bundle []byte, passphrase string) (*msharePayload, *mshareContext, error) {
	if !utf8.ValidString(passphrase) {
		return nil, nil, errors.New("passphrase must be valid UTF-8")
	}
	if n := utf8.RuneCountInString(passphrase); n < mshareMinPassLen || n > mshareMaxPassLen {
		return nil, nil, fmt.Errorf("passphrase must be %d-%d characters", mshareMinPassLen, mshareMaxPassLen)
	}
	if len(bundle) > mshareMaxBundleSize {
		return nil, nil, errors.New("bundle too large")
	}

	var env mshareEnvelope
	if err := decodeStrictJSON(bundle, &env); err != nil || env.Format != mshareFormat {
		return nil, nil, errors.New("invalid wallet recovery share envelope")
	}
	if env.KDF.Name != "argon2id" || env.KDF.MemoryKiB != argon2MemoryKiB ||
		env.KDF.Time != argon2Time || env.KDF.Threads != argon2Threads {
		return nil, nil, errors.New("unsupported Argon2id parameters")
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil || len(salt) != mshareSaltLen {
		return nil, nil, errors.New("invalid salt")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != mshareNonceLen {
		return nil, nil, errors.New("invalid nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil || len(ciphertext) < 16 {
		return nil, nil, errors.New("invalid ciphertext")
	}

	aad, err := json.Marshal(mshareProtectedHeader{
		Format: env.Format, KDF: env.KDF, Salt: env.Salt, Nonce: env.Nonce, Context: env.Context,
	})
	if err != nil {
		return nil, nil, err
	}
	key := argon2.IDKey([]byte(passphrase), salt, env.KDF.Time, env.KDF.MemoryKiB, env.KDF.Threads, argon2KeyLen)
	defer wipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, nil, errors.New("wrong passphrase or corrupted bundle")
	}
	defer wipe(plain)

	var payload msharePayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, nil, errors.New("invalid decrypted payload")
	}
	ctx := env.Context
	return &payload, &ctx, nil
}

func decodeStrictJSON(data []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
