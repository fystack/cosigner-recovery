package recovery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/bnb-chain/tss-lib/v3/crypto"
	ecdsaKeygen "github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	eddsaKeygen "github.com/bnb-chain/tss-lib/v3/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"golang.org/x/crypto/argon2"
	"recovery/internal/ckd"
	"recovery/internal/envelope"
)

const (
	testPassphrase = "wait-industry-bring-nasty-wonder-cousin"
	exportDir      = "export-test"
	ws2Dir         = "ws2"
	ws2Participant = "cos-fixture-3"
)

// Fixtures are synthetic: random wallets split into Shamir shares at test start, so no real key material is checked in.
var (
	fixtureDir string
	fx         *fixtureSet
)

type fixtureSet struct {
	mixed, export, ws2 *fixtureWallet
}

type fixtureWallet struct {
	id      string
	secrets map[string]*big.Int
	coefs   map[string]*big.Int
	parties int
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "recovery-fixtures-")
	if err != nil {
		panic(err)
	}
	fixtureDir = dir
	generateFixtures()
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func curveFor(proto string) elliptic.Curve {
	if proto == ProtocolEdDSA {
		return tss.Edwards()
	}
	return tss.S256()
}

func randomScalar(curve elliptic.Curve) *big.Int {
	for {
		d, err := rand.Int(rand.Reader, curve.Params().N)
		check(err)
		if d.Sign() != 0 {
			return d
		}
	}
}

func newFixtureWallet(id string, parties int) *fixtureWallet {
	w := &fixtureWallet{id: id, secrets: map[string]*big.Int{}, coefs: map[string]*big.Int{}, parties: parties}
	for _, proto := range []string{ProtocolECDSA, ProtocolEdDSA} {
		w.secrets[proto] = randomScalar(curveFor(proto))
		w.coefs[proto] = randomScalar(curveFor(proto))
	}
	return w
}

func (w *fixtureWallet) pub(proto string) *crypto.ECPoint {
	return crypto.ScalarBaseMult(curveFor(proto), w.secrets[proto])
}

func (w *fixtureWallet) pubBytes(proto string) []byte {
	p := w.pub(proto)
	if proto == ProtocolEdDSA {
		return edwards.NewPublicKey(p.X(), p.Y()).Serialize()
	}
	return elliptic.MarshalCompressed(tss.S256(), p.X(), p.Y())
}

func (w *fixtureWallet) address(proto string) string {
	if proto == ProtocolEdDSA {
		return solanaAddress(w.pub(proto))
	}
	return ethereumAddress(w.pub(proto))
}

// shareBlob returns the tss-lib share JSON of the 1-based party, from a degree-1 polynomial (any 2 parties recover the key).
func (w *fixtureWallet) shareBlob(proto string, party int) []byte {
	order := curveFor(proto).Params().N
	x := big.NewInt(int64(party))
	xi := new(big.Int).Mul(w.coefs[proto], x)
	xi.Add(xi, w.secrets[proto]).Mod(xi, order)
	ks := make([]*big.Int, w.parties)
	for i := range ks {
		ks[i] = big.NewInt(int64(i + 1))
	}
	var blob []byte
	var err error
	if proto == ProtocolEdDSA {
		blob, err = json.Marshal(eddsaKeygen.LocalPartySaveData{LocalSecrets: eddsaKeygen.LocalSecrets{ShareID: x, Xi: xi}, EDDSAPub: w.pub(proto), Ks: ks})
	} else {
		blob, err = json.Marshal(ecdsaKeygen.LocalPartySaveData{LocalSecrets: ecdsaKeygen.LocalSecrets{ShareID: x, Xi: xi}, ECDSAPub: w.pub(proto), Ks: ks})
	}
	check(err)
	return blob
}

func (w *fixtureWallet) rsaBundle(party int, participant string, pubPEM []byte) []byte {
	type item struct {
		Protocol      string `json:"protocol"`
		KeyID         string `json:"key_id"`
		ParticipantID string `json:"participant_id"`
		Envelope      string `json:"envelope"`
	}
	b := struct {
		Format string `json:"format"`
		Wallet string `json:"wallet"`
		Shares []item `json:"shares"`
	}{Format: bundleFormat, Wallet: w.id}
	for _, proto := range []string{ProtocolECDSA, ProtocolEdDSA} {
		aad := fmt.Sprintf("%s|%s|%s", w.id, proto, participant)
		sealed, err := envelope.Build(w.shareBlob(proto, party), pubPEM, aad)
		check(err)
		b.Shares = append(b.Shares, item{proto, w.id, participant, string(sealed)})
	}
	raw, err := json.Marshal(b)
	check(err)
	return raw
}

func (w *fixtureWallet) mshare(party int, participant, passphrase string) []byte {
	var ctxShares []mshareContextEntry
	var payload msharePayload
	for _, proto := range []string{ProtocolECDSA, ProtocolEdDSA} {
		joint := base64.StdEncoding.EncodeToString(w.pubBytes(proto))
		ctxShares = append(ctxShares, mshareContextEntry{Protocol: proto, JointPublicKeyBase64: joint})
		payload.Shares = append(payload.Shares, mshareShare{
			WalletID:             w.id,
			Protocol:             proto,
			JointPublicKeyBase64: joint,
			ShareBlobBase64:      base64.StdEncoding.EncodeToString(w.shareBlob(proto, party)),
		})
	}
	salt := make([]byte, mshareSaltLen)
	nonce := make([]byte, mshareNonceLen)
	_, err := rand.Read(salt)
	check(err)
	_, err = rand.Read(nonce)
	check(err)
	header := mshareProtectedHeader{
		Format:  mshareFormat,
		KDF:     mshareKDFParams{Name: "argon2id", MemoryKiB: argon2MemoryKiB, Time: argon2Time, Threads: argon2Threads},
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Context: mshareContext{WorkspaceID: "ws-fixture", WalletID: w.id, ParticipantID: participant, DeviceID: "device-fixture", Shares: ctxShares},
	}
	aad, err := json.Marshal(header)
	check(err)
	plain, err := json.Marshal(payload)
	check(err)
	key := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2MemoryKiB, argon2Threads, argon2KeyLen)
	block, err := aes.NewCipher(key)
	check(err)
	gcm, err := cipher.NewGCM(block)
	check(err)
	raw, err := json.Marshal(mshareEnvelope{
		Format:     header.Format,
		KDF:        header.KDF,
		Salt:       header.Salt,
		Nonce:      header.Nonce,
		Context:    header.Context,
		Ciphertext: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, plain, aad)),
	})
	check(err)
	return raw
}

func fixtureChainCode() []byte {
	chain := make([]byte, 32)
	for i := range chain {
		chain[i] = byte(i + 1)
	}
	return chain
}

func (w *fixtureWallet) hdBundle(children []HDChild) *HDBundle {
	return &HDBundle{
		Format:               hdRecoveryFormat,
		MasterWalletID:       w.id,
		KeyID:                w.id,
		CKDVersion:           "v1",
		Threshold:            2,
		ChainCode:            hex.EncodeToString(fixtureChainCode()),
		MasterPublicKeyECDSA: hex.EncodeToString(w.pubBytes(ProtocolECDSA)),
		MasterPublicKeyEDDSA: hex.EncodeToString(w.pubBytes(ProtocolEdDSA)),
		Children:             children,
	}
}

func sealHDBundle(b *HDBundle, pubPEM []byte) []byte {
	plain, err := json.Marshal(b)
	check(err)
	sealed, err := envelope.Build(plain, pubPEM, "hd-recovery|"+b.MasterWalletID)
	check(err)
	file, err := json.MarshalIndent(hdBundleFile{Format: hdBundleFileFormat, Envelope: string(sealed)}, "", "  ")
	check(err)
	return file
}

// referenceChildren derives the expected keys straight from the known master secrets, bypassing DeriveChildren.
func (w *fixtureWallet) referenceChildren(b *HDBundle) []ChildKey {
	var out []ChildKey
	for _, proto := range []string{ProtocolECDSA, ProtocolEdDSA} {
		curve := curveFor(proto)
		order := curve.Params().N
		masterPub := w.pubBytes(proto)
		out = append(out, ChildKey{
			WalletID:       w.id,
			Name:           "master",
			DerivationPath: []uint32{},
			Protocol:       proto,
			PrivateKeyHex:  hex.EncodeToString(w.secrets[proto].FillBytes(make([]byte, 32))),
			PublicKeyHex:   hex.EncodeToString(masterPub),
			Address:        w.address(proto),
		})
		for _, child := range b.Children {
			var r *ckd.Result
			var err error
			if proto == ProtocolEdDSA {
				r, err = ckd.DeriveEd25519(masterPub, b.ChainCode, child.DerivationPath)
			} else {
				r, err = ckd.DeriveSecp256k1(masterPub, b.ChainCode, child.DerivationPath)
			}
			check(err)
			priv := new(big.Int).Add(w.secrets[proto], new(big.Int).SetBytes(r.Delta))
			priv.Mod(priv, order)
			point := crypto.ScalarBaseMult(curve, priv)
			address := ethereumAddress(point)
			if proto == ProtocolEdDSA {
				address = base58Encode(r.PublicKey)
			}
			out = append(out, ChildKey{
				WalletID:       child.WalletID,
				Name:           child.Name,
				DerivationPath: child.DerivationPath,
				Protocol:       proto,
				PrivateKeyHex:  hex.EncodeToString(priv.FillBytes(make([]byte, 32))),
				PublicKeyHex:   hex.EncodeToString(r.PublicKey),
				Address:        address,
			})
		}
	}
	return out
}

func newRSAKey() (privPEM, pubPEM []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	check(err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	check(err)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func writeFixture(name string, data []byte) {
	path := filepath.Join(fixtureDir, name)
	check(os.MkdirAll(filepath.Dir(path), 0o755))
	check(os.WriteFile(path, data, 0o600))
}

func writeJSONFixture(name string, v any) {
	raw, err := json.MarshalIndent(v, "", "  ")
	check(err)
	writeFixture(name, raw)
}

var fixtureChildren = []HDChild{
	{WalletID: "child-0", Name: "bbil", DerivationIndex: 0, DerivationPath: []uint32{0}},
	{WalletID: "child-1", Name: "ops", DerivationIndex: 1, DerivationPath: []uint32{1}},
	{WalletID: "child-9", Name: "treasury", DerivationIndex: 9, DerivationPath: []uint32{9}},
}

const (
	hdBundleFixture = "hd-bundle.json"
	hdGoldenFixture = "hd-children.golden.json"
)

func generateFixtures() {
	fx = &fixtureSet{
		mixed:  newFixtureWallet("11111111-aaaa-4bbb-8ccc-000000000001", 3),
		export: newFixtureWallet("22222222-aaaa-4bbb-8ccc-000000000002", 3),
		ws2:    newFixtureWallet("33333333-aaaa-4bbb-8ccc-000000000003", 3),
	}

	recipientPriv, recipientPub := newRSAKey()
	writeFixture("recipient_priv.pem", recipientPriv)

	// One wallet backed up in two formats: an RSA bundle and a passphrase-protected mshare.
	writeFixture("rsa-bundle.enc", fx.mixed.rsaBundle(1, "cos-fixture-1", recipientPub))
	writeFixture("cos11.mshare", fx.mixed.mshare(2, "cos-fixture-2", testPassphrase))
	mixedHD := fx.mixed.hdBundle(fixtureChildren)
	writeFixture(hdBundleFixture, sealHDBundle(mixedHD, recipientPub))
	writeJSONFixture(hdGoldenFixture, fx.mixed.referenceChildren(mixedHD))

	// A full Fystack-style export: two shares, the child wallet list, the child keys and their keystores.
	exportPriv, exportPub := newRSAKey()
	writeFixture(filepath.Join(exportDir, "test_priv.pem"), exportPriv)
	writeFixture(filepath.Join(exportDir, "share-cosigner.enc"), fx.export.rsaBundle(1, "cos-fixture-1", exportPub))
	writeFixture(filepath.Join(exportDir, "share-hd1.enc"), fx.export.rsaBundle(2, "hd-fixture-2", exportPub))
	exportHD := fx.export.hdBundle([]HDChild{
		{WalletID: "44444444-aaaa-4bbb-8ccc-000000000004", Name: "child1", DerivationIndex: 0, DerivationPath: []uint32{0}},
		{WalletID: "55555555-aaaa-4bbb-8ccc-000000000005", Name: "child2", DerivationIndex: 1, DerivationPath: []uint32{1}},
	})
	writeFixture(filepath.Join(exportDir, "hd-paths-hd1.enc"), sealHDBundle(exportHD, exportPub))
	exportKeys := fx.export.referenceChildren(exportHD)
	writeJSONFixture(filepath.Join(exportDir, "child-keys.json"), exportKeys)
	for _, k := range exportKeys {
		if k.Protocol != ProtocolECDSA {
			continue
		}
		raw, err := BuildKeystoreV3(k.PrivateKeyHex, k.Address, "fixture-password")
		check(err)
		writeFixture(filepath.Join(exportDir, fmt.Sprintf("keystore-%s.json", k.Name)), raw)
	}

	// A single share of another wallet, plus its Solana-sweepable child keys.
	writeFixture(filepath.Join(ws2Dir, "share-cosigner.enc"), fx.ws2.rsaBundle(1, ws2Participant, exportPub))
	ws2HD := fx.ws2.hdBundle([]HDChild{{WalletID: "66666666-aaaa-4bbb-8ccc-000000000006", Name: "bbil", DerivationIndex: 0, DerivationPath: []uint32{0}}})
	writeJSONFixture(filepath.Join(ws2Dir, "child-keys-hd.json"), fx.ws2.referenceChildren(ws2HD))
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}
