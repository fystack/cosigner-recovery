package recovery

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/bnb-chain/tss-lib/v3/crypto"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/fystack/mpcium-sdk/protocol"
)

var update = flag.Bool("update", false, "regenerate testdata/hd-bundle.json and testdata/hd-children.golden.json")

const (
	hdBundleFixture = "hd-bundle.json"
	hdGoldenFixture = "hd-children.golden.json"
)

var fixtureChildren = []HDChild{
	{WalletID: "child-0", Name: "bbil", DerivationIndex: 0, DerivationPath: []uint32{0}},
	{WalletID: "child-1", Name: "ops", DerivationIndex: 1, DerivationPath: []uint32{1}},
	{WalletID: "child-9", Name: "treasury", DerivationIndex: 9, DerivationPath: []uint32{9}},
}

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

func writeHDFixtures(t *testing.T) {
	t.Helper()
	s, keys := recoveredFixtureSession(t)
	walletID := s.Status().WalletID
	chainCode := make([]byte, 32)
	for i := range chainCode {
		chainCode[i] = byte(i + 1)
	}
	bundle := HDBundle{
		Format:               hdRecoveryFormat,
		MasterWalletID:       walletID,
		KeyID:                walletID,
		CKDVersion:           "v1",
		Threshold:            2,
		ChainCode:            hex.EncodeToString(chainCode),
		MasterPublicKeyECDSA: keyFor(t, keys, ProtocolECDSA).PublicKeyHex,
		MasterPublicKeyEDDSA: edwardsPublicKeyHex(t, keyFor(t, keys, ProtocolEdDSA)),
		Children:             fixtureChildren,
	}
	plain, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := loadRSAPrivateKey(read(t, "recipient_priv.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	envelope, err := protocol.BuildExportEnvelope(plain, pubPEM, "hd-recovery|"+walletID)
	if err != nil {
		t.Fatal(err)
	}
	file, err := json.MarshalIndent(hdBundleFile{Format: hdBundleFileFormat, Envelope: string(envelope)}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("testdata", hdBundleFixture), file, 0o644); err != nil {
		t.Fatal(err)
	}

	children, err := DeriveChildren(&bundle, keys)
	if err != nil {
		t.Fatal(err)
	}
	golden, err := json.MarshalIndent(children, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("testdata", hdGoldenFixture), golden, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

func TestRegenerateHDFixtures(t *testing.T) {
	if !*update {
		t.Skip("run with -update to regenerate HD fixtures")
	}
	writeHDFixtures(t)
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
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("derived child keys differ from %s; rerun with -update only if the change is intended", hdGoldenFixture)
	}
}
