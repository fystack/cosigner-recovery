package envelope

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func testKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestBuildOpenRoundTrip(t *testing.T) {
	priv, pubPEM := testKey(t)
	want := []byte(`{"share":"secret"}`)
	sealed, err := Build(want, pubPEM, "key|ECDSA|node0")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(sealed, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	_, pubPEM := testKey(t)
	other, _ := testKey(t)
	sealed, err := Build([]byte("x"), pubPEM, "aad")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(sealed, other); err == nil {
		t.Fatal("expected failure with the wrong private key")
	}
}

func TestOpenRejectsUnknownFormat(t *testing.T) {
	priv, _ := testKey(t)
	if _, err := Open([]byte(`{"format":"other"}`), priv); err == nil {
		t.Fatal("expected format error")
	}
}
