package recovery

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"recovery/internal/envelope"
)

const bundleFormat = "mpcium-export-bundle-v1"

type rsaBundle struct {
	Format string `json:"format"`
	Wallet string `json:"wallet"`
	Shares []struct {
		Protocol      string `json:"protocol"`
		KeyID         string `json:"key_id"`
		ParticipantID string `json:"participant_id"`
		Envelope      string `json:"envelope"`
	} `json:"shares"`
	Envelope string `json:"envelope"`
	KeyID    string `json:"key_id"`
	Protocol string `json:"protocol"`
}

func looksLikeRSABundle(raw []byte) bool {
	var probe struct {
		Format string `json:"format"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return false
	}
	return probe.Format == bundleFormat || probe.Format == "" && looksLikeSingleEnvelope(raw)
}

func looksLikeSingleEnvelope(raw []byte) bool {
	var probe struct {
		Envelope string `json:"envelope"`
	}
	return json.Unmarshal(raw, &probe) == nil && probe.Envelope != ""
}

// openRSABundle decrypts every envelope in the bundle with the recipient RSA key,
// returning the raw tss-lib share JSON per protocol.
func openRSABundle(raw []byte, priv *rsa.PrivateKey) (walletID string, participantID string, shares map[string][]byte, err error) {
	var b rsaBundle
	if err = json.Unmarshal(raw, &b); err != nil {
		return "", "", nil, errors.New("invalid bundle JSON")
	}

	type item struct{ protocol, keyID, participant, envelope string }
	var items []item
	if len(b.Shares) > 0 {
		for _, s := range b.Shares {
			items = append(items, item{s.Protocol, s.KeyID, s.ParticipantID, s.Envelope})
		}
	} else if b.Envelope != "" {
		items = append(items, item{b.Protocol, b.KeyID, "", b.Envelope})
	}
	if len(items) == 0 {
		return "", "", nil, errors.New("no shares found in bundle")
	}

	shares = make(map[string][]byte, len(items))
	for _, it := range items {
		plain, derr := envelope.Open([]byte(it.envelope), priv)
		if derr != nil {
			return "", "", nil, fmt.Errorf("decrypt %s failed: wrong RSA key or corrupted bundle", normalizeProtocol(it.protocol))
		}
		shares[normalizeProtocol(it.protocol)] = plain
		if walletID == "" {
			walletID = it.keyID
		}
		if participantID == "" {
			participantID = it.participant
		}
	}
	return walletID, participantID, shares, nil
}

func loadRSAPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("not a valid PEM private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("cannot parse RSA private key (PKCS1/PKCS8)")
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rsaKey, nil
}
