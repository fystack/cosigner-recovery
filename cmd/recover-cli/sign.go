package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"recovery/internal/recovery"
)

type signRequest struct {
	WalletID   string `json:"wallet_id,omitempty"`
	Address    string `json:"address,omitempty"`
	MessageHex string `json:"message_hex"`
}

type signResult struct {
	WalletID        string `json:"wallet_id"`
	Address         string `json:"address"`
	SignatureHex    string `json:"signature_hex"`
	SignatureBase58 string `json:"signature_base58"`
}

type eddsaKeyIndex struct {
	byWallet  map[string]recovery.ChildKey
	byAddress map[string]recovery.ChildKey
}

func indexEdDSAKeys(children []recovery.ChildKey) eddsaKeyIndex {
	idx := eddsaKeyIndex{byWallet: map[string]recovery.ChildKey{}, byAddress: map[string]recovery.ChildKey{}}
	for _, c := range children {
		if c.Protocol != recovery.ProtocolEdDSA {
			continue
		}
		idx.byWallet[c.WalletID] = c
		idx.byAddress[c.Address] = c
	}
	return idx
}

func (idx eddsaKeyIndex) find(req signRequest) (recovery.ChildKey, bool) {
	if req.WalletID == "" {
		key, ok := idx.byAddress[req.Address]
		return key, ok
	}
	key, ok := idx.byWallet[req.WalletID]
	return key, ok
}

func signBatch(opts options, children []recovery.ChildKey) error {
	var requests []signRequest
	if err := readJSONFile(opts.signBatch, &requests); err != nil {
		return fmt.Errorf("sign batch must be a JSON array of {wallet_id|address, message_hex}: %w", err)
	}

	keys := indexEdDSAKeys(children)
	results := make([]signResult, 0, len(requests))
	for i, req := range requests {
		key, ok := keys.find(req)
		if !ok {
			return fmt.Errorf("request %d: no EdDSA key for wallet_id=%q address=%q", i, req.WalletID, req.Address)
		}
		msg, err := hex.DecodeString(strings.TrimPrefix(req.MessageHex, "0x"))
		if err != nil || len(msg) == 0 {
			return fmt.Errorf("request %d: invalid message_hex", i)
		}
		sig, err := recovery.SignEdDSA(key.PrivateKeyHex, msg)
		if err != nil {
			return fmt.Errorf("request %d: %w", i, err)
		}
		results = append(results, signResult{
			WalletID:        key.WalletID,
			Address:         key.Address,
			SignatureHex:    hex.EncodeToString(sig),
			SignatureBase58: recovery.Base58Encode(sig),
		})
	}
	return writeJSONOutput(opts.signOut, results)
}
