package recovery

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// WriteChildKeys writes keys as CSV when path ends in .csv, otherwise as JSON.
func WriteChildKeys(path string, keys []ChildKey) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if !strings.HasSuffix(strings.ToLower(path), ".csv") {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(keys)
	}
	w := csv.NewWriter(f)
	w.Write([]string{"wallet_id", "name", "derivation_path", "protocol", "address", "public_key", "private_key_hex"})
	for _, k := range keys {
		parts := make([]string, len(k.DerivationPath))
		for i, idx := range k.DerivationPath {
			parts[i] = strconv.FormatUint(uint64(idx), 10)
		}
		w.Write([]string{k.WalletID, k.Name, "m/" + strings.Join(parts, "/"), k.Protocol, k.Address, k.PublicKeyHex, k.PrivateKeyHex})
	}
	w.Flush()
	return w.Error()
}

func ReadChildKeys(path string) ([]ChildKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []ChildKey
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}
