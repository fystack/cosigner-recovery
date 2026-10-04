package recovery

import "encoding/json"

func (b rsaBundle) walletID() string {
	if len(b.Shares) > 0 {
		return b.Shares[0].KeyID
	}
	return b.KeyID
}

func (b rsaBundle) participant() string {
	if len(b.Shares) > 0 {
		return b.Shares[0].ParticipantID
	}
	return ""
}

func (b rsaBundle) protocols() []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		n := normalizeProtocol(p)
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(b.Shares) > 0 {
		for _, s := range b.Shares {
			add(s.Protocol)
		}
	} else if b.Protocol != "" {
		add(b.Protocol)
	}
	return out
}

func peekMShare(raw []byte) (walletID, participantID string, protocols []string, ok bool) {
	var env mshareEnvelope
	if json.Unmarshal(raw, &env) != nil || env.Format != mshareFormat {
		return "", "", nil, false
	}
	seen := map[string]bool{}
	for _, e := range env.Context.Shares {
		n := normalizeProtocol(e.Protocol)
		if n != "" && !seen[n] {
			seen[n] = true
			protocols = append(protocols, n)
		}
	}
	return env.Context.WalletID, env.Context.ParticipantID, protocols, true
}
