package recovery

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
)

type Format string

const (
	FormatRSABundle Format = "rsa-bundle"
	FormatMShare    Format = "mshare"
	FormatUnknown   Format = "unknown"
)

// ShareInfo describes a parsed share file before it is unlocked.
type ShareInfo struct {
	ID            string   `json:"id"`
	Format        Format   `json:"format"`
	WalletID      string   `json:"walletId"`
	ParticipantID string   `json:"participantId"`
	Protocols     []string `json:"protocols"`
	Unlocked      bool     `json:"unlocked"`
	NeedsRSAKey   bool     `json:"needsRsaKey"`
	NeedsPass     bool     `json:"needsPassphrase"`
	Cancelled     bool     `json:"cancelled"`
}

type pendingShare struct {
	info ShareInfo
	raw  []byte
}

type unlockedShare struct {
	participantID string
	blobs         map[string][]byte
}

// Session holds parsed and decrypted shares in memory for one recovery run.
type Session struct {
	mu       sync.Mutex
	pending  map[string]*pendingShare
	unlocked map[string]*unlockedShare
}

func NewSession() *Session {
	return &Session{
		pending:  map[string]*pendingShare{},
		unlocked: map[string]*unlockedShare{},
	}
}

func detectFormat(raw []byte) Format {
	switch {
	case looksLikeMShare(raw):
		return FormatMShare
	case looksLikeRSABundle(raw):
		return FormatRSABundle
	default:
		return FormatUnknown
	}
}

func shareID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

// AddShare parses a raw share file and registers it as pending unlock.
func (s *Session) AddShare(raw []byte) (ShareInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := shareID(raw)
	if _, exists := s.pending[id]; exists {
		return s.pending[id].info, errors.New("this share file was already added")
	}

	info := ShareInfo{ID: id, Format: detectFormat(raw)}
	switch info.Format {
	case FormatRSABundle:
		info.NeedsRSAKey = true
		var b rsaBundle
		if err := jsonUnmarshal(raw, &b); err == nil {
			info.WalletID = b.walletID()
			info.ParticipantID = b.participant()
			info.Protocols = b.protocols()
		}
	case FormatMShare:
		info.NeedsPass = true
		if wid, pid, protos, ok := peekMShare(raw); ok {
			info.WalletID, info.ParticipantID, info.Protocols = wid, pid, protos
		}
	default:
		return info, errors.New("unrecognized share file format")
	}

	s.pending[id] = &pendingShare{info: info, raw: raw}
	return info, nil
}

// UnlockShare decrypts a pending share with the supplied secret (RSA PEM or passphrase).
func (s *Session) UnlockShare(id, secret string) (ShareInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.pending[id]
	if !ok {
		return ShareInfo{}, errors.New("share not found")
	}

	var (
		walletID, participantID string
		blobs                   map[string][]byte
		err                     error
	)
	switch p.info.Format {
	case FormatRSABundle:
		key, kerr := loadRSAPrivateKey([]byte(secret))
		if kerr != nil {
			return p.info, kerr
		}
		walletID, participantID, blobs, err = openRSABundle(p.raw, key)
	case FormatMShare:
		payload, ctx, merr := openMShare(p.raw, secret)
		if merr != nil {
			return p.info, merr
		}
		walletID, participantID = ctx.WalletID, ctx.ParticipantID
		blobs = map[string][]byte{}
		for _, sh := range payload.Shares {
			blob, derr := base64.StdEncoding.DecodeString(sh.ShareBlobBase64)
			if derr != nil {
				return p.info, errors.New("invalid share blob in bundle")
			}
			blobs[normalizeProtocol(sh.Protocol)] = blob
		}
	default:
		return p.info, errors.New("unrecognized share file format")
	}
	if err != nil {
		return p.info, err
	}

	s.unlocked[id] = &unlockedShare{participantID: participantID, blobs: blobs}
	p.info.Unlocked = true
	p.info.WalletID = walletID
	p.info.ParticipantID = participantID
	p.info.Protocols = keysOf(blobs)
	return p.info, nil
}

// RemoveShare drops a share from the session.
func (s *Session) RemoveShare(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.unlocked[id]; u != nil {
		for _, b := range u.blobs {
			wipe(b)
		}
	}
	delete(s.pending, id)
	delete(s.unlocked, id)
}

// Status summarizes the current session.
type Status struct {
	WalletID       string         `json:"walletId"`
	Shares         []ShareInfo    `json:"shares"`
	UnlockedCounts map[string]int `json:"unlockedCounts"`
	WalletMismatch bool           `json:"walletMismatch"`
}

func (s *Session) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked()
}

func (s *Session) statusLocked() Status {
	st := Status{UnlockedCounts: map[string]int{}}
	wallets := map[string]bool{}
	ids := make([]string, 0, len(s.pending))
	for id := range s.pending {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		info := s.pending[id].info
		st.Shares = append(st.Shares, info)
		if u := s.unlocked[id]; u != nil {
			if info.WalletID != "" {
				wallets[info.WalletID] = true
				st.WalletID = info.WalletID
			}
			for proto := range u.blobs {
				st.UnlockedCounts[proto]++
			}
		}
	}
	st.WalletMismatch = len(wallets) > 1
	return st
}

// Recover reconstructs every protocol that has at least 2 unlocked shares.
func (s *Session) Recover() ([]*CombinedKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if st := s.statusLocked(); st.WalletMismatch {
		return nil, errors.New("unlocked shares belong to different wallets")
	}

	byProto := map[string][][]byte{}
	for id, u := range s.unlocked {
		_ = id
		for proto, blob := range u.blobs {
			byProto[proto] = append(byProto[proto], blob)
		}
	}
	if len(byProto) == 0 {
		return nil, errors.New("no unlocked shares to recover from")
	}

	protos := keysOf(byProto)
	results := make([]*CombinedKey, 0, len(protos))
	for _, proto := range protos {
		blobs := byProto[proto]
		if len(blobs) < 2 {
			return nil, fmt.Errorf("%s: need at least 2 shares, have %d", proto, len(blobs))
		}
		key, err := combine(proto, blobs)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", proto, err)
		}
		results = append(results, key)
	}
	return results, nil
}

// Reset wipes all session state.
func (s *Session) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.unlocked {
		for _, b := range u.blobs {
			wipe(b)
		}
	}
	s.pending = map[string]*pendingShare{}
	s.unlocked = map[string]*unlockedShare{}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
