package recovery

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	parties       map[string]int
}

func (u *unlockedShare) wipe() {
	for _, b := range u.blobs {
		wipe(b)
	}
}

// Session holds parsed and decrypted shares in memory for one recovery run.
type Session struct {
	mu         sync.Mutex
	pending    map[string]*pendingShare
	unlocked   map[string]*unlockedShare
	hd         *HDBundle
	hdRaw      []byte
	hdFileName string
	lastKeys   []*CombinedKey
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
		if err := json.Unmarshal(raw, &b); err == nil {
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

	var opened openedShare
	var err error
	switch p.info.Format {
	case FormatRSABundle:
		opened, err = openRSAShare(p.raw, secret)
	case FormatMShare:
		opened, err = openMShareShare(p.raw, secret)
	default:
		err = errors.New("unrecognized share file format")
	}
	if err != nil {
		return p.info, err
	}

	parties := make(map[string]int, len(opened.blobs))
	for proto, blob := range opened.blobs {
		parties[proto] = partyCount(proto, blob)
	}
	s.unlocked[id] = &unlockedShare{participantID: opened.participantID, blobs: opened.blobs, parties: parties}
	p.info.Unlocked = true
	p.info.WalletID = opened.walletID
	p.info.ParticipantID = opened.participantID
	p.info.Protocols = keysOf(opened.blobs)
	return p.info, nil
}

type openedShare struct {
	walletID      string
	participantID string
	blobs         map[string][]byte
}

func openRSAShare(raw []byte, pemKey string) (openedShare, error) {
	key, err := loadRSAPrivateKey([]byte(pemKey))
	if err != nil {
		return openedShare{}, err
	}
	walletID, participantID, blobs, err := openRSABundle(raw, key)
	return openedShare{walletID, participantID, blobs}, err
}

func openMShareShare(raw []byte, passphrase string) (openedShare, error) {
	payload, ctx, err := openMShare(raw, passphrase)
	if err != nil {
		return openedShare{}, err
	}
	blobs := make(map[string][]byte, len(payload.Shares))
	for _, sh := range payload.Shares {
		blob, err := base64.StdEncoding.DecodeString(sh.ShareBlobBase64)
		if err != nil {
			return openedShare{}, errors.New("invalid share blob in bundle")
		}
		blobs[normalizeProtocol(sh.Protocol)] = blob
	}
	return openedShare{ctx.WalletID, ctx.ParticipantID, blobs}, nil
}

// RemoveShare drops a share from the session.
func (s *Session) RemoveShare(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.unlocked[id]; u != nil {
		u.wipe()
	}
	delete(s.pending, id)
	delete(s.unlocked, id)
}

// Status summarizes the current session.
type Status struct {
	WalletID       string         `json:"walletId"`
	Shares         []ShareInfo    `json:"shares"`
	UnlockedCounts map[string]int `json:"unlockedCounts"`
	// PartyCounts is the total number of participants per protocol, as recorded in the shares (0 if unknown).
	PartyCounts    map[string]int `json:"partyCounts"`
	WalletMismatch bool           `json:"walletMismatch"`
}

func (s *Session) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked()
}

func (s *Session) statusLocked() Status {
	st := Status{UnlockedCounts: map[string]int{}, PartyCounts: map[string]int{}}
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
				st.PartyCounts[proto] = max(st.PartyCounts[proto], u.parties[proto])
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
	for _, u := range s.unlocked {
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
		if errors.Is(err, ErrInsufficientShares) {
			return nil, fmt.Errorf("%s: %w (have %d) — add more participants' shares", proto, err, len(blobs))
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", proto, err)
		}
		results = append(results, key)
	}
	s.lastKeys = results
	return results, nil
}

// Reset wipes all session state.
func (s *Session) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.unlocked {
		u.wipe()
	}
	s.pending = map[string]*pendingShare{}
	s.unlocked = map[string]*unlockedShare{}
	s.hd, s.hdRaw, s.hdFileName = nil, nil, ""
	s.lastKeys = nil
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
