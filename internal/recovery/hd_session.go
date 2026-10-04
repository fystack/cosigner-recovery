package recovery

import "errors"

type HDInfo struct {
	Loaded         bool   `json:"loaded"`
	Pending        bool   `json:"pending"`
	FileName       string `json:"fileName"`
	MasterWalletID string `json:"masterWalletId"`
	ChildCount     int    `json:"childCount"`
}

func (s *Session) hdInfoLocked() HDInfo {
	info := HDInfo{FileName: s.hdFileName, Pending: s.hdRaw != nil && s.hd == nil}
	if s.hd != nil {
		info.Loaded = true
		info.MasterWalletID = s.hd.MasterWalletID
		info.ChildCount = len(s.hd.Children)
	}
	return info
}

// AddHDFile registers the child wallet list as pending until its RSA key is supplied.
func (s *Session) AddHDFile(raw []byte, name string) (HDInfo, error) {
	if !LooksLikeHDBundle(raw) {
		return HDInfo{}, errors.New("not a Fystack child wallet list file")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hdRaw, s.hd, s.hdFileName = raw, nil, name
	return s.hdInfoLocked(), nil
}

func (s *Session) UnlockHD(rsaKeyPEM []byte) (HDInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hdRaw == nil {
		return HDInfo{}, errors.New("add the child wallet list first")
	}
	bundle, err := OpenHDBundle(s.hdRaw, rsaKeyPEM)
	if err != nil {
		return s.hdInfoLocked(), err
	}
	s.hd = bundle
	return s.hdInfoLocked(), nil
}

func (s *Session) RemoveHD() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hdRaw, s.hd, s.hdFileName = nil, nil, ""
}

func (s *Session) HDInfo() HDInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hdInfoLocked()
}

// DeriveChildKeys needs the master keys from a prior Recover and an unlocked HD bundle.
func (s *Session) DeriveChildKeys() ([]ChildKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hd == nil {
		return nil, errors.New("unlock the child wallet list first")
	}
	if len(s.lastKeys) == 0 {
		return nil, errors.New("recover the master keys first")
	}
	if wallet := s.statusLocked().WalletID; wallet != "" && s.hd.MasterWalletID != "" && wallet != s.hd.MasterWalletID {
		return nil, errors.New("child wallet list belongs to a different master wallet")
	}
	return DeriveChildren(s.hd, s.lastKeys)
}
