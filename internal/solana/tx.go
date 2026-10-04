package solana

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/edwards/v2"

	"recovery/internal/recovery"
)

type PublicKey [32]byte

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func (p PublicKey) String() string { return recovery.Base58Encode(p[:]) }

func decodeBase58(s string) ([]byte, error) {
	n := new(big.Int)
	radix := big.NewInt(58)
	for _, c := range s {
		idx := -1
		for i, a := range base58Alphabet {
			if a == c {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", c)
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(idx)))
	}
	raw := n.Bytes()
	zeros := 0
	for _, c := range s {
		if c != rune(base58Alphabet[0]) {
			break
		}
		zeros++
	}
	return append(make([]byte, zeros), raw...), nil
}

func ParseAddress(s string) (PublicKey, error) {
	raw, err := decodeBase58(s)
	if err != nil || len(raw) != 32 {
		return PublicKey{}, fmt.Errorf("invalid Solana address %q", s)
	}
	var p PublicKey
	copy(p[:], raw)
	return p, nil
}

func mustAddress(s string) PublicKey {
	p, err := ParseAddress(s)
	if err != nil {
		panic(err)
	}
	return p
}

var (
	SystemProgram     = PublicKey{}
	TokenProgram      = mustAddress("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
	Token2022Program  = mustAddress("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
	AssociatedProgram = mustAddress("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
)

type AccountMeta struct {
	Key      PublicKey
	Signer   bool
	Writable bool
}

type Instruction struct {
	Program  PublicKey
	Accounts []AccountMeta
	Data     []byte
}

const maxTxSize = 1232

func putCompact(out []byte, n int) []byte {
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func readCompact(raw []byte, pos *int) (int, error) {
	value, shift := 0, 0
	for {
		if *pos >= len(raw) {
			return 0, errors.New("truncated message")
		}
		b := raw[*pos]
		*pos++
		value |= int(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, nil
		}
		shift += 7
	}
}

// CompileMessage builds a legacy message with payer as the only required signer.
func CompileMessage(payer PublicKey, blockhash [32]byte, ixs []Instruction) []byte {
	type meta struct {
		key      PublicKey
		signer   bool
		writable bool
	}
	metas := []*meta{{key: payer, signer: true, writable: true}}
	find := func(k PublicKey) *meta {
		for _, m := range metas {
			if m.key == k {
				return m
			}
		}
		return nil
	}
	add := func(k PublicKey, signer, writable bool) {
		if m := find(k); m != nil {
			m.signer = m.signer || signer
			m.writable = m.writable || writable
			return
		}
		metas = append(metas, &meta{key: k, signer: signer, writable: writable})
	}
	for _, ix := range ixs {
		for _, a := range ix.Accounts {
			add(a.Key, a.Signer, a.Writable)
		}
	}
	for _, ix := range ixs {
		add(ix.Program, false, false)
	}

	var ordered []*meta
	var numSigners, numROSigners, numROUnsigned int
	for _, group := range []struct{ signer, writable bool }{{true, true}, {true, false}, {false, true}, {false, false}} {
		for _, m := range metas {
			if m.signer == group.signer && m.writable == group.writable {
				ordered = append(ordered, m)
				switch {
				case group.signer && group.writable:
					numSigners++
				case group.signer:
					numSigners++
					numROSigners++
				case !group.writable:
					numROUnsigned++
				}
			}
		}
	}

	out := []byte{byte(numSigners), byte(numROSigners), byte(numROUnsigned)}
	out = putCompact(out, len(ordered))
	index := map[PublicKey]int{}
	for i, m := range ordered {
		out = append(out, m.key[:]...)
		index[m.key] = i
	}
	out = append(out, blockhash[:]...)
	out = putCompact(out, len(ixs))
	for _, ix := range ixs {
		out = append(out, byte(index[ix.Program]))
		out = putCompact(out, len(ix.Accounts))
		for _, a := range ix.Accounts {
			out = append(out, byte(index[a.Key]))
		}
		out = putCompact(out, len(ix.Data))
		out = append(out, ix.Data...)
	}
	return out
}

func SystemTransfer(from, to PublicKey, lamports uint64) Instruction {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data, 2)
	binary.LittleEndian.PutUint64(data[4:], lamports)
	return Instruction{
		Program:  SystemProgram,
		Accounts: []AccountMeta{{from, true, true}, {to, false, true}},
		Data:     data,
	}
}

func TokenTransferChecked(program, source, mint, dest, owner PublicKey, amount uint64, decimals uint8) Instruction {
	data := make([]byte, 10)
	data[0] = 12
	binary.LittleEndian.PutUint64(data[1:], amount)
	data[9] = decimals
	return Instruction{
		Program:  program,
		Accounts: []AccountMeta{{source, false, true}, {mint, false, false}, {dest, false, true}, {owner, true, false}},
		Data:     data,
	}
}

func TokenCloseAccount(program, account, dest, owner PublicKey) Instruction {
	return Instruction{
		Program:  program,
		Accounts: []AccountMeta{{account, false, true}, {dest, false, true}, {owner, true, false}},
		Data:     []byte{9},
	}
}

func CreateATAIdempotent(payer, ata, owner, mint, tokenProgram PublicKey) Instruction {
	return Instruction{
		Program: AssociatedProgram,
		Accounts: []AccountMeta{
			{payer, true, true}, {ata, false, true}, {owner, false, false},
			{mint, false, false}, {SystemProgram, false, false}, {tokenProgram, false, false},
		},
		Data: []byte{1},
	}
}

func onCurve(b [32]byte) bool {
	_, err := edwards.ParsePubKey(b[:])
	return err == nil
}

func FindATA(owner, mint, tokenProgram PublicKey) PublicKey {
	for bump := 255; bump >= 0; bump-- {
		h := sha256.New()
		h.Write(owner[:])
		h.Write(tokenProgram[:])
		h.Write(mint[:])
		h.Write([]byte{byte(bump)})
		h.Write(AssociatedProgram[:])
		h.Write([]byte("ProgramDerivedAddress"))
		var candidate [32]byte
		copy(candidate[:], h.Sum(nil))
		if !onCurve(candidate) {
			return candidate
		}
	}
	panic("no valid program address")
}

type ParsedMessage struct {
	Keys         []PublicKey
	Blockhash    [32]byte
	Instructions []ParsedInstruction
	NumSigners   int
}

type ParsedInstruction struct {
	Program  PublicKey
	Accounts []PublicKey
	Data     []byte
}

func ParseMessage(raw []byte) (*ParsedMessage, error) {
	if len(raw) < 4 || raw[0]&0x80 != 0 {
		return nil, errors.New("unsupported message format")
	}
	pm := &ParsedMessage{NumSigners: int(raw[0])}
	pos := 3
	n, err := readCompact(raw, &pos)
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		if pos+32 > len(raw) {
			return nil, errors.New("truncated account keys")
		}
		var k PublicKey
		copy(k[:], raw[pos:pos+32])
		pm.Keys = append(pm.Keys, k)
		pos += 32
	}
	if pos+32 > len(raw) {
		return nil, errors.New("truncated blockhash")
	}
	copy(pm.Blockhash[:], raw[pos:pos+32])
	pos += 32
	count, err := readCompact(raw, &pos)
	if err != nil {
		return nil, err
	}
	for i := 0; i < count; i++ {
		if pos >= len(raw) {
			return nil, errors.New("truncated instruction")
		}
		progIdx := int(raw[pos])
		pos++
		nAcc, err := readCompact(raw, &pos)
		if err != nil {
			return nil, err
		}
		pi := ParsedInstruction{}
		if progIdx >= len(pm.Keys) {
			return nil, errors.New("program index out of range")
		}
		pi.Program = pm.Keys[progIdx]
		for j := 0; j < nAcc; j++ {
			if pos >= len(raw) || int(raw[pos]) >= len(pm.Keys) {
				return nil, errors.New("account index out of range")
			}
			pi.Accounts = append(pi.Accounts, pm.Keys[raw[pos]])
			pos++
		}
		nData, err := readCompact(raw, &pos)
		if err != nil {
			return nil, err
		}
		if pos+nData > len(raw) {
			return nil, errors.New("truncated instruction data")
		}
		pi.Data = append([]byte(nil), raw[pos:pos+nData]...)
		pos += nData
		pm.Instructions = append(pm.Instructions, pi)
	}
	if pos != len(raw) {
		return nil, errors.New("trailing bytes in message")
	}
	return pm, nil
}
