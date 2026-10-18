// Package spake2p implements the SPAKE2+ password-authenticated key exchange of
// RFC 9383 for one ciphersuite only: P256-SHA256-HKDF-SHA256-HMAC-SHA256.
//
// SPAKE2+ is an asymmetric PAKE. The Prover (typically the client) knows a
// password; the Verifier (typically the device) stores only a verification
// record derived from it, (w0, L). An eavesdropper or an active attacker gets
// one password guess per protocol run and nothing else. A Verifier that is
// breached still needs a brute-force search to recover the password, because it
// holds L = w1·P and never w1.
//
// # Flow
//
// Registration, once, on any machine that knows the password:
//
//  1. Stretch the password with a PBKDF of your choice (scrypt, Argon2id, ...)
//     into 80 bytes. [PBKDFInput] gives the encoding RFC 9383 recommends for
//     the PBKDF input.
//  2. [W0W1FromPBKDFOutput] splits those bytes into the scalars w0 and w1.
//  3. [Register] computes L from w1. Hand (w0, L) to the Verifier. Discard w1.
//
// Exchange, every time the Prover connects:
//
//  1. Prover: [StartProver] returns shareP. Send it to the Verifier.
//  2. Verifier: [RespondVerifier] returns shareV and confirmV. Send both back.
//  3. Prover: [Prover.Finish] checks confirmV and returns confirmP and the
//     shared key. Send confirmP to the Verifier.
//  4. Verifier: [Verifier.Finish] checks confirmP and returns the shared key.
//
// The two sides hold the same 32-byte shared key if and only if both returned
// no error. Both Finish methods are single use: whatever the outcome, the state
// is consumed and a second call returns [ErrFinished].
//
// # Rate limiting
//
// A password is only as strong as the number of guesses an attacker gets, and
// this library cannot count them for you. Every call to [RespondVerifier],
// whatever its outcome, consumes one guess: the attacker learns confirmV from
// it (and can test its guess offline) or learns from a failure that its guess
// was exactly right, and then simply never sends confirmP. Counting only
// [Verifier.Finish] failures therefore gives an attacker unlimited guesses.
// Likewise every [Prover.Finish] against a peer that has not yet proved itself
// consumes one guess of that peer. The application must keep a small budget of
// attempts per password, count them at RespondVerifier, and rotate the
// password when the budget is spent.
//
// # Types
//
// Values that must not be mixed up have distinct types: [W0] and [W1] (the
// password-derived scalars), [L] (the stored verification value), and
// [ShareP], [ShareV], [ConfirmP], [ConfirmV] (peer messages, named byte
// slices). Swapping two of them does not compile. Parse stored values with
// [ParseW0], [ParseW1] and [ParseL] when you load them, so that a corrupted
// record is found before a peer connects; [ErrInvalidRecord] then means a
// local fault, never a bad peer. W0, W1 and L also implement
// encoding.BinaryMarshaler/BinaryUnmarshaler and json.Marshaler/Unmarshaler
// (hex), all going through the same parsers, so a stored struct can never
// silently decode to a zero value that passes as a valid secret.
//
// # Wire format
//
// Shares and L are SEC1 uncompressed points: exactly 65 bytes, first byte 0x04.
// Compressed, hybrid, short, long, off-curve, non-canonical and identity
// encodings are all rejected. Scalars are 32 bytes, big-endian, in [1, n-1]
// where n is the P-256 group order. Confirmation messages and the shared key
// are 32 bytes.
//
// # Secrets in memory
//
// Secret byte slices (x, y, w0, w1, Z, V, K_main, K_confirmP, K_confirmV and
// the shared key held internally) are overwritten with zeros once they are no
// longer needed: by Finish, or by Close for a state that is abandoned. Always
// reach one of them, for example with defer v.Close() right after
// [RespondVerifier] succeeds. This is best effort only: Go's garbage collector
// may have copied them before, and the runtime gives no way to prevent that;
// the elliptic-curve point objects of the underlying library are not wiped.
// The shared key returned to the caller is the caller's to protect and wipe.
package spake2p

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"

	"filippo.io/bigmod"
	"filippo.io/nistec"
)

// Sizes of the values on the wire.
const (
	// ScalarSize is the length in bytes of an encoded scalar.
	ScalarSize = 32
	// PointSize is the length in bytes of an encoded point (SEC1 uncompressed).
	PointSize = 65
	// ConfirmSize is the length in bytes of a confirmation message.
	ConfirmSize = 32
	// KeySize is the length in bytes of the shared key.
	KeySize = 32
	// PBKDFOutputSize is the length in bytes of the PBKDF output that
	// [W0W1FromPBKDFOutput] accepts.
	PBKDFOutputSize = 80
)

// Sentinel errors. Test with [errors.Is]. None of them carries secret data.
var (
	// ErrInvalidScalar means a scalar was not 32 bytes, was zero (including a
	// zero-value or wiped [W0]/[W1]), or was not below the P-256 group order.
	// Such values are never silently reduced.
	ErrInvalidScalar = errors.New("spake2p: invalid scalar")
	// ErrInvalidPBKDFOutput means the PBKDF output was not exactly 80 bytes,
	// or one of the two scalars derived from it was zero.
	ErrInvalidPBKDFOutput = errors.New("spake2p: invalid PBKDF output")
	// ErrInvalidPoint means a received share was not a valid 65-byte
	// uncompressed P-256 point (including a non-canonical coordinate), or a
	// point computed from it was the identity. It is about the peer.
	ErrInvalidPoint = errors.New("spake2p: invalid point")
	// ErrInvalidRecord means the locally stored verification value L was not a
	// valid 65-byte uncompressed P-256 point (or was nil or zero-value). It is a
	// local fault, never the peer's.
	ErrInvalidRecord = errors.New("spake2p: invalid record")
	// ErrInvalidMessage means a confirmation message had the wrong length.
	ErrInvalidMessage = errors.New("spake2p: invalid message length")
	// ErrConfirmationFailed means a confirmation tag did not verify: the peer
	// used a different password, context or identity, or a message was altered.
	ErrConfirmationFailed = errors.New("spake2p: confirmation failed")
	// ErrFinished means Finish or Close was already called on this state object.
	ErrFinished = errors.New("spake2p: already finished")
	// ErrInvalidState means the state object is a zero value, not one returned
	// by [StartProver] or [RespondVerifier].
	ErrInvalidState = errors.New("spake2p: invalid state")
	// ErrRandom means the operating system's random number generator failed.
	ErrRandom = errors.New("spake2p: random source failed")
)

// The RFC 9383 §4 constants M and N for P-256, compressed SEC1.
const (
	mCompressed = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
	nCompressed = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
)

// p256Order is the order n of the P-256 group, big-endian.
var p256Order = []byte{
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
	0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
}

var (
	orderMod *bigmod.Modulus // n
	wideMod  *bigmod.Modulus // a container for 40-byte inputs
	pointM   *nistec.P256Point
	pointN   *nistec.P256Point
	pointM65 []byte
	pointN65 []byte
)

func init() {
	var err error
	if orderMod, err = bigmod.NewModulus(p256Order); err != nil {
		panic(err)
	}
	// 41 bytes: 0x01 followed by forty 0xff. Odd, as bigmod requires, and
	// larger than every 40-byte value, so any 40-byte input fits in it.
	wide := make([]byte, 41)
	for i := range wide {
		wide[i] = 0xff
	}
	wide[0] = 0x01
	if wideMod, err = bigmod.NewModulus(wide); err != nil {
		panic(err)
	}
	pointM = mustPoint(mCompressed)
	pointN = mustPoint(nCompressed)
	pointM65 = pointM.Bytes()
	pointN65 = pointN.Bytes()
}

func mustPoint(compressedHex string) *nistec.P256Point {
	b := make([]byte, len(compressedHex)/2)
	for i := range b {
		var v byte
		for _, c := range []byte(compressedHex[2*i : 2*i+2]) {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			default:
				v |= c - 'a' + 10
			}
		}
		b[i] = v
	}
	p, err := nistec.NewP256Point().SetBytes(b)
	if err != nil {
		panic(err)
	}
	return p
}

// isZero reports whether b is all zero bytes, without branching on its value.
func isZero(b []byte) bool {
	var acc byte
	for _, c := range b {
		acc |= c
	}
	return subtle.ConstantTimeByteEq(acc, 0) == 1
}

// checkScalar validates a 32-byte scalar: in [1, n-1].
func checkScalar(b []byte) error {
	if len(b) != ScalarSize {
		return ErrInvalidScalar
	}
	n, err := bigmod.NewNat().SetBytes(b, orderMod)
	if err != nil || n.IsZero() == 1 || isZero(b) {
		return ErrInvalidScalar
	}
	return nil
}

func marshalHex(b []byte) []byte {
	out := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(out, b)
	return out
}

func unmarshalHexJSON(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return nil, errors.New("spake2p: JSON value must be a hex string")
	}
	return hex.DecodeString(string(data[1 : len(data)-1]))
}

// W0 is the password-derived scalar w0, an integer in [1, n-1], n the P-256
// group order. Obtain one from [ParseW0] or [W0W1FromPBKDFOutput]. The zero W0
// is invalid and is rejected by [StartProver], [RespondVerifier].
type W0 struct {
	b [ScalarSize]byte
}

// W1 is the password-derived scalar w1, an integer in [1, n-1]. Obtain one from
// [ParseW1] or [W0W1FromPBKDFOutput]. The zero W1 is invalid and is rejected by
// [StartProver] and [Register].
type W1 struct {
	b [ScalarSize]byte
}

// ParseW0 reads a 32-byte big-endian w0. It returns [ErrInvalidScalar] if b is
// not exactly 32 bytes, is zero, or is greater than or equal to the group
// order. A value at or above the order is an error, never reduced.
func ParseW0(b []byte) (*W0, error) {
	if err := checkScalar(b); err != nil {
		return nil, err
	}
	s := new(W0)
	copy(s.b[:], b)
	return s, nil
}

// ParseW1 is [ParseW0] for w1.
func ParseW1(b []byte) (*W1, error) {
	if err := checkScalar(b); err != nil {
		return nil, err
	}
	s := new(W1)
	copy(s.b[:], b)
	return s, nil
}

// valid reports whether s is non-nil and a scalar in [1, n-1].
func (s *W0) valid() bool { return s != nil && checkScalar(s.b[:]) == nil }
func (s *W1) valid() bool { return s != nil && checkScalar(s.b[:]) == nil }

// Bytes returns a copy of the 32-byte big-endian encoding of s.
func (s *W0) Bytes() []byte { return bytes.Clone(s.b[:]) }

// Bytes returns a copy of the 32-byte big-endian encoding of s.
func (s *W1) Bytes() []byte { return bytes.Clone(s.b[:]) }

// Zero overwrites s with zeros (best effort, see the package documentation).
// The all-zero value is invalid, so every entry point rejects s afterwards
// with [ErrInvalidScalar].
func (s *W0) Zero() { wipe(s.b[:]) }

// Zero overwrites s with zeros; see [W0.Zero].
func (s *W1) Zero() { wipe(s.b[:]) }

// MarshalBinary returns the 32-byte encoding. It fails for an invalid (zero)
// value.
func (s W0) MarshalBinary() ([]byte, error) {
	if checkScalar(s.b[:]) != nil {
		return nil, ErrInvalidScalar
	}
	return bytes.Clone(s.b[:]), nil
}

// UnmarshalBinary parses like [ParseW0]; on error s is left unchanged.
func (s *W0) UnmarshalBinary(data []byte) error {
	p, err := ParseW0(data)
	if err != nil {
		return err
	}
	*s = *p
	p.Zero()
	return nil
}

// MarshalJSON encodes s as a hex string.
func (s W0) MarshalJSON() ([]byte, error) {
	b, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	defer wipe(b)
	return append(append([]byte{'"'}, marshalHex(b)...), '"'), nil
}

// UnmarshalJSON decodes a hex string through [ParseW0].
func (s *W0) UnmarshalJSON(data []byte) error {
	b, err := unmarshalHexJSON(data)
	if err != nil {
		return ErrInvalidScalar
	}
	defer wipe(b)
	return s.UnmarshalBinary(b)
}

// MarshalBinary returns the 32-byte encoding. It fails for an invalid (zero)
// value.
func (s W1) MarshalBinary() ([]byte, error) {
	if checkScalar(s.b[:]) != nil {
		return nil, ErrInvalidScalar
	}
	return bytes.Clone(s.b[:]), nil
}

// UnmarshalBinary parses like [ParseW1]; on error s is left unchanged.
func (s *W1) UnmarshalBinary(data []byte) error {
	p, err := ParseW1(data)
	if err != nil {
		return err
	}
	*s = *p
	p.Zero()
	return nil
}

// MarshalJSON encodes s as a hex string.
func (s W1) MarshalJSON() ([]byte, error) {
	b, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	defer wipe(b)
	return append(append([]byte{'"'}, marshalHex(b)...), '"'), nil
}

// UnmarshalJSON decodes a hex string through [ParseW1].
func (s *W1) UnmarshalJSON(data []byte) error {
	b, err := unmarshalHexJSON(data)
	if err != nil {
		return ErrInvalidScalar
	}
	defer wipe(b)
	return s.UnmarshalBinary(b)
}

// L is the Verifier's stored verification value L = w1·P: a valid, non-identity
// P-256 point. Obtain one from [Register] or [ParseL]. The zero L is invalid and
// is rejected by [RespondVerifier] with [ErrInvalidRecord].
type L struct {
	b [PointSize]byte
}

// ParseL validates a stored L: exactly 65 bytes, SEC1 uncompressed, canonical,
// on the curve, not the identity. Call it when loading a record, so that a
// corrupted record is found before any peer connects. It returns
// [ErrInvalidRecord] on failure.
func ParseL(b []byte) (*L, error) {
	if _, err := decodePoint(b); err != nil {
		return nil, ErrInvalidRecord
	}
	l := new(L)
	copy(l.b[:], b)
	return l, nil
}

// Bytes returns a copy of the 65-byte encoding of l.
func (l *L) Bytes() []byte { return bytes.Clone(l.b[:]) }

// MarshalBinary returns the 65-byte encoding. It fails for an invalid value.
func (l L) MarshalBinary() ([]byte, error) {
	if _, err := decodePoint(l.b[:]); err != nil {
		return nil, ErrInvalidRecord
	}
	return bytes.Clone(l.b[:]), nil
}

// UnmarshalBinary parses like [ParseL]; on error l is left unchanged.
func (l *L) UnmarshalBinary(data []byte) error {
	p, err := ParseL(data)
	if err != nil {
		return err
	}
	*l = *p
	return nil
}

// MarshalJSON encodes l as a hex string.
func (l L) MarshalJSON() ([]byte, error) {
	b, err := l.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(append([]byte{'"'}, marshalHex(b)...), '"'), nil
}

// UnmarshalJSON decodes a hex string through [ParseL].
func (l *L) UnmarshalJSON(data []byte) error {
	b, err := unmarshalHexJSON(data)
	if err != nil {
		return ErrInvalidRecord
	}
	return l.UnmarshalBinary(b)
}

// The messages exchanged with the peer, as distinct types so that two of them
// cannot be swapped. They are plain byte slices: convert with ShareP(b) when
// reading from the network.
type (
	// ShareP is the Prover's share X, 65 bytes.
	ShareP []byte
	// ShareV is the Verifier's share Y, 65 bytes.
	ShareV []byte
	// ConfirmP is the Prover's confirmation tag, 32 bytes.
	ConfirmP []byte
	// ConfirmV is the Verifier's confirmation tag, 32 bytes.
	ConfirmV []byte
)

// reduce40 reads a 40-byte big-endian integer and reduces it mod n.
// Constant time in the value (bigmod).
func reduce40(b []byte) []byte {
	wide, err := bigmod.NewNat().SetBytes(append([]byte{0}, b...), wideMod)
	if err != nil {
		panic("spake2p: 40-byte value exceeds container") // unreachable
	}
	return bigmod.NewNat().Mod(wide, orderMod).Bytes(orderMod)
}

// W0W1FromPBKDFOutput splits the 80-byte output of a PBKDF into w0 and w1
// (RFC 9383 §3.2): each 40-byte half is read as a big-endian integer and
// reduced mod n, which keeps the bias below 2^-64. Any other length returns
// [ErrInvalidPBKDFOutput], as does a half that reduces to zero (probability
// about 2^-256 for a PBKDF).
//
// The PBKDF itself is the application's choice and out of scope here.
func W0W1FromPBKDFOutput(out []byte) (w0 *W0, w1 *W1, err error) {
	if len(out) != PBKDFOutputSize {
		return nil, nil, ErrInvalidPBKDFOutput
	}
	w0b := reduce40(out[:40])
	w1b := reduce40(out[40:])
	defer wipe(w0b)
	defer wipe(w1b)
	w0, err0 := ParseW0(w0b)
	w1, err1 := ParseW1(w1b)
	if err0 != nil || err1 != nil {
		return nil, nil, ErrInvalidPBKDFOutput
	}
	return w0, w1, nil
}

// PBKDFInput returns the PBKDF input RFC 9383 §3.2 recommends:
// len(pw)||pw||len(idProver)||idProver||len(idVerifier)||idVerifier, each
// length an 8-byte little-endian integer.
func PBKDFInput(pw, idProver, idVerifier []byte) []byte {
	out := make([]byte, 0, 24+len(pw)+len(idProver)+len(idVerifier))
	out = appendLP(out, pw)
	out = appendLP(out, idProver)
	return appendLP(out, idVerifier)
}

// Register computes L = w1·P, the Verifier's verification value, as a 65-byte
// uncompressed point, as an [L]. It returns [ErrInvalidScalar] for a nil, zero or
// wiped w1. The Verifier stores (w0, L) and never w1.
func Register(w1 *W1) (*L, error) {
	if !w1.valid() {
		return nil, ErrInvalidScalar
	}
	p, err := nistec.NewP256Point().ScalarBaseMult(w1.b[:])
	if err != nil || isIdentity(p) {
		return nil, ErrInvalidScalar
	}
	l := new(L)
	copy(l.b[:], p.Bytes())
	return l, nil
}

// ---- helpers ----

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func appendLP(dst, v []byte) []byte {
	dst = binary.LittleEndian.AppendUint64(dst, uint64(len(v)))
	return append(dst, v...)
}

func isIdentity(p *nistec.P256Point) bool { return p.Bytes()[0] == 0 }

// decodePoint accepts exactly a 65-byte SEC1 uncompressed on-curve point.
// nistec alone would also accept compressed and identity encodings.
func decodePoint(b []byte) (*nistec.P256Point, error) {
	if len(b) != PointSize || b[0] != 0x04 {
		return nil, ErrInvalidPoint
	}
	p, err := nistec.NewP256Point().SetBytes(b)
	if err != nil || isIdentity(p) {
		return nil, ErrInvalidPoint
	}
	return p, nil
}

// randomScalar returns a uniform value in [1, n-1] by rejection sampling: it
// draws 32 random bytes and retries while the value is >= n (probability about
// 2^-32 per draw) or zero. Rejection leaks nothing about the accepted value.
func randomScalar() ([]byte, error) {
	buf := make([]byte, ScalarSize)
	for {
		if _, err := rand.Read(buf); err != nil {
			wipe(buf)
			return nil, ErrRandom
		}
		if n, err := bigmod.NewNat().SetBytes(buf, orderMod); err == nil && n.IsZero() == 0 {
			return buf, nil
		}
	}
}

// maskedShare returns s·P + w0·mask: X = x·P + w0·M or Y = y·P + w0·N.
func maskedShare(s []byte, w0 []byte, mask *nistec.P256Point) ([]byte, error) {
	sp, err := nistec.NewP256Point().ScalarBaseMult(s)
	if err != nil {
		return nil, err
	}
	wm, err := nistec.NewP256Point().ScalarMult(mask, w0)
	if err != nil {
		return nil, err
	}
	share := nistec.NewP256Point().Add(sp, wm)
	if isIdentity(share) {
		return nil, ErrInvalidPoint
	}
	return share.Bytes(), nil
}

// unmask returns share − w0·mask, rejecting the identity.
func unmask(share *nistec.P256Point, w0 []byte, mask *nistec.P256Point) (*nistec.P256Point, error) {
	wm, err := nistec.NewP256Point().ScalarMult(mask, w0)
	if err != nil {
		return nil, err
	}
	u := nistec.NewP256Point().Add(share, nistec.NewP256Point().Negate(wm))
	if isIdentity(u) {
		return nil, ErrInvalidPoint
	}
	return u, nil
}

// trace holds every intermediate value of one run, so the RFC vector test can
// check each byte. It is wiped when the owning state object finishes.
type trace struct {
	shareP, shareV              []byte
	z, v                        []byte
	tt                          []byte
	kMain, kConfirmP, kConfirmV []byte
	confirmP, confirmV          []byte
	kShared                     []byte
}

func (t *trace) wipe() {
	for _, b := range [][]byte{t.z, t.v, t.tt, t.kMain, t.kConfirmP, t.kConfirmV, t.kShared} {
		wipe(b)
	}
}

// derive computes the transcript and key schedule of RFC 9383 §3.3 and §3.4
// and fills the confirmation tags. t.shareP and t.shareV must be set.
func derive(t *trace, context, idProver, idVerifier, w0 []byte, z, v *nistec.P256Point) error {
	if isIdentity(z) || isIdentity(v) {
		return ErrInvalidPoint
	}
	t.z, t.v = z.Bytes(), v.Bytes()
	tt := make([]byte, 0, 8*9+len(context)+len(idProver)+len(idVerifier)+2*PointSize*4+ScalarSize)
	tt = appendLP(tt, context)
	tt = appendLP(tt, idProver)
	tt = appendLP(tt, idVerifier)
	tt = appendLP(tt, pointM65)
	tt = appendLP(tt, pointN65)
	tt = appendLP(tt, t.shareP)
	tt = appendLP(tt, t.shareV)
	tt = appendLP(tt, t.z)
	tt = appendLP(tt, t.v)
	tt = appendLP(tt, w0)
	t.tt = tt

	km := sha256.Sum256(tt)
	t.kMain = km[:]
	confirmKeys, err := hkdf.Key(sha256.New, t.kMain, nil, "ConfirmationKeys", 64)
	if err != nil {
		return err
	}
	t.kConfirmP, t.kConfirmV = confirmKeys[:32], confirmKeys[32:]
	if t.kShared, err = hkdf.Key(sha256.New, t.kMain, nil, "SharedKey", 32); err != nil {
		return err
	}
	t.confirmP = mac(t.kConfirmP, t.shareV)
	t.confirmV = mac(t.kConfirmV, t.shareP)
	return nil
}

func mac(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// ---- Prover ----

// Prover is the Prover's state between [StartProver] and [Prover.Finish]. It is
// safe to call Finish and Close from several goroutines; exactly one Finish
// succeeds.
type Prover struct {
	mu                            sync.Mutex
	context, idProver, idVerifier []byte
	x, w0, w1                     []byte
	shareP                        []byte
	finished                      bool
}

// StartProver begins an exchange as the Prover. It draws x uniformly from
// [1, n-1] using crypto/rand and returns shareP = x·P + w0·M, 65 bytes, to
// send to the Verifier. context, idProver and idVerifier must be identical on
// both sides; any of them may be empty. The scalars are copied. A nil, zero or
// wiped w0 or w1 returns [ErrInvalidScalar]. Always reach [Prover.Finish] or
// [Prover.Close].
func StartProver(context, idProver, idVerifier []byte, w0 *W0, w1 *W1) (*Prover, ShareP, error) {
	x, err := randomScalar()
	if err != nil {
		return nil, nil, err
	}
	return startProver(context, idProver, idVerifier, w0, w1, x)
}

// startProver is StartProver with x injected (test hook). It takes ownership
// of x.
func startProver(context, idProver, idVerifier []byte, w0 *W0, w1 *W1, x []byte) (*Prover, ShareP, error) {
	if !w0.valid() || !w1.valid() || len(x) != ScalarSize {
		wipe(x)
		return nil, nil, ErrInvalidScalar
	}
	shareP, err := maskedShare(x, w0.b[:], pointM)
	if err != nil {
		wipe(x)
		return nil, nil, err
	}
	p := &Prover{
		context:    append([]byte(nil), context...),
		idProver:   append([]byte(nil), idProver...),
		idVerifier: append([]byte(nil), idVerifier...),
		x:          x,
		w0:         w0.Bytes(),
		w1:         w1.Bytes(),
		shareP:     shareP,
	}
	return p, append(ShareP(nil), shareP...), nil
}

// Close wipes every secret the Prover holds and consumes it: a later Finish
// returns [ErrFinished]. It is idempotent and safe for concurrent use. Use it
// as defer p.Close() so that an abandoned exchange does not leave x, w0 and w1
// behind; [Prover.Finish] calls it itself.
func (p *Prover) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
}

func (p *Prover) closeLocked() {
	p.finished = true
	wipe(p.x)
	wipe(p.w0)
	wipe(p.w1)
}

// Finish completes the exchange. It validates shareV, derives the keys and
// checks confirmV in constant time. Only if confirmV is correct does it return
// confirmP (send it to the Verifier) and the 32-byte shared key; otherwise it
// returns an error and nothing else. Errors: [ErrInvalidPoint],
// [ErrInvalidMessage], [ErrConfirmationFailed], [ErrFinished],
// [ErrInvalidState] (a zero-value Prover). Finish may be called once, also
// across goroutines; the state is consumed whatever the outcome.
func (p *Prover) Finish(shareV ShareV, confirmV ConfirmV) (confirmP ConfirmP, kShared []byte, err error) {
	t, err := p.finish(shareV, confirmV)
	if err != nil {
		return nil, nil, err
	}
	confirmP = append(ConfirmP(nil), t.confirmP...)
	kShared = append([]byte(nil), t.kShared...)
	t.wipe()
	return confirmP, kShared, nil
}

// finish returns the full trace on success; the caller wipes it.
func (p *Prover) finish(shareV ShareV, confirmV ConfirmV) (*trace, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return nil, ErrFinished
	}
	if len(p.x) != ScalarSize || len(p.w0) != ScalarSize || len(p.w1) != ScalarSize {
		return nil, ErrInvalidState
	}
	defer p.closeLocked()

	y, err := decodePoint(shareV)
	if err != nil {
		return nil, err
	}
	if len(confirmV) != ConfirmSize {
		return nil, ErrInvalidMessage
	}
	u, err := unmask(y, p.w0, pointN) // Y - w0·N
	if err != nil {
		return nil, err
	}
	z, err := nistec.NewP256Point().ScalarMult(u, p.x)
	if err != nil {
		return nil, err
	}
	v, err := nistec.NewP256Point().ScalarMult(u, p.w1)
	if err != nil {
		return nil, err
	}
	t := &trace{shareP: p.shareP, shareV: append([]byte(nil), shareV...)}
	if err := derive(t, p.context, p.idProver, p.idVerifier, p.w0, z, v); err != nil {
		t.wipe()
		return nil, err
	}
	if !hmac.Equal(confirmV, t.confirmV) {
		t.wipe()
		return nil, ErrConfirmationFailed
	}
	return t, nil
}

// ---- Verifier ----

// Verifier is the Verifier's state between [RespondVerifier] and
// [Verifier.Finish]. It is safe to call Finish and Close from several
// goroutines; exactly one Finish succeeds.
type Verifier struct {
	mu       sync.Mutex
	t        *trace
	finished bool
}

// RespondVerifier handles shareP as the Verifier. w0 and l are the stored
// verification record (l as returned by [Register] or [ParseL]). It validates
// shareP, draws y uniformly from [1, n-1] using crypto/rand, and returns
// shareV = y·P + w0·N and confirmV, both to send to the Prover. Errors:
// [ErrInvalidPoint] (a bad shareP), [ErrInvalidRecord] (a bad l, a local
// fault), [ErrInvalidScalar] (a nil, zero or wiped w0), [ErrRandom].
//
// Every call consumes one password guess of the peer, whatever its outcome;
// see "Rate limiting" in the package documentation. Always reach
// [Verifier.Finish] or [Verifier.Close] on the returned Verifier.
func RespondVerifier(context, idProver, idVerifier []byte, w0 *W0, l *L, shareP ShareP) (*Verifier, ShareV, ConfirmV, error) {
	y, err := randomScalar()
	if err != nil {
		return nil, nil, nil, err
	}
	return respondVerifier(context, idProver, idVerifier, w0, l, shareP, y)
}

// respondVerifier is RespondVerifier with y injected (test hook). It takes
// ownership of y.
func respondVerifier(context, idProver, idVerifier []byte, w0 *W0, l *L, shareP ShareP, y []byte) (*Verifier, ShareV, ConfirmV, error) {
	defer wipe(y)
	if !w0.valid() || len(y) != ScalarSize {
		return nil, nil, nil, ErrInvalidScalar
	}
	if l == nil {
		return nil, nil, nil, ErrInvalidRecord
	}
	lp, err := decodePoint(l.b[:])
	if err != nil {
		return nil, nil, nil, ErrInvalidRecord
	}
	x, err := decodePoint(shareP)
	if err != nil {
		return nil, nil, nil, err
	}
	shareV, err := maskedShare(y, w0.b[:], pointN)
	if err != nil {
		return nil, nil, nil, err
	}
	u, err := unmask(x, w0.b[:], pointM) // X - w0·M
	if err != nil {
		return nil, nil, nil, err
	}
	z, err := nistec.NewP256Point().ScalarMult(u, y)
	if err != nil {
		return nil, nil, nil, err
	}
	v, err := nistec.NewP256Point().ScalarMult(lp, y)
	if err != nil {
		return nil, nil, nil, err
	}
	t := &trace{shareP: append([]byte(nil), shareP...), shareV: shareV}
	if err := derive(t, context, idProver, idVerifier, w0.b[:], z, v); err != nil {
		t.wipe()
		return nil, nil, nil, err
	}
	return &Verifier{t: t}, append(ShareV(nil), shareV...), append(ConfirmV(nil), t.confirmV...), nil
}

// Close wipes every secret the Verifier holds and consumes it: a later Finish
// returns [ErrFinished]. It is idempotent and safe for concurrent use. Use it
// as defer v.Close() right after [RespondVerifier] succeeds, so that an
// abandoned exchange (the usual shape of a guessing attacker) does not leave
// the keys and the transcript behind; [Verifier.Finish] calls it itself.
func (v *Verifier) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closeLocked()
}

func (v *Verifier) closeLocked() {
	v.finished = true
	if v.t != nil {
		v.t.wipe()
	}
}

// Finish checks confirmP in constant time and, only if it is correct, returns
// the 32-byte shared key. Errors: [ErrInvalidMessage], [ErrConfirmationFailed],
// [ErrFinished], [ErrInvalidState] (a zero-value Verifier). Finish may be called
// once, also across goroutines; the state is consumed whatever the outcome.
func (v *Verifier) Finish(confirmP ConfirmP) (kShared []byte, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.finished {
		return nil, ErrFinished
	}
	if v.t == nil {
		return nil, ErrInvalidState
	}
	defer v.closeLocked()
	if len(confirmP) != ConfirmSize {
		return nil, ErrInvalidMessage
	}
	if !hmac.Equal(confirmP, v.t.confirmP) {
		return nil, ErrConfirmationFailed
	}
	return append([]byte(nil), v.t.kShared...), nil
}
