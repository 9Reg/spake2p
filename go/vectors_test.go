package spake2p

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"filippo.io/nistec"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadVector(t testing.TB) (v struct {
	Context, IDProver, IDVerifier                            []byte
	W0, W1, L, X, ShareP, Y, ShareV, Z, V, TT                []byte
	KMain, KConfirmP, KConfirmV, ConfirmP, ConfirmV, KShared []byte
}) {
	t.Helper()
	raw, err := os.ReadFile("../vectors/rfc9383-p256-sha256-hkdf-hmac.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	h := func(k string) []byte { return unhex(t, m[k]) }
	v.Context = []byte(m["context"]) // the vector gives the context as text
	v.IDProver, v.IDVerifier = []byte(m["idProver"]), []byte(m["idVerifier"])
	v.W0, v.W1, v.L, v.X, v.ShareP = h("w0"), h("w1"), h("L"), h("x"), h("shareP")
	v.Y, v.ShareV, v.Z, v.V, v.TT = h("y"), h("shareV"), h("Z"), h("V"), h("TT")
	v.KMain, v.KConfirmP, v.KConfirmV = h("K_main"), h("K_confirmP"), h("K_confirmV")
	v.ConfirmP, v.ConfirmV, v.KShared = h("confirmP"), h("confirmV"), h("K_shared")
	return v
}

func eq(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s mismatch\n got %x\nwant %x", name, got, want)
	}
}

// Test 1: RFC 9383 Appendix C, byte for byte, with x and y injected.
func TestRFCVector(t *testing.T) {
	v := loadVector(t)
	w0, err := ParseW0(v.W0)
	if err != nil {
		t.Fatal(err)
	}
	w1, err := ParseW1(v.W1)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Register(w1)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "L", l.Bytes(), v.L)

	prover, shareP, err := startProver(v.Context, v.IDProver, v.IDVerifier, w0, w1, bytes.Clone(v.X))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "shareP", shareP, v.ShareP)

	ver, shareV, confirmV, err := respondVerifier(v.Context, v.IDProver, v.IDVerifier, w0, l, shareP, bytes.Clone(v.Y))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "shareV", shareV, v.ShareV)
	eq(t, "confirmV", confirmV, v.ConfirmV)
	tr := ver.t
	eq(t, "verifier Z", tr.z, v.Z)
	eq(t, "verifier V", tr.v, v.V)
	eq(t, "verifier TT", tr.tt, v.TT)
	eq(t, "verifier K_main", tr.kMain, v.KMain)
	eq(t, "verifier K_confirmP", tr.kConfirmP, v.KConfirmP)
	eq(t, "verifier K_confirmV", tr.kConfirmV, v.KConfirmV)
	eq(t, "verifier confirmP", tr.confirmP, v.ConfirmP)
	eq(t, "verifier K_shared", tr.kShared, v.KShared)

	pt, err := prover.finish(shareV, confirmV)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "prover Z", pt.z, v.Z)
	eq(t, "prover V", pt.v, v.V)
	eq(t, "prover TT", pt.tt, v.TT)
	eq(t, "prover K_main", pt.kMain, v.KMain)
	eq(t, "prover K_confirmP", pt.kConfirmP, v.KConfirmP)
	eq(t, "prover K_confirmV", pt.kConfirmV, v.KConfirmV)
	eq(t, "prover confirmP", pt.confirmP, v.ConfirmP)
	eq(t, "prover K_shared", pt.kShared, v.KShared)

	k, err := ver.Finish(pt.confirmP)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "verifier Finish K_shared", k, v.KShared)
}

// pair holds a registered password for the remaining tests.
type pair struct {
	w0 *W0
	w1 *W1
	l  *L
}

func register(t testing.TB, seed byte) pair {
	t.Helper()
	out := make([]byte, PBKDFOutputSize)
	for i := range out {
		out[i] = seed + byte(i)*7
	}
	w0, w1, err := W0W1FromPBKDFOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Register(w1)
	if err != nil {
		t.Fatal(err)
	}
	return pair{w0, w1, l}
}

var (
	ctx = []byte("test context")
	idP = []byte("client")
	idV = []byte("server")
)

// Test 2: round trip.
func TestRoundTrip(t *testing.T) {
	for i := 0; i < 20; i++ {
		pw := register(t, 1)
		p, shareP, err := StartProver(ctx, idP, idV, pw.w0, pw.w1)
		if err != nil {
			t.Fatal(err)
		}
		v, shareV, confirmV, err := RespondVerifier(ctx, idP, idV, pw.w0, pw.l, shareP)
		if err != nil {
			t.Fatal(err)
		}
		confirmP, kp, err := p.Finish(shareV, confirmV)
		if err != nil {
			t.Fatal(err)
		}
		kv, err := v.Finish(confirmP)
		if err != nil {
			t.Fatal(err)
		}
		if len(kp) != KeySize || !bytes.Equal(kp, kv) {
			t.Fatalf("keys differ: %x vs %x", kp, kv)
		}
	}
}

func TestEmptyContextAndIdentities(t *testing.T) {
	pw := register(t, 2)
	p, shareP, _ := StartProver(nil, nil, nil, pw.w0, pw.w1)
	v, shareV, confirmV, err := RespondVerifier(nil, nil, nil, pw.w0, pw.l, shareP)
	if err != nil {
		t.Fatal(err)
	}
	confirmP, kp, err := p.Finish(shareV, confirmV)
	if err != nil {
		t.Fatal(err)
	}
	if kv, err := v.Finish(confirmP); err != nil || !bytes.Equal(kp, kv) {
		t.Fatal("empty-input round trip failed")
	}
}

// Test 3: wrong password.
func TestWrongPassword(t *testing.T) {
	good, bad := register(t, 1), register(t, 2)
	for _, c := range []struct {
		name string
		prov pair
	}{{"both wrong", bad}, {"w0 right, w1 wrong", pair{good.w0, bad.w1, nil}}, {"w0 wrong, w1 right", pair{bad.w0, good.w1, nil}}} {
		p, shareP, _ := StartProver(ctx, idP, idV, c.prov.w0, c.prov.w1)
		v, shareV, confirmV, err := RespondVerifier(ctx, idP, idV, good.w0, good.l, shareP)
		if err != nil {
			t.Fatal(err)
		}
		cp, k, err := p.Finish(shareV, confirmV)
		if err != ErrConfirmationFailed || cp != nil || k != nil {
			t.Errorf("%s: got %v %x %x", c.name, err, cp, k)
		}
		// The Verifier's own Finish with a junk tag also fails.
		if _, err := v.Finish(make([]byte, 32)); err != ErrConfirmationFailed {
			t.Errorf("%s: verifier: %v", c.name, err)
		}
	}
}

func flip(b []byte, i int) []byte {
	c := bytes.Clone(b)
	c[i] ^= 0x01
	return c
}

// Test 4: a flipped bit anywhere in a message fails.
func TestTampering(t *testing.T) {
	pw := register(t, 1)
	run := func(mutP, mutV, mutCV, mutCP func([]byte) []byte) (pErr, vErr error) {
		p, shareP, _ := StartProver(ctx, idP, idV, pw.w0, pw.w1)
		v, shareV, confirmV, err := RespondVerifier(ctx, idP, idV, pw.w0, pw.l, mutP(shareP))
		if err != nil {
			return nil, err
		}
		confirmP, _, err := p.Finish(mutV(shareV), mutCV(confirmV))
		if err != nil {
			return err, nil
		}
		_, err = v.Finish(mutCP(confirmP))
		return nil, err
	}
	id := func(b []byte) []byte { return b }
	if a, b := run(id, id, id, id); a != nil || b != nil {
		t.Fatalf("untampered run failed: %v %v", a, b)
	}
	// Flip a bit in shareP's y (stays off-curve with overwhelming probability
	// or leads to a different key): either way the exchange must fail.
	for _, bit := range []int{1, 32, 33, 64} {
		if a, b := run(func(x []byte) []byte { return flip(x, bit) }, id, id, id); a == nil && b == nil {
			t.Errorf("shareP byte %d: tampering accepted", bit)
		}
		if a, b := run(id, func(x []byte) []byte { return flip(x, bit) }, id, id); a == nil && b == nil {
			t.Errorf("shareV byte %d: tampering accepted", bit)
		}
	}
	for _, bit := range []int{0, 15, 31} {
		if a, b := run(id, id, func(x []byte) []byte { return flip(x, bit) }, id); a != ErrConfirmationFailed {
			t.Errorf("confirmV byte %d: %v %v", bit, a, b)
		}
		if a, b := run(id, id, id, func(x []byte) []byte { return flip(x, bit) }); b != ErrConfirmationFailed {
			t.Errorf("confirmP byte %d: %v %v", bit, a, b)
		}
	}
	// Wrong-length confirmations.
	if a, _ := run(id, id, func(x []byte) []byte { return x[:31] }, id); a != ErrInvalidMessage {
		t.Errorf("short confirmV: %v", a)
	}
	if _, b := run(id, id, id, func(x []byte) []byte { return append(bytes.Clone(x), 0) }); b != ErrInvalidMessage {
		t.Errorf("long confirmP: %v", b)
	}
}

// Test 5: context and identity binding.
func TestBinding(t *testing.T) {
	pw := register(t, 1)
	type ids struct{ c, p, v []byte }
	base := ids{ctx, idP, idV}
	for name, other := range map[string]ids{
		"context":    {[]byte("other"), idP, idV},
		"idProver":   {ctx, []byte("clienT"), idV},
		"idVerifier": {ctx, idP, []byte("serveR")},
		"empty ctx":  {nil, idP, idV},
	} {
		p, shareP, _ := StartProver(base.c, base.p, base.v, pw.w0, pw.w1)
		_, shareV, confirmV, err := RespondVerifier(other.c, other.p, other.v, pw.w0, pw.l, shareP)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.Finish(shareV, confirmV); err != ErrConfirmationFailed {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// Test 6: invalid points.
func TestInvalidPoints(t *testing.T) {
	pw := register(t, 1)
	good := func() (*Prover, []byte) {
		p, s, _ := StartProver(ctx, idP, idV, pw.w0, pw.w1)
		return p, s
	}
	_, goodShare := good()

	compressed := pointM.BytesCompressed()
	offCurve := bytes.Clone(goodShare)
	offCurve[64] ^= 0x01
	hybrid := bytes.Clone(goodShare)
	hybrid[0] = 0x06 | (goodShare[64] & 1)
	badPrefix := bytes.Clone(goodShare)
	badPrefix[0] = 0x05
	identity := make([]byte, PointSize)
	cases := map[string][]byte{
		"compressed 02/03":  compressed,
		"compressed padded": append(bytes.Clone(compressed), make([]byte, 32)...),
		"single 0x00":       {0x00},
		"all-zero 65":       identity,
		"hybrid":            hybrid,
		"prefix 0x05":       badPrefix,
		"short":             goodShare[:64],
		"long":              append(bytes.Clone(goodShare), 0),
		"empty":             nil,
		"off curve":         offCurve,
		"x >= p":            append([]byte{0x04}, bytes.Repeat([]byte{0xff}, 64)...),
		// SP-4: the valid point with x = 0, written as x + p.
		"non-canonical x+p": unhex(t, nonCanonicalHex),
	}
	// A share equal to w0·M (so X - w0·M is the identity) and w0·N.
	w0M := mul(t, pointM, pw.w0.b[:]).Bytes()
	w0N := mul(t, pointN, pw.w0.b[:]).Bytes()

	for name, bad := range cases {
		if _, _, _, err := RespondVerifier(ctx, idP, idV, pw.w0, pw.l, bad); err != ErrInvalidPoint {
			t.Errorf("verifier shareP %s: %v", name, err)
		}
		if _, err := ParseL(bad); err != ErrInvalidRecord {
			t.Errorf("ParseL %s: %v", name, err)
		}
		p, _ := good()
		if _, _, err := p.Finish(bad, make([]byte, 32)); err != ErrInvalidPoint {
			t.Errorf("prover shareV %s: %v", name, err)
		}
	}
	if _, _, _, err := RespondVerifier(ctx, idP, idV, pw.w0, pw.l, w0M); err != ErrInvalidPoint {
		t.Errorf("verifier accepted X = w0*M: %v", err)
	}
	p, _ := good()
	if _, _, err := p.Finish(w0N, make([]byte, 32)); err != ErrInvalidPoint {
		t.Errorf("prover accepted Y = w0*N: %v", err)
	}
	// Negation: -L and -X are valid points and must not crash; the exchange
	// then simply fails or yields different keys, never the identity.
	neg := nistec.NewP256Point()
	lp, _ := decodePoint(pw.l.b[:])
	negL, err := ParseL(neg.Negate(lp).Bytes())
	if err != nil {
		t.Fatalf("valid negated L rejected: %v", err)
	}
	if _, _, _, err := RespondVerifier(ctx, idP, idV, pw.w0, negL, goodShare); err != nil {
		t.Errorf("valid negated L rejected by respond: %v", err)
	}
}

const (
	// SP-4: the valid point with x = 0 and y = 66485c78..., with x written as
	// x + p (non-canonical), and its canonical twin.
	nonCanonicalHex = "04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4"
	canonicalHex    = "040000000000000000000000000000000000000000000000000000000000000000" + "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4"
)

// SP-4: the canonical encoding is accepted as shareP, shareV and L; the
// non-canonical twin is rejected in all three places (see TestInvalidPoints).
func TestCanonicalTwinAccepted(t *testing.T) {
	pw := register(t, 1)
	canon := unhex(t, canonicalHex)
	if _, err := ParseL(canon); err != nil {
		t.Errorf("canonical L rejected: %v", err)
	}
	if _, err := ParseL(unhex(t, nonCanonicalHex)); err != ErrInvalidRecord {
		t.Errorf("non-canonical L: %v", err)
	}
	if _, _, _, err := RespondVerifier(ctx, idP, idV, pw.w0, pw.l, canon); err != nil {
		t.Errorf("canonical shareP rejected: %v", err)
	}
	if _, _, _, err := RespondVerifier(ctx, idP, idV, pw.w0, pw.l, unhex(t, nonCanonicalHex)); err != ErrInvalidPoint {
		t.Errorf("non-canonical shareP: %v", err)
	}
	p, _, _ := StartProver(ctx, idP, idV, pw.w0, pw.w1)
	if _, _, err := p.Finish(canon, make([]byte, 32)); err != ErrConfirmationFailed {
		t.Errorf("canonical shareV not accepted as a point: %v", err)
	}
	p, _, _ = StartProver(ctx, idP, idV, pw.w0, pw.w1)
	if _, _, err := p.Finish(unhex(t, nonCanonicalHex), make([]byte, 32)); err != ErrInvalidPoint {
		t.Errorf("non-canonical shareV: %v", err)
	}
}

// Test 7: registration.
func TestRegistration(t *testing.T) {
	n := new(big.Int).SetBytes(p256Order)
	// A known reduction: the all-ones 40-byte value, and n+5 (>= n, fits 40 B).
	for _, c := range []struct {
		name string
		val  *big.Int
	}{
		{"max 40 bytes", new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 320), big.NewInt(1))},
		{"n+5", new(big.Int).Add(n, big.NewInt(5))},
		{"n", new(big.Int).Set(n)}, // reduces to zero
		{"n-1", new(big.Int).Sub(n, big.NewInt(1))},
		{"2n+9", new(big.Int).Add(new(big.Int).Lsh(n, 1), big.NewInt(9))},
	} {
		out := make([]byte, 80)
		c.val.FillBytes(out[:40])
		new(big.Int).SetInt64(1).FillBytes(out[40:]) // w1 half = 1
		w0, w1, err := W0W1FromPBKDFOutput(out)
		want := new(big.Int).Mod(c.val, n)
		if want.Sign() == 0 {
			if err != ErrInvalidPBKDFOutput {
				t.Errorf("%s: zero w0 accepted: %v", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := new(big.Int).SetBytes(w0.Bytes()); got.Cmp(want) != 0 {
			t.Errorf("%s: w0 = %x, want %x", c.name, got, want)
		}
		if got := new(big.Int).SetBytes(w1.Bytes()); got.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("%s: w1 = %x", c.name, got)
		}
	}
	// Second half is reduced too.
	out := make([]byte, 80)
	out[39] = 1
	new(big.Int).Add(n, big.NewInt(7)).FillBytes(out[40:])
	if _, w1, err := W0W1FromPBKDFOutput(out); err != nil || new(big.Int).SetBytes(w1.Bytes()).Int64() != 7 {
		t.Errorf("w1 reduction: %v", err)
	}
	// Lengths.
	for _, l := range []int{0, 1, 32, 64, 79, 81, 160} {
		if _, _, err := W0W1FromPBKDFOutput(make([]byte, l)); err != ErrInvalidPBKDFOutput {
			t.Errorf("length %d accepted: %v", l, err)
		}
	}
	// Scalar parsing.
	nb := bytes.Clone(p256Order)
	nm1 := new(big.Int).Sub(n, big.NewInt(1)).FillBytes(make([]byte, 32))
	np1 := new(big.Int).Add(n, big.NewInt(1)).FillBytes(make([]byte, 32))
	one := new(big.Int).SetInt64(1).FillBytes(make([]byte, 32))
	for name, c := range map[string]struct {
		in []byte
		ok bool
	}{
		"zero": {make([]byte, 32), false}, "one": {one, true}, "n-1": {nm1, true},
		"n": {nb, false}, "n+1": {np1, false}, "all ff": {bytes.Repeat([]byte{0xff}, 32), false},
		"31 bytes": {one[1:], false}, "33 bytes": {append([]byte{0}, one...), false}, "nil": {nil, false},
	} {
		s0, err := ParseW0(c.in)
		if c.ok != (err == nil) || (err != nil && err != ErrInvalidScalar) || (c.ok && s0 == nil) {
			t.Errorf("ParseW0 %s: %v", name, err)
		}
		s1, err := ParseW1(c.in)
		if c.ok != (err == nil) || (err != nil && err != ErrInvalidScalar) || (c.ok && s1 == nil) {
			t.Errorf("ParseW1 %s: %v", name, err)
		}
	}
	if _, err := Register(nil); err != ErrInvalidScalar {
		t.Errorf("Register(nil): %v", err)
	}
}

func TestPBKDFInput(t *testing.T) {
	got := PBKDFInput([]byte("pw"), []byte("a"), nil)
	want := append(append(append([]byte{2, 0, 0, 0, 0, 0, 0, 0}, "pw"...), 1, 0, 0, 0, 0, 0, 0, 0), append([]byte("a"), make([]byte, 8)...)...)
	eq(t, "PBKDFInput", got, want)
}

func TestFinishSingleUse(t *testing.T) {
	pw := register(t, 1)
	p, shareP, _ := StartProver(ctx, idP, idV, pw.w0, pw.w1)
	v, shareV, confirmV, _ := RespondVerifier(ctx, idP, idV, pw.w0, pw.l, shareP)
	confirmP, _, err := p.Finish(shareV, confirmV)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Finish(shareV, confirmV); err != ErrFinished {
		t.Errorf("prover second Finish: %v", err)
	}
	if _, err := v.Finish(confirmP); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Finish(confirmP); err != ErrFinished {
		t.Errorf("verifier second Finish: %v", err)
	}
	// A failed Finish also consumes the state.
	p2, shareP2, _ := StartProver(ctx, idP, idV, pw.w0, pw.w1)
	_, sv, cv, _ := RespondVerifier(ctx, idP, idV, pw.w0, pw.l, shareP2)
	if _, _, err := p2.Finish(sv, make([]byte, 32)); err != ErrConfirmationFailed {
		t.Fatal(err)
	}
	if _, _, err := p2.Finish(sv, cv); err != ErrFinished {
		t.Errorf("retry after failure: %v", err)
	}
}

func TestSecretsWiped(t *testing.T) {
	pw := register(t, 1)
	p, shareP, _ := StartProver(ctx, idP, idV, pw.w0, pw.w1)
	v, shareV, confirmV, _ := RespondVerifier(ctx, idP, idV, pw.w0, pw.l, shareP)
	if _, _, err := p.Finish(shareV, confirmV); err != nil {
		t.Fatal(err)
	}
	zero := make([]byte, 32)
	if !bytes.Equal(p.x, zero) || !bytes.Equal(p.w0, zero) || !bytes.Equal(p.w1, zero) {
		t.Error("prover secrets not wiped")
	}
	tr := v.t
	if _, err := v.Finish(make([]byte, 32)); err == nil {
		t.Fatal("expected failure")
	}
	if !bytes.Equal(tr.kShared, zero) || !bytes.Equal(tr.kMain, zero) {
		t.Error("verifier keys not wiped")
	}
}

func TestErrorTextHasNoSecrets(t *testing.T) {
	for _, e := range []error{ErrInvalidScalar, ErrInvalidPBKDFOutput, ErrInvalidPoint, ErrInvalidMessage, ErrConfirmationFailed, ErrFinished, ErrRandom, ErrInvalidRecord, ErrInvalidState} {
		if len(e.Error()) > 60 {
			t.Errorf("suspiciously long error text: %q", e)
		}
	}
}

func mul(t testing.TB, p *nistec.P256Point, s []byte) *nistec.P256Point {
	t.Helper()
	r, err := nistec.NewP256Point().ScalarMult(p, s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// SP-1: an all-zero w0 or w1 is rejected by every entry point, however it was
// produced; Zero() leaves a value that the check catches.
func TestZeroScalarsRejected(t *testing.T) {
	pw := register(t, 1)
	_, goodShare, _ := StartProver(ctx, idP, idV, pw.w0, pw.w1)
	zeroW0, zeroW1 := new(W0), new(W1)
	wiped0, wiped1 := &W0{pw.w0.b}, &W1{pw.w1.b}
	wiped0.Zero()
	wiped1.Zero()
	for name, w0 := range map[string]*W0{"new": zeroW0, "wiped": wiped0, "nil": nil} {
		if _, _, _, err := RespondVerifier(ctx, idP, idV, w0, pw.l, goodShare); err != ErrInvalidScalar {
			t.Errorf("RespondVerifier w0 %s: %v", name, err)
		}
		if _, _, err := StartProver(ctx, idP, idV, w0, pw.w1); err != ErrInvalidScalar {
			t.Errorf("StartProver w0 %s: %v", name, err)
		}
	}
	for name, w1 := range map[string]*W1{"new": zeroW1, "wiped": wiped1, "nil": nil} {
		if _, _, err := StartProver(ctx, idP, idV, pw.w0, w1); err != ErrInvalidScalar {
			t.Errorf("StartProver w1 %s: %v", name, err)
		}
		if _, err := Register(w1); err != ErrInvalidScalar {
			t.Errorf("Register w1 %s: %v", name, err)
		}
	}
	if !isZero(wiped0.b[:]) || isZero(pw.w0.b[:]) {
		t.Error("isZero wrong")
	}
	// Marshalling an invalid value fails too.
	if _, err := zeroW0.MarshalBinary(); err != ErrInvalidScalar {
		t.Errorf("MarshalBinary zero W0: %v", err)
	}
	if _, err := zeroW1.MarshalJSON(); err != ErrInvalidScalar {
		t.Errorf("MarshalJSON zero W1: %v", err)
	}
}

// SP-1: a stored struct holding a W0, W1 or L cannot silently decode to a zero
// value: the hex form goes through the parsers, and a missing field stays zero
// and is rejected at use.
func TestJSONCannotYieldZeroScalar(t *testing.T) {
	pw := register(t, 1)
	type record struct {
		W0 W0 `json:"w0"`
		W1 W1 `json:"w1"`
		L  L  `json:"l"`
	}
	in := record{*pw.w0, *pw.w1, *pw.l}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out record
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Error("JSON round trip changed the record")
	}
	zero := `"` + string(bytes.Repeat([]byte("0"), 64)) + `"`
	for name, doc := range map[string]string{
		"all-zero w0": `{"w0":` + zero + `}`,
		"all-zero w1": `{"w1":` + zero + `}`,
		"empty obj":   `{"w0":{}}`,
		"number":      `{"w0":0}`,
		"short hex":   `{"w0":"00"}`,
		"bad hex":     `{"w1":"zz"}`,
		"zero L":      `{"l":"` + string(bytes.Repeat([]byte("0"), 130)) + `"}`,
		"w0 = n":      `{"w0":"` + hex.EncodeToString(p256Order) + `"}`,
	} {
		var r record
		if err := json.Unmarshal([]byte(doc), &r); err == nil {
			t.Errorf("%s: decoded without error", name)
		}
	}
	// A field that is absent stays zero, and every entry point rejects it.
	var absent record
	if err := json.Unmarshal([]byte(`{}`), &absent); err != nil {
		t.Fatal(err)
	}
	if _, _, err := StartProver(ctx, idP, idV, &absent.W0, &absent.W1); err != ErrInvalidScalar {
		t.Errorf("absent field accepted: %v", err)
	}
	_, goodShare, _ := StartProver(ctx, idP, idV, pw.w0, pw.w1)
	if _, _, _, err := RespondVerifier(ctx, idP, idV, pw.w0, &absent.L, goodShare); err != ErrInvalidRecord {
		t.Errorf("absent L accepted: %v", err)
	}
	// Binary form.
	var w W0
	if err := w.UnmarshalBinary(make([]byte, 32)); err != ErrInvalidScalar {
		t.Errorf("UnmarshalBinary zero: %v", err)
	}
	b, _ := pw.w0.MarshalBinary()
	if err := w.UnmarshalBinary(b); err != nil || !bytes.Equal(w.Bytes(), b) {
		t.Errorf("UnmarshalBinary: %v", err)
	}
}

// SP-5: zero-value states return a sentinel and never panic.
func TestZeroValueStates(t *testing.T) {
	var v Verifier
	if _, err := v.Finish(make([]byte, 32)); err != ErrInvalidState {
		t.Errorf("zero Verifier: %v", err)
	}
	var p Prover
	if _, _, err := p.Finish(make([]byte, 65), make([]byte, 32)); err != ErrInvalidState {
		t.Errorf("zero Prover: %v", err)
	}
	var v2 Verifier
	v2.Close()
	if _, err := v2.Finish(nil); err != ErrFinished {
		t.Errorf("closed zero Verifier: %v", err)
	}
	var p2 Prover
	p2.Close()
	if _, _, err := p2.Finish(nil, nil); err != ErrFinished {
		t.Errorf("closed zero Prover: %v", err)
	}
}

// SP-6: a bad stored L is its own error, never a bad-peer error.
func TestInvalidRecord(t *testing.T) {
	pw := register(t, 1)
	_, shareP, _ := StartProver(ctx, idP, idV, pw.w0, pw.w1)
	for name, l := range map[string]*L{"nil": nil, "zero": new(L)} {
		if _, _, _, err := RespondVerifier(ctx, idP, idV, pw.w0, l, shareP); err != ErrInvalidRecord {
			t.Errorf("%s L: %v", name, err)
		}
	}
	bad := pw.l.Bytes()
	bad[64] ^= 1 // off curve
	if _, err := ParseL(bad); err != ErrInvalidRecord {
		t.Errorf("off-curve L: %v", err)
	}
	if l, err := ParseL(pw.l.Bytes()); err != nil || !bytes.Equal(l.Bytes(), pw.l.Bytes()) {
		t.Errorf("valid L: %v", err)
	}
}

// SP-3: Close wipes an abandoned state, is idempotent, and consumes it.
func TestClose(t *testing.T) {
	pw := register(t, 1)
	p, shareP, _ := StartProver(ctx, idP, idV, pw.w0, pw.w1)
	v, shareV, confirmV, err := RespondVerifier(ctx, idP, idV, pw.w0, pw.l, shareP)
	if err != nil {
		t.Fatal(err)
	}
	tr := v.t
	if isZero(tr.kShared) || isZero(tr.kMain) {
		t.Fatal("keys already zero")
	}
	v.Close()
	v.Close()
	p.Close()
	p.Close()
	zero := make([]byte, 32)
	for name, b := range map[string][]byte{"kShared": tr.kShared, "kMain": tr.kMain, "kConfirmP": tr.kConfirmP,
		"kConfirmV": tr.kConfirmV, "x": p.x, "w0": p.w0, "w1": p.w1} {
		if !bytes.Equal(b, zero) && !isZero(b) {
			t.Errorf("%s not wiped", name)
		}
	}
	if !isZero(tr.tt) || !isZero(tr.z) || !isZero(tr.v) {
		t.Error("transcript not wiped")
	}
	if _, err := v.Finish(tr.confirmP); err != ErrFinished {
		t.Errorf("Finish after Close: %v", err)
	}
	if _, _, err := p.Finish(shareV, confirmV); err != ErrFinished {
		t.Errorf("prover Finish after Close: %v", err)
	}
}

// SP-7: concurrent Finish calls with the right tag give exactly one success,
// and the successful key is never a wiped one.
func TestConcurrentFinish(t *testing.T) {
	pw := register(t, 1)
	for round := 0; round < 50; round++ {
		p, shareP, _ := StartProver(ctx, idP, idV, pw.w0, pw.w1)
		v, shareV, confirmV, err := RespondVerifier(ctx, idP, idV, pw.w0, pw.l, shareP)
		if err != nil {
			t.Fatal(err)
		}
		var confirmP ConfirmP
		var wg sync.WaitGroup
		var okP, okV atomic.Int32
		type res struct {
			cp ConfirmP
			k  []byte
		}
		resP := make(chan res, 8)
		resV := make(chan []byte, 8)
		start := make(chan struct{})
		for i := 0; i < 8; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				if cp, k, err := p.Finish(shareV, confirmV); err == nil {
					okP.Add(1)
					resP <- res{cp, k}
				}
			}()
			go func() {
				defer wg.Done()
				<-start
				// The right tag needs the prover's output; compute it from the verifier's trace.
				if k, err := v.Finish(v.t.confirmP); err == nil {
					okV.Add(1)
					resV <- k
				}
			}()
		}
		close(start)
		wg.Wait()
		close(resP)
		close(resV)
		if okP.Load() != 1 || okV.Load() != 1 {
			t.Fatalf("round %d: successes prover %d verifier %d", round, okP.Load(), okV.Load())
		}
		r := <-resP
		confirmP = r.cp
		kv := <-resV
		if isZero(kv) || isZero(r.k) || !bytes.Equal(kv, r.k) || len(confirmP) != ConfirmSize {
			t.Fatalf("round %d: bad keys", round)
		}
	}
}
