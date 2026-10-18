package spake2p

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
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
	w0, err := ParseScalar(v.W0)
	if err != nil {
		t.Fatal(err)
	}
	w1, err := ParseScalar(v.W1)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Register(w1)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "L", l, v.L)

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
	w0, w1 *Scalar
	l      []byte
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
	}
	// A share equal to w0·M (so X - w0·M is the identity) and w0·N.
	w0M := mul(t, pointM, pw.w0.b[:]).Bytes()
	w0N := mul(t, pointN, pw.w0.b[:]).Bytes()

	for name, bad := range cases {
		if _, _, _, err := RespondVerifier(ctx, idP, idV, pw.w0, pw.l, bad); err != ErrInvalidPoint {
			t.Errorf("verifier shareP %s: %v", name, err)
		}
		if _, _, _, err := RespondVerifier(ctx, idP, idV, pw.w0, bad, goodShare); err != ErrInvalidPoint {
			t.Errorf("verifier L %s: %v", name, err)
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
	lp, _ := decodePoint(pw.l)
	negL := neg.Negate(lp).Bytes()
	if _, _, _, err := RespondVerifier(ctx, idP, idV, pw.w0, negL, goodShare); err != nil {
		t.Errorf("valid negated L rejected: %v", err)
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
		s, err := ParseScalar(c.in)
		if c.ok != (err == nil) || (err != nil && err != ErrInvalidScalar) || (c.ok && s == nil) {
			t.Errorf("ParseScalar %s: %v", name, err)
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
	for _, e := range []error{ErrInvalidScalar, ErrInvalidPBKDFOutput, ErrInvalidPoint, ErrInvalidMessage, ErrConfirmationFailed, ErrFinished, ErrRandom} {
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
