# Core security review — `ee79b26` (core-1), 2026-10-18

Read before changing `rust/src/lib.rs`, `go/spake2p.go` or SPEC.md's Validation/Secrets sections,
and before integrating the library into a pairing flow (its Integration advice). Reviewer: fresh
Opus 5.5 context, repo mounted read-only. Stored verbatim; the reviewer's text wins over any
annotation beside it. Scope: rust/ and go/ at `ee79b26`; ffi/ and swift/ were not in it.

---

**Verdict: APPROVE WITH CHANGES.** 1 major, 5 minor, 6 nit. The protocol core follows RFC 9383 in both languages. That covers the transcript layout and the 8-byte little-endian length prefixes, uncompressed M and N in TT, HKDF with a nil salt and the info strings "ConfirmationKeys" (64 bytes) and "SharedKey" (32 bytes), confirmP = MAC(K_confirmP, shareV) and confirmV = MAC(K_confirmV, shareP). The ordering is right: the Prover returns confirmP and K_shared only after confirmV verifies, and the Verifier releases K_shared only after confirmP verifies. Tags are compared in constant time. Both decoders reject compressed, hybrid, off-curve and non-canonical points. A probe confirmed that a valid point with x=0, re-encoded as x+p, is rejected by Rust (NotOnCurve) and by Go (ErrInvalidPoint). Scalar multiplication is constant-time in both: primeorder `lincomb` with constant-time table select, and nistec. Both random samplers use uniform rejection sampling. The 40-byte reduction is correct and constant-time in both: Horner over `p256::Scalar`, and `bigmod.Mod`. Python independently confirms the Rust constants 2^312 mod n and (2^320−1) mod n. `cargo test` and `go test ./...` pass at ee79b26. One real defect: the Go library accepts w0 = 0, which the SPEC forbids, and that turns an active run into an offline dictionary attack.

## Findings

### SP-1 (major, CONFIRMED): Go accepts the zero-value `Scalar` as w0
- **Evidence:** go/spake2p.go:164-169 says "The zero Scalar is invalid", but nothing enforces it.
  - `startProver` (go/spake2p.go:411) and `respondVerifier` (go/spake2p.go:520) check only `w0 == nil`.
  - `maskedShare` and `unmask` (go/spake2p.go:299-326) happily multiply by an all-zero scalar.
  - A probe ran `StartProver` and `RespondVerifier` with `new(spake2p.Scalar)` as w0 and a valid w1/L. Both completed, with equal keys and no error.
  - Rust cannot construct a zero `W0` (lib.rs:297-305, 331), so the two libraries diverge here. interop/run.sh never exercises it.
- **How a zero w0 gets in silently:**
  - `encoding/json` (or gob) skips `Scalar`'s unexported field, so a stored record struct holding a `spake2p.Scalar` decodes to zero without an error.
  - `Scalar.Zero()` (go/spake2p.go:196) is documented as "unusable afterwards", but nothing stops reuse. The interop driver calls it on w1 at go/cmd/interop-driver/main.go:155.
- **Attack:** with w0 = 0 at the Verifier, Y = y·P and the Verifier computes V = y·L = w1·Y. An attacker acting as Prover sends X = x·P and receives Y and confirmV. It computes Z = x·Y, and w0 = 0 in TT is known. For each candidate password it derives w1', computes V' = w1'·Y and checks confirmV offline. One run yields a full offline brute force; for a 6-digit code that means instant recovery. An honest Prover with a real w0 would fail against such a Verifier, so this is mostly caught in testing, unless both sides share the same record-loading bug.
- **Fix:**
  - Reject an all-zero w0 or w1 in `StartProver`, `RespondVerifier` and `Register`, using a constant-time OR over the bytes, or `bigmod` `IsZero`.
  - Make `Zero()` leave the value detectably invalid, which the check above then catches.
  - Add a test that passes `new(Scalar)` to each entry point.
  - Consider `MarshalBinary`/`UnmarshalBinary` on `Scalar`, so serialization goes through `ParseScalar`.

### SP-2 (minor, CONFIRMED): The library never says what counts as an "attempt"
- **Evidence:** lib.rs:66-67, rust/README.md:43, go/README.md:33 and README.md:8 all say "rate-limit attempts" without defining one.
- **Why it matters:** an attacker gets its one guess per run before `Verifier::finish` ever runs, in two ways:
  - (a) It receives confirmV from `respond` and tests the guess offline.
  - (b) It sends X = w0'·M. A correct guess makes `respond` itself fail (`IdentityPoint`, lib.rs:694; go/spake2p.go:322), and a wrong one produces a normal reply.

  Either way the attacker just walks away and never sends confirmP. An integration that counts only `Verifier.finish` failures gives unlimited guesses: 10^6 codes means recovery in minutes.
- **Fix:** document in both packages that every call to `respond`/`RespondVerifier`, whatever its outcome, consumes one attempt. Say the same on the Prover side for each `finish` against an unauthenticated peer.

### SP-3 (minor, CONFIRMED): Zeroisation claims exceed the code, and Go never wipes an abandoned state
- **Go:** wiping happens only inside `Finish` (go/spake2p.go:461, 564). A `Verifier` that is never finished keeps `kShared`, `kConfirmP`, `tt` (which contains w0) and `kMain` until garbage collection. The same goes for an unfinished `Prover` (x, w0, w1). An abandoned Verifier is exactly the attacker's flow in SP-2. The nistec points (u, z, v, w0·M) are never wiped.
- **Rust:** `ProjectivePoint` values z, v and diff (lib.rs:602-605, 694-697) are plain copies on the stack and are not zeroised, although `DefaultIsZeroes` is available. p256's `try_random` leaves its `FieldBytes` buffer holding x or y unwiped. The Horner accumulator in `scalar_reduce_be` is not wiped either.
- **SPEC:** SPEC.md "Secrets" lists Z and V as zeroised without qualification.
- **Fix:**
  - Add `(*Verifier).Close()` and `(*Prover).Close()` in Go and document `defer v.Close()`.
  - In Rust, wrap z, v and diff in `Zeroizing`.
  - Reword SPEC.md to "encoded Z/V; point objects best effort".

### SP-4 (minor, CONFIRMED): The "x ≥ field prime" tests do not test canonicality
- **Evidence:** rust/src/tests.rs:435-440 and go/vectors_test.go:310 use x = 2^256−1 with y = 0xff…, which is off-curve anyway. A decoder that reduced coordinates mod p would still pass both tests. tests.rs:439 also checks only `is_err()`.
- **Fix:** add the non-canonical encoding of the valid point with x=0, written as x+p:
  `04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4`
  Its canonical form is `04` + 32 zero bytes + `66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4`, which both libraries accept. Assert rejection for shareP, shareV and L.

### SP-5 (minor, CONFIRMED): Go zero-value states misbehave
- `var v spake2p.Verifier; v.Finish(x)` panics with a nil dereference at go/spake2p.go:564, because `defer v.t.wipe()` runs on a nil `t`.
- A zero `Prover` returns nistec's raw error "invalid scalar length", not a sentinel; the driver's `kind()` maps it to "io".
- **Fix:** in `Finish`, return `ErrFinished` (or `ErrInvalidState`) when `t == nil` or `x == nil`.

### SP-6 (minor, CONFIRMED): Neither library can validate a stored L until a peer connects
- **Evidence:** `L::from_bytes` (lib.rs:169) checks only the length, and Go takes L as `[]byte`. A corrupted record surfaces only inside `respond` (lib.rs:686; go/spake2p.go:527), with the same error kind as a bad peer share.
- **Effect:** "my stored record is broken" looks the same as an attack. An attempt counter would burn attempts on what is really a local fault.
- **Fix:** add `L::parse`/`validate` (Rust) and `ParseL` (Go) for load time. Optionally give a bad L its own error.

### SP-7 (nit, PLAUSIBLE): Go `Finish` is not goroutine-safe
- **Evidence:** the plain `finished` bool at go/spake2p.go:457-460 and 560-563.
- **Race:** two concurrent calls with the correct confirmP can both pass the check. One call's deferred `wipe` can then zero `kShared` before the other copies it. That caller gets a confirmed all-zero key. This requires the application to misuse the API.
- **Fix:** document that a state must not be shared across goroutines, or use `sync.Mutex` or `atomic.Bool.CompareAndSwap`.

### SP-8 (nit, CONFIRMED): Go types make argument swaps compile
- **Evidence:** `StartProver(…, w0, w1 *Scalar)` uses one type for both scalars. `RespondVerifier(…, w0, l, shareP []byte)` takes L and shareP as two 65-byte `[]byte` arguments, side by side.
- **Effect:** a swap compiles silently. Rust uses distinct newtypes (`W0`/`W1`/`L`/`ShareP`), and Go should match.

### SP-9 (nit, CONFIRMED): Rust `Prover::start` would panic on an identity X
- **Evidence:** `encode_point` (lib.rs:358-363, comment at lib.rs:571) would panic on `copy_from_slice` if X were the identity. Go returns an error in this case (go/spake2p.go:309).
- **Effect:** unreachable without the discrete log of M. Still, a panic in a crypto library is worse than an error; use `reject_identity` there.

### SP-10 (nit, CONFIRMED): Minor sampling and error-kind divergences
- Go's `randomScalar` can return 0 (go/spake2p.go:285-296); Rust resamples it (lib.rs:499). Both are within the SPEC and the probability is 2^-256.
- A non-canonical coordinate is `NotOnCurve` in Rust and `InvalidPoint` in Go.

### SP-11 (nit, CONFIRMED): Test gaps
- SPEC test 6 says "−L is accepted": Go tests it (go/vectors_test.go:337-342), Rust does not.
- The comment at tests.rs:531 claims "half = n is rejected", but that test never checks it.
- interop/run.sh covers only random 24-byte contexts and short identities. It never runs cross-language with empty context or identities, fields of 256+ bytes (multi-byte length prefixes), or edge-input parity (SP-1, SP-10).
- The mismatch case passes on any `ok:false`, including transport failures. The match cases would catch a broken build, so this matters little.

### SP-12 (nit, CONFIRMED): README.md lists a swift/ package that is not in this commit
- swift/ exists only untracked in the working tree. Either commit it or drop the row before publishing.

## Integration advice (6-digit code, TLS fingerprint in Context)

1. **Count attempts at `respond`, not at `finish`.** Every shareP the NAS answers is one guess, whatever happens afterwards. Give each code a small total budget (for example 3–5 respond calls), a short lifetime, and single use. Then rotate the code and require the user to start over. With a 10^6 code space, each attempt gives an attacker a 1-in-10^6 chance; the budget is the entire defence.
2. **The phone must never auto-retry with the same code.** A spoofed NAS acting as Verifier gets one guess per phone attempt. Treat a failed confirmV as "re-enter or re-display the code".
3. **Augmentation buys nothing at this entropy.** A stolen (w0, L) for a 6-digit code is brute-forced in seconds whatever the PBKDF. Keep the verifier record ephemeral: create it when the code is shown, delete it on success or expiry, and never persist it. Generate the code from a CSPRNG by rejection sampling, not by `% 1000000`.
4. **Fix the Context format exactly**, for example `"lumento-pair-v1" || 0x00 || SHA-256(DER leaf cert)`, with fixed lengths. Both sides must hash the same object (leaf DER, not the chain or SPKI unless both agree). The NAS uses its own certificate; the phone uses the certificate it actually saw. A TLS man-in-the-middle then produces a confirmation failure, which also counts as an attempt.
5. **Use non-empty, distinct, role-fixed `idProver`/`idVerifier`** (RFC SHOULD), and put the same identities into `pbkdf_input`.
6. **The Prover gets K_shared before the Verifier has accepted confirmP.** Do not mark the phone as paired, or store long-lived credentials, until the NAS sends an acknowledgement authenticated under a key derived from K_shared.
7. **Derive application keys from K_shared** with HKDF and distinct labels. Do not use K_shared directly as a token.
8. **In Go:** validate every stored scalar with `ParseScalar` and never store `spake2p.Scalar` in a JSON or gob struct (SP-1). Always reach `Finish`, or wipe, on every path (SP-3).

## Not reviewed
- The swift/ wrapper and the ffi/ C ABI: both are untracked and outside ee79b26.
- interop/run.sh was read but not run.
- Constant-time behaviour of `bigmod` v0.1.0 `SetBytes`/`Mod` and of nistec `SetBytes`/`ScalarMult` was taken from their documented guarantees, not re-audited. I did confirm that both reject non-canonical coordinates.
- The getrandom 0.4 and rand_core 0.10 `SysRng` path, beyond checking that its errors surface as `Error::Rng`.
- go/example_test.go and go/README.md were only grepped.

---

## Disposition (2026-10-18, Claude)

- SP-1 to SP-11: fixed on `core-1` in the commit that adds this review, as the reviewer proposed,
  with these notes. Every suite was re-run green after the fixes (Rust 50 unit + 1 doctest, ffi 14,
  `go test -race`, `swift test` 16, `interop/run.sh 2` 72/0).
  - SP-1: Go rejects an all-zero w0/w1 (constant-time) at every entry point; `Zero()` leaves the
    value detectably invalid; Go has `W0`/`W1`/`L` with Parse and binary/JSON marshalling through them.
  - SP-3: Go `Close()` on Prover and Verifier; Rust wraps the points in `Zeroizing`. SPEC "Secrets"
    now says encoded Z/V and derived keys are wiped and library point objects are best effort.
  - SP-6: Rust `L::parse` and Go `ParseL` for load time, and a bad stored L has its own error
    (`InvalidRecord` / `ErrInvalidRecord` / ffi status 10 / driver `invalid_record`).
  - SP-7: fixed with a mutex in Go's Prover and Verifier, not just documented.
  - SP-9: `encode_point` returns an error instead of panicking. Its test reaches only the
    helper (`encode_point`, `reject_identity`): a real identity X needs the discrete log of M.
  - SP-10: Go resamples a zero scalar. The library error kinds for a non-canonical coordinate still
    differ (`NotOnCurve` in Rust, `ErrInvalidPoint` in Go); the drivers both report `invalid_point`,
    and SPEC.md "Validation" documents the mapping.
  - SP-11: Rust tests −L and the non-canonical point; interop adds empty and ≥ 300-byte fields
    cross-language, and a mismatch needs Prover `confirmation_failed` and Verifier `peer_aborted`.
    Driver error kinds are not fully uniform (`finished`/`invalid_state` are Go-only; Rust and Swift
    report a bad `pbkdf_output` length as `invalid_message`); SPEC.md "Driver contract" says so.
- SP-12: closed by `6665def` (the swift/ and ffi/ commit).
- Integration advice: carried into Loadmento's PAIRING-HARDEN-1 design. Its one-pending-code
  rule (9Reg, 2026-10-18) goes with advice 1.
- ffi/ and swift/ get their own review after the fixes.
