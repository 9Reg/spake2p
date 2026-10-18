# spake2p — implementation contract

Every implementation in this repo (Rust in `rust/`, Go in `go/`, and the Swift wrapper in `swift/`
over the Rust core) follows this file. When an implementation and this file disagree, fix one of
them in the same change; the RFC wins over both.

## Scope

- SPAKE2+ as defined by [RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html), one ciphersuite
  only: **P256-SHA256-HKDF-SHA256-HMAC-SHA256** (RFC 9383 §4, first row). Other suites are out of
  scope until someone needs one; adding one means adding its RFC vector set to `vectors/`.
- M and N are the RFC's P-256 constants (§4), compressed SEC1:
  - M = `02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f`
  - N = `03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49`
- Group arithmetic comes from a maintained library, never written here: RustCrypto `p256`
  (arithmetic feature) in Rust, `filippo.io/nistec` in Go. This repo writes the protocol steps only.
- The PBKDF that turns a password into w0/w1 is the application's choice (RFC 9383 §3.2 leaves it
  out of the ciphersuite). This library takes its output; see "Registration".

## Encodings

- Points on the wire and in the transcript: **SEC1 uncompressed, 65 bytes, leading 0x04**, exactly
  as the RFC's vectors encode them. M and N enter the transcript uncompressed too (the RFC's TT
  vector shows this).
- Scalars (w0, w1, x, y): 32 bytes big-endian, value in [0, n-1] where n is the P-256 group order
  (the RFC calls it p; this file says n to keep it apart from the field prime).
- `len(S)` in the transcript: 8-byte little-endian byte length (RFC §3).
- Confirmation messages: 32 bytes (HMAC-SHA256 tag). K_shared: 32 bytes.

## Registration

- `w0w1_from_pbkdf_output(out: 80 bytes) -> (w0, w1)`: split into two 40-byte halves, each read
  as a big-endian integer and reduced mod n (RFC §3.2, k = 64 bits of bias margin). Exactly 80
  bytes; any other length is an error, and so is a half that reduces to zero.
- `w0, w1` may also be given directly as 32-byte scalars; a value ≥ n is an error (never reduced
  silently). w0 = 0 or w1 = 0 is an error.
- `register(w1) -> L = w1·P`, 65 bytes uncompressed. The Verifier stores (w0, L), never w1.
- The library also exports the RFC's recommended PBKDF input encoding as a helper:
  `pbkdf_input(pw, idProver, idVerifier) = len(pw)||pw||len(idProver)||idProver||len(idVerifier)||idVerifier`.

## Protocol

Inputs common to both roles: `context`, `idProver`, `idVerifier` (byte strings, any may be empty
except as the application requires; the RFC's SHOULD on non-empty identities is the
application's to honour).

Prover:
1. `Prover::start(context, idProver, idVerifier, w0, w1) -> (prover, shareP)`: x uniform in
   [0, n-1] from the OS CSPRNG; X = x·P + w0·M; shareP = encode(X).
2. `prover.finish(shareV, confirmV) -> (confirmP, K_shared)`: decode and validate shareV (below);
   Z = h·x·(Y − w0·N), V = h·w1·(Y − w0·N) (h = 1 for P-256); build TT; derive keys; verify
   `confirmV == HMAC(K_confirmV, shareP)` in constant time. **Only if it matches** return
   `confirmP = HMAC(K_confirmP, shareV)` and K_shared. On mismatch return an error and nothing else.

Verifier:
1. `Verifier::respond(context, idProver, idVerifier, w0, L, shareP) -> (verifier, shareV, confirmV)`:
   decode and validate shareP and L; y uniform in [0, n-1]; Y = y·P + w0·N; Z = h·y·(X − w0·M),
   V = h·y·L; build TT; derive keys; confirmV = HMAC(K_confirmV, shareP).
2. `verifier.finish(confirmP) -> K_shared`: verify `confirmP == HMAC(K_confirmP, shareV)` in
   constant time; only then return K_shared.

Transcript, exactly RFC §3.3: `TT = len(Context)||Context || len(idProver)||idProver ||
len(idVerifier)||idVerifier || len(M)||M || len(N)||N || len(shareP)||shareP || len(shareV)||shareV ||
len(Z)||Z || len(V)||V || len(w0)||w0`. The context and its length prefix are always present
(never omitted, even when empty).

Key schedule, exactly RFC §3.4: `K_main = SHA256(TT)`; `K_confirmP || K_confirmV =
HKDF-SHA256(salt = nil, ikm = K_main, info = "ConfirmationKeys", L = 64)`; `K_shared =
HKDF-SHA256(salt = nil, ikm = K_main, info = "SharedKey", L = 32)`. `confirmP = HMAC(K_confirmP,
shareV)`, `confirmV = HMAC(K_confirmV, shareP)`.

## Validation (RFC §6) — every one is a test

- A received share (shareP, shareV) or a supplied L must be exactly 65 bytes, start with 0x04,
  and decode to a point on P-256. Compressed, hybrid, short, long or off-curve input: error.
- The identity element is rejected wherever a point is received or computed: X, Y, L, and also
  `Y − w0·N`, `X − w0·M`, Z and V (an all-zero share is not even encodable as uncompressed SEC1;
  the computed checks catch a peer who sends exactly w0·M or w0·N).
- A non-canonical point encoding (wrong prefix, compressed, hybrid, coordinate >= the field prime,
  off-curve) is `NotOnCurve` (Rust), `ErrInvalidPoint` (Go) and `invalid_point` (drivers); a wrong
  length is `InvalidLength` / `ErrInvalidMessage`, except that drivers report a wrong-length share
  as `invalid_point`.
- A bad stored L is a local fault, never a peer error: `InvalidRecord` (Rust), `ErrInvalidRecord`
  (Go), ffi status 10, driver kind `invalid_record`. A stored L is checked at load time with
  `L::parse` (Rust) / `ParseL` (Go), and again by `respond`.
- w0 = 0 or w1 = 0 is rejected (`ZeroScalar` / `ErrInvalidScalar`), including the zero value of the
  Go `W0` / `W1` types.
- Any error ends the exchange: the state object is consumed by `finish` and cannot be retried.
  A failed confirmation reveals nothing beyond "failed" (no partial keys, no distinguishing error
  text between "bad share" and "bad confirmation" at the API boundary beyond an error kind).

## Secrets

- x, y, w0, w1, the encoded Z and V, K_main, K_confirmP, K_confirmV and K_shared are zeroised when
  the state object is dropped or finished (Rust: `zeroize`; Go: overwrite byte slices, best
  effort, since Go's GC may copy). The underlying library's point objects (`p256`, `nistec`) are
  wiped only where the implementation holds them, best effort, not inside the library's temporaries.
- Go: `Prover.Close()` / `Verifier.Close()` wipe and consume an exchange that will not reach
  `Finish`; they are idempotent and `Finish` calls them itself.
- x and y are sampled by rejection: 32 bytes from the OS CSPRNG into a wiped buffer, retried while
  the value is >= n or zero (about 2^-32 per draw).
- Confirmation tags are compared in constant time (Rust: `subtle` / `hmac::Mac::verify_slice`;
  Go: `crypto/hmac.Equal`).

## Rate limiting

SPAKE2+ lets an active attacker test exactly one password guess per run, and the library cannot
count runs. **Every Verifier `respond` counts as one guess, whatever its outcome**: the attacker
either receives `confirmV` and tests its guess offline, or learns from a failure that its guess was
exactly right and never sends `confirmP`. Counting only Verifier `finish` failures gives an attacker
unlimited guesses. Likewise **every Prover `finish` against a peer that has not yet proved itself**
counts as one guess of that peer. The application keeps a small attempt budget per password, counts
at `respond`, and rotates the password when the budget is spent.

## Tests every implementation carries

1. **RFC vector**: with x and y injected from `vectors/rfc9383-p256-sha256-hkdf-hmac.json`
   (a test-only entry point, not part of the public API), reproduce shareP, shareV, Z, V, TT,
   K_main, K_confirmP, K_confirmV, confirmP, confirmV and K_shared byte for byte, and L from w1.
2. **Round trip**: random x, y, same password → both sides get the same K_shared.
3. **Wrong password**: different w0/w1 on the Prover → `prover.finish` fails on confirmV.
4. **Tampering**: a flipped bit in shareP, shareV, confirmV or confirmP → failure.
5. **Context / identity binding**: Prover and Verifier with different context (or idProver, or
   idVerifier) → failure.
6. **Invalid points**: each rejection listed under Validation, including a share equal to
   w0·M (resp. w0·N), an off-curve point, and x ≥ the field prime; a valid point's negation (e.g. −L)
   is accepted.
7. **Registration**: `w0w1_from_pbkdf_output` against a known reduction (a 40-byte value ≥ n
   reduces correctly), wrong lengths rejected, scalar ≥ n rejected.

## Cross-language interop

`interop/` holds a driver for each implementation speaking line-delimited JSON on stdin/stdout,
one role per process. `interop/run.sh` wires Rust-Prover↔Go-Verifier and Go-Prover↔Rust-Verifier
with random passwords and contexts, plus a mismatched-password run per pairing that must fail with the Prover reporting
`confirmation_failed` and the Verifier `peer_aborted`, and cases with empty context and identities
and with fields of 300 bytes or more. The Swift wrapper adds its own round trip against the Rust core inside `swift test`.

Driver contract (both languages identical; all byte values lowercase hex):

- Invocation: `<driver> prover|verifier <config.json>`. Config:
  `{"context": hex, "idProver": hex, "idVerifier": hex, "pbkdf_output": hex(80 bytes)}`. The
  Verifier derives w0 and L from `pbkdf_output` itself (it must never be handed w1 by the driver
  after that point).
- stdout/stdin carry only peer messages, one JSON object per line, flushed after each line:
  Prover → `{"shareP": hex}`; Verifier → `{"shareV": hex, "confirmV": hex}`;
  Prover → `{"confirmP": hex}` (or `{"abort": true}` if confirmV failed, then exits).
- The outcome is one JSON line on stderr: `{"ok": true, "K_shared": hex}` or
  `{"ok": false, "error": "<kind>"}`. `<kind>` is one of `confirmation_failed`, `peer_aborted`,
  `invalid_point`, `invalid_record`, `io`, `invalid_message`, `invalid_scalar`,
  `invalid_pbkdf_output`, `finished`, `invalid_state`, `random`. Not every driver can reach every
  kind: `finished` and `invalid_state` exist only in Go (Rust and Swift consume the state by
  construction), and the Rust and Swift drivers report a wrong-length `pbkdf_output` as
  `invalid_message`. Exit code 0 on ok, 1 on protocol failure, 2 on bad usage.
- `interop/run.sh` connects two drivers with two FIFOs, and passes when both report ok with equal
  K_shared (matching password) or both report not ok (mismatched password).
