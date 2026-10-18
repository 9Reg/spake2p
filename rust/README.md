# spake2p

An implementation of **SPAKE2+** ([RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html)), the
augmented password-authenticated key exchange, for one ciphersuite only:
**P256-SHA256-HKDF-SHA256-HMAC-SHA256**.

A Prover that knows a password and a Verifier that stores only a password-derived verifier agree on
a shared key and confirm to each other that they hold it, without the password crossing the wire.
All group arithmetic comes from RustCrypto's [`p256`](https://crates.io/crates/p256); this crate
writes the protocol steps only. The password-hashing step is left to the application (RFC 9383
§3.2): this crate takes the 80-byte output of the PBKDF you choose.

## Example

```rust
use spake2p::{register, w0w1_from_pbkdf_output, Prover, Verifier};

// Registration, once. `pbkdf_output` is 80 bytes from your PBKDF run over
// `spake2p::pbkdf_input(password, id_prover, id_verifier)`.
let pbkdf_output = [0x42u8; 80];
let (w0, w1) = w0w1_from_pbkdf_output(&pbkdf_output)?;
let l = register(&w1)?; // the Verifier stores (w0, l), never w1

let (ctx, idp, idv) = (b"my-app v1".as_slice(), b"client".as_slice(), b"server".as_slice());

let (prover, share_p) = Prover::start(ctx, idp, idv, &w0, &w1)?;
let (verifier, share_v, confirm_v) = Verifier::respond(ctx, idp, idv, &w0, &l, &share_p)?;
let (confirm_p, prover_key) = prover.finish(&share_v, &confirm_v)?;
let verifier_key = verifier.finish(&confirm_p)?;
assert_eq!(prover_key.as_bytes(), verifier_key.as_bytes());
# Ok::<(), spake2p::Error>(())
```

## Security notes

- Points on the wire are SEC1 uncompressed (65 bytes). Compressed, hybrid, wrong-length, off-curve
  and identity points are rejected, as are computed identities (`Y - w0·N`, `X - w0·M`, `Z`, `V`).
- `finish` consumes the state: a failed exchange cannot be retried. A failed confirmation returns
  one error and no key material. Tags are compared in constant time.
- Secrets (`x`, `y`, `w0`, `w1`, the encoded `Z` and `V`, derived keys) are zeroised on drop, on a
  best-effort basis (the `p256` point objects only where this crate holds them); the compiler or OS may have copied them.
- Randomness comes from the operating system's CSPRNG (`getrandom`).
- An active attacker gets one password guess per run, and **every `Verifier::respond` call counts
  as one guess whatever its outcome** (the attacker either receives `confirmV` to test offline, or
  learns from a failure that its guess was right and never sends `confirmP`). Counting only
  `Verifier::finish` failures gives unlimited guesses. The same holds for `Prover::finish` against
  a peer that has not proved itself. Keep a small attempt budget per password, count at `respond`,
  and use a memory-hard PBKDF. Use non-empty prover and verifier identities, as RFC 9383
  recommends. See "Rate limiting" in `SPEC.md`.
- This crate has not had an independent audit. It reproduces the RFC 9383 test vector byte for
  byte.

## License

Licensed under either of Apache-2.0 or MIT at your option. See [LICENSE-APACHE](LICENSE-APACHE)
and [LICENSE-MIT](LICENSE-MIT) (the repository root holds the same files: `../LICENSE-APACHE`,
`../LICENSE-MIT`).
