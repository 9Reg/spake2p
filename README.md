# spake2p

SPAKE2+ ([RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html)) for Rust, Go and Swift, one
ciphersuite: **P256-SHA256-HKDF-SHA256-HMAC-SHA256**.

SPAKE2+ lets two parties that share a short secret, such as a 6-digit pairing code, agree on a
strong key and prove to each other that they know the secret. Nothing either side sends can be
used to test password guesses offline: an attacker gets one guess per attempt, against a live peer.
The "+" makes it augmented: the Verifier stores a record derived from the password, not the
password itself.

| Directory | What | Built on |
|---|---|---|
| [`rust/`](rust/) | crate `spake2p` | RustCrypto `p256`, `sha2`, `hmac`, `hkdf` |
| [`go/`](go/) | module `github.com/9Reg/spake2p/go` | `filippo.io/nistec`, Go standard library |
| [`swift/`](swift/) | package `Spake2p` | the Rust crate, through a C ABI |

The Rust and Go implementations are independent of each other. Both reproduce the RFC's test
vectors byte for byte ([`vectors/`](vectors/)), and [`interop/run.sh`](interop/run.sh) runs each as
Prover against the other as Verifier. No group arithmetic is written here: curve and field
operations come from the maintained libraries above. [`SPEC.md`](SPEC.md) is the contract all of
them follow.

**Status:** pre-release, not yet independently audited.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual licensed as
above, without any additional terms or conditions.
