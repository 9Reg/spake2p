# spake2p (Go)

An implementation of [RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html) SPAKE2+, a
password-authenticated key exchange where the verifying side stores a verification record instead of
the password. One ciphersuite only: **P256-SHA256-HKDF-SHA256-HMAC-SHA256**. The protocol steps are
written here; all group arithmetic comes from [`filippo.io/nistec`](https://pkg.go.dev/filippo.io/nistec)
and scalar reduction from [`filippo.io/bigmod`](https://pkg.go.dev/filippo.io/bigmod). The contract
shared with the other implementations in this repo is [`../SPEC.md`](../SPEC.md).

```
go get github.com/9Reg/spake2p/go
```

## Example

```go
// Registration, once: PBKDF output (80 bytes) -> w0, w1 -> L. Verifier stores (w0, L).
w0, w1, _ := spake2p.W0W1FromPBKDFOutput(pbkdfOut)
l, _ := spake2p.Register(w1)

// Exchange.
prover, shareP, _ := spake2p.StartProver(ctx, idProver, idVerifier, w0, w1)
verifier, shareV, confirmV, _ := spake2p.RespondVerifier(ctx, idProver, idVerifier, w0, l, shareP)
confirmP, proverKey, err := prover.Finish(shareV, confirmV) // err: wrong password, tampering, ...
verifierKey, err := verifier.Finish(confirmP)               // equal to proverKey
```

`example_test.go` is a runnable version. Handle every error; ignoring them as above is shorthand.

## Security notes

- The PBKDF that turns a password into the 80 bytes is yours to choose (use a memory-hard one such as
  scrypt or Argon2id). SPAKE2+ limits an attacker to one guess per run; it does not make a weak
  password strong.
- Shares and `L` are validated: exactly 65 bytes, `0x04` prefix, on the curve, and the identity is
  rejected wherever it can appear (including `Y - w0·N`, `X - w0·M`, `Z`, `V`).
- `Finish` is single use. Any failure consumes the state; start a new exchange to retry. A failed
  `Prover.Finish` returns no keys. Confirmation tags are compared with `hmac.Equal`.
- `x` and `y` are drawn from `crypto/rand` by rejection sampling over `[0, n-1]`.
- Secret slices are zeroed after use on a best-effort basis; Go's garbage collector may have copied
  them already.
- Run one exchange per connection and bind `context` to your application and protocol version.
- This code has not had an independent audit. It reproduces the RFC 9383 Appendix C vectors byte for
  byte (`go test ./...`).

## Interop driver

`cmd/interop-driver` speaks the line-delimited JSON protocol in `SPEC.md` ("Driver contract") so
this implementation can be tested against the others.

## License

Licensed under either of Apache-2.0 or MIT at your option. See [`../LICENSE-APACHE`](../LICENSE-APACHE)
and [`../LICENSE-MIT`](../LICENSE-MIT).
