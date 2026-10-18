# Spake2p (Swift)

SPAKE2+ ([RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html)), ciphersuite
P256-SHA256-HKDF-SHA256-HMAC-SHA256, for iOS 18 and macOS 14. A thin Swift API over the Rust
[`spake2p`](../rust/) crate, linked as a static library through a C ABI ([`../ffi/`](../ffi/)).
No cryptography is written in Swift.

```swift
import Spake2p

// Registration: run your PBKDF over Spake2p.pbkdfInput(...) to get 80 bytes.
let (w0, w1) = try Spake2p.w0w1(fromPBKDFOutput: pbkdfOutput)
let l = try Spake2p.register(w1: w1)           // the Verifier stores (w0, l), never w1

let (prover, shareP) = try Prover.start(context: ctx, idProver: a, idVerifier: b, w0: w0, w1: w1)
let (verifier, shareV, confirmV) = try Verifier.respond(
    context: ctx, idProver: a, idVerifier: b, w0: w0, l: l, shareP: shareP)
let (confirmP, key) = try prover.finish(shareV: shareV, confirmV: confirmV)   // key: SymmetricKey
let sameKey = try verifier.finish(confirmP: confirmP)
```

`Prover` and `Verifier` are final classes that own the Rust state (zeroised when freed).
`finish` is single-use, on success and on failure; a second call throws
`Spake2pError.alreadyFinished`. They are not `Sendable`. Rate-limit attempts and choose a
memory-hard PBKDF: one run lets an active attacker test one password guess.

## Building

The package links `CSpake2p.xcframework`, which is not checked in. Build it (needs Docker for the
Rust cross-compile and Xcode for `lipo`/`xcodebuild`; nothing opens a window):

```sh
scripts/build-xcframework.sh          # from the repository root
cd swift && swift test
```

Slices: iOS device (arm64), iOS simulator (arm64), macOS (arm64 + x86_64).
`swift run -c release spake2p-interop-driver` is the Swift side of [`../interop/run.sh`](../interop/run.sh).

Licensed under either of Apache-2.0 or MIT at your option.
