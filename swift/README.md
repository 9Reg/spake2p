# Spake2p (Swift)

SPAKE2+ ([RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html)), ciphersuite
P256-SHA256-HKDF-SHA256-HMAC-SHA256, for iOS 18 and macOS 14. A thin Swift API over the Rust
[`spake2p`](../rust/) crate, linked as a static library through a C ABI ([`../ffi/`](../ffi/)).
No cryptography is written in Swift.

```swift
import Spake2p

// Registration: run your PBKDF over Spake2p.pbkdfInput(...) to get 80 bytes.
let pbkdfOutput = try Spake2p.withPBKDFInput(password: pw, idProver: a, idVerifier: b) { bytes in
    yourPBKDF(bytes)                            // 80 bytes; `bytes` is wiped when the closure returns
}
let (w0, w1) = try Spake2p.w0w1(fromPBKDFOutput: pbkdfOutput)   // W0, W1: secrets
let l = try Spake2p.register(w1: w1)           // an L; the Verifier stores (w0, l), never w1

let (prover, shareP) = try Prover.start(context: ctx, idProver: a, idVerifier: b, w0: w0, w1: w1)
let (verifier, shareV, confirmV) = try Verifier.respond(
    context: ctx, idProver: a, idVerifier: b, w0: w0, l: l, shareP: shareP)
let (confirmP, key) = try prover.finish(shareV: shareV, confirmV: confirmV)   // key: SymmetricKey
let sameKey = try verifier.finish(confirmP: confirmP)
```

Everything crossing the API is a typed value with a validating init: `W0` and `W1` (secrets, held in
`SymmetricKey` storage, no printing or comparing), `L` (checked fully by the Rust core,
`Spake2pError.invalidRecord` on any defect), `ShareP`, `ShareV`, `ConfirmP`, `ConfirmV` (length
checked, `invalidLength`). Point checks on shares happen when the exchange uses them. To store `w0`
next to `L`, use `w0.withUnsafeBytes { ... }`.

`Spake2p.abiVersion` is the linked library's ABI version; the package checks it against the header
on first use and traps on a mismatch (a stale xcframework).

`Prover` and `Verifier` are final classes that own the Rust state (zeroised when freed).
`finish` is single-use, on success and on failure; a second call throws
`Spake2pError.alreadyFinished`. They are not `Sendable`. Rate-limit attempts: one run lets an
active attacker test one password guess. A slow PBKDF matters only when the verifier record is
persisted and the password is low-entropy; for a short-lived record from a short code, the attempt
budget is the defence.

## Building

The package links `CSpake2p.xcframework`, which is not checked in. Build it (needs Docker for the
Rust cross-compile and Xcode for `lipo`/`xcodebuild`; nothing opens a window):

```sh
scripts/build-xcframework.sh          # from the repository root
cd swift && swift test
```

Slices: iOS device (arm64), iOS simulator (arm64 + x86_64, lipo'd), macOS (arm64 + x86_64). The
objects are built for the deployment targets in `Package.swift` (iOS 18, macOS 14). The script fails
(nonzero exit) if any step fails, and writes the source commit to `CSpake2p.xcframework/BUILD_INFO`
(with `dirty` if `ffi/` or `rust/` had uncommitted changes).

**One Rust staticlib per app.** `libspake2p_ffi.a` carries the Rust runtime (`std`, the allocator
and panic machinery) and exports those symbols too. Linking a second Rust staticlib into the same
app can clash or duplicate them: if the app has another, build both into one library instead.
`swift run -c release spake2p-interop-driver` is the Swift side of [`../interop/run.sh`](../interop/run.sh).

Licensed under either of Apache-2.0 or MIT at your option.
