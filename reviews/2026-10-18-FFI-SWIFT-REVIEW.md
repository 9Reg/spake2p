# FFI and Swift review — `8e772e9` (core-1), 2026-10-18

Read before changing ffi/ or swift/. Reviewer: fresh Opus 5.5 context, repo read-only. Stored
verbatim; the reviewer's text wins over any annotation beside it. Scope: ffi/ and swift/ at
`8e772e9`; rust/ and go/ only where these depend on them (they had their own review,
`2026-10-18-CORE-REVIEW.md`).

---

**Verdict: APPROVE WITH CHANGES.** 1 major, 4 minor, 6 nit.

The FFI boundary is memory-safe as written:
- Every pointer is null-checked, and so is every length.
- Outputs are written only after every check has passed.
- Each handle is turned back into a `Box` exactly once.
- Every body runs under `catch_unwind`. The default `panic = unwind` applies, and Rust ≥1.81 would abort anyway if a panic escaped.
- The Rust error → C status mapping is complete. Header and `lib.rs` values agree. All three header copies in the xcframework are byte-identical to `ffi/include/spake2p.h`.
- Swift's `handle = nil` before the C call is correct, and so are the `deinit` paths. Swift 6 language mode keeps the classes non-`Sendable`.

Tests:
- `cargo test` in ffi/: 14 passed.
- `swift test`: 16 passed.
- `swift test --sanitize=address`: 16 passed, no ASan report.

The one real defect: `*_finish` leaves the inline secret state in the freed heap block. That contradicts the header's "freed (and zeroised)".

## Findings

### FS-1 (major, CONFIRMED): `*_finish` frees the handle without zeroising it
- Evidence:
  - `ffi/src/lib.rs:319-321` and `:439-441` do `let boxed = Box::from_raw(p); let state = boxed.0;`.
  - Moving out of the `Box` copies the bytes to the stack. The heap block is then deallocated without `Drop` running on it, so `ZeroizeOnDrop` wipes only the moved copy.
  - The header promises "freed (and zeroised)" (`ffi/include/spake2p.h:14`). SPEC "Secrets" says the same.
- Probe: a replica that compiles the real `ffi/src/lib.rs` under a counting global allocator. It counts non-zero bytes in the handle's block at `dealloc`:
  - `spake2p_prover_free`: 26 of 240. These are the three `Vec` ptr/cap words; not secret.
  - `spake2p_prover_finish`, failing (bad length) or succeeding: 190 of 240. That is `w0`, `w1`, `x` and shareP.
  - `spake2p_verifier_finish`, success: 127 of 129. That is `k_confirm_p` and `k_shared`.
  - `spake2p_verifier_free`: 0 of 129.
- Effect:
  - Every normal exchange leaves w0/w1 (password-equivalent), the ephemeral `x` and the Verifier's session key in freed heap memory, until the allocator reuses it.
  - The `_free` path is clean; only the path every caller takes is not.
- Fix (either):
  - Read the state out with `ptr::read(&(*p).0)`, then volatile-zero the block (`zeroize` on a `&mut [u8]` view of `size_of::<Spake2pProver>()` bytes), then free it as `Box<MaybeUninit<_>>`.
  - Or give the core `finish(&mut self)` and drop the `Box` in place.
- Add a test with a counting allocator, like the probe, for all four paths.

### FS-2 (minor, CONFIRMED): The build script reports success when `xcodebuild` fails, and does not use the lockfile
- Evidence: `scripts/build-xcframework.sh:40-44` runs `xcodebuild ... | grep -v '^$' || true`. Under `sh` with no pipefail, the pipeline's status is grep's, and `|| true` hides even that. The script then prints "slice sizes" and exits 0.
- Evidence: `:28` runs `cargo build -q --release` without `--locked`, so `ffi/Cargo.lock` can be re-resolved silently.
- Effect:
  - A failed build looks green.
  - The xcframework is not pinned to the committed dependency set.
  - It is gitignored, so nobody can see which dependencies went in.
- Fix:
  - Drop `|| true`, and check that `$XCF/Info.plist` exists afterwards.
  - Use `cargo build --locked`.
  - Optionally set `IPHONEOS_DEPLOYMENT_TARGET=18.0` and `MACOSX_DEPLOYMENT_TARGET=14.0` to match `Package.swift`. rustc's defaults are lower; that is harmless but not reproducible-by-intent.

### FS-3 (minor, CONFIRMED): Swift forces secrets into unwipeable `Data`, and its types allow argument swaps
- Evidence:
  - `Spake2p.w0w1` returns `(Data, Data)` (`swift/Sources/Spake2p/Spake2p.swift:32-38`).
  - `Prover.start` and `Verifier.respond` take w0, w1, L and shareP as plain `Data` (`Prover.swift:29-31`, `Verifier.swift:31-33`).
  - `pbkdfInput` returns the password inside a `Data` (`Spake2p.swift:57-66`).
  - Only the key gets a secret-holding type (`SymmetricKey`).
- Effect:
  - The internal `wipe` calls are cosmetic. The caller must hold w0 and w1 (and the Verifier record) in `Data`, which can never be zeroised.
  - Swapping `w0`/`w1`, or `l`/`shareP` (both 65-byte points), compiles and runs. It ends in a misleading `confirmationFailed`, or `invalidRecord`. This is the Swift form of core SP-8.
- Fix:
  - Add wrapper types: `struct W0`, `W1` backed by `SymmetricKey` or a wiped buffer, and `struct L`, `ShareP`, `ShareV`, `ConfirmV`, `ConfirmP` with validating inits.
  - Have `w0w1` return `(W0, W1)`.
  - Have `pbkdfInput` hand its bytes to a closure (`withPBKDFInput { }`) rather than return `Data`.

### FS-4 (minor, CONFIRMED): The C ABI and Swift cannot validate a stored L at load time
- Evidence: SPEC "Validation" says a stored L is checked at load time with `L::parse` / `ParseL`. Core SP-6 was fixed in Rust and Go. ffi/ exports no `spake2p_l_parse` (or `spake2p_l_validate`), and Swift has no matching call. The only check is inside `spake2p_verifier_respond` (`ffi/src/lib.rs:406`).
- Effect:
  - A Swift/C Verifier finds a corrupt record only when a peer connects, and that failure spends one of the peer's counted guesses.
  - This is low impact for Loadmento if the NAS Verifier uses the Rust crate directly, but the SPEC contract has a gap in two of four bindings.
- Fix: export `spake2p_l_validate(const uint8_t*, size_t)` returning OK or `INVALID_RECORD`. Expose it as a validating `L` initializer in Swift (it fits FS-3).

### FS-5 (minor, CONFIRMED): Tests do not test what their names claim
- `finish_consumes_handle_even_on_failure` (`ffi/src/tests.rs:418-429`):
  - It checks only that a status is returned.
  - Its comment promises that "the same inputs on a *fresh* handle succeed", but the test does not do that.
  - Nothing observes that the handle was freed. A leak or double free would pass.
- `unfinishedObjectsFreeCleanly` (`swift/Tests/Spake2pTests/Spake2pTests.swift:176-181`) asserts nothing. It passes whether `deinit` frees or not.
- `panic_becomes_status` (`ffi/src/tests.rs:470-473`) tests `guard` with a closure. It does not test the `catch_unwind` in either `_free`, and does not show that an exported function maps a panic.
- `tamperedShareV` (`Spake2pTests.swift:67`) accepts any `Spake2pError`.
- Fix:
  - Use a counting allocator (see FS-1) to assert each path frees exactly once and leaves a zeroed block.
  - Run `cargo miri test` on ffi/ in CI.
  - Pin `tamperedShareV` to the exact error.

### FS-6 (nit, CONFIRMED): Swift hardcodes status codes and sizes instead of importing them
- Evidence: `Spake2pError.swift:31-43` matches the literals `1...10`. `Spake2p.swift:21-25` hardcodes 65, 32 and 80. Both are available from `CSpake2p` as `SPAKE2P_ERR_*` and `SPAKE2P_*_LEN`.
- Also: there is no Swift case for `SPAKE2P_ERR_UNKNOWN` (9), `NULL_POINTER`, `BUFFER_TOO_SMALL` or `PANIC`. All of them fall into `.unexpected`, which is acceptable.
- Also: the header is hand-written (no cbindgen). Only 9, 10 and 100 are asserted (`ffi/src/tests.rs:496-498`).
- Fix:
  - Switch on the imported constants.
  - Add a test that asserts every `lib.rs` constant against the header, or generate the header.

### FS-7 (nit, CONFIRMED): No ABI version, and nothing stops a stale xcframework
- Evidence: `swift/CSpake2p.xcframework` is gitignored (`.gitignore`) and built out of band. The slices on disk are dated 18:26:04 and HEAD 8e772e9 is 18:28:47. They are probably the same source, but nothing checks that.
- Effect: `swift test` can pass against an older Rust core than the commit under test.
- Fix:
  - Export `spake2p_abi_version()` and check it in Swift: a test, plus a precondition at first use.
  - Optionally have the build script write the git hash into the xcframework.

### FS-8 (nit, CONFIRMED): The `spake2p_pbkdf_input` probe idiom is odd and the header's general rule is loose
- Evidence:
  - The probe needs a non-NULL `out` even with `out_cap = 0` (`ffi/src/lib.rs:229-231`).
  - NULL+0 returns `NULL_POINTER` but still writes `*out_len`.
  - The header's general rule says "On error no output buffer is written" (`spake2p.h:7`). The function documents the exception for `BUFFER_TOO_SMALL` only.
  - Nothing says outputs must not overlap inputs. That is safe today because inputs are copied first, but it is undocumented.
- Fix:
  - Accept `out == NULL` when `out_cap == 0`, as the usual C probe.
  - State the `*out_len` exception, and the no-overlap rule, in the header's conventions block.

### FS-9 (nit, CONFIRMED): Slice coverage
- Evidence: `TARGETS` in `scripts/build-xcframework.sh:16` has no `x86_64-apple-ios` (Intel simulator) and no Mac Catalyst. Yet `Package.swift` declares macOS 14, which includes Intel Macs.
- Effect: an Intel Mac cannot link the package for the iOS simulator.
- Fix: add the x86_64 simulator target and `lipo` it with arm64-sim, or document that Apple silicon is required.

### FS-10 (nit, CONFIRMED): The staticlib exports Rust runtime symbols globally
- Evidence: `nm -gU` on the ios-arm64 slice shows 346 global text symbols, including `_rust_eh_personality` and `compiler_builtins` intrinsics.
- Effect: linking a second Rust staticlib into the same app gives duplicate-symbol errors or a silent pick.
- Fix: note it in `swift/README.md`. If it is ever needed, post-process with `ld -r -exported_symbols_list` limited to `_spake2p_*`.

### FS-11 (nit, CONFIRMED): `ffi/Cargo.toml` comments promise settings it does not make
- Evidence:
  - `:17` says "Panics must unwind so that catch_unwind can..." above `[profile.release]`, but no `panic` key is set. It relies on the default.
  - `strip = "symbols"` (`:22`) has no effect on a `staticlib`.
- Fix: set `panic = "unwind"` explicitly so a later profile edit cannot silently switch it, and drop or explain `strip`.

## Not reviewed
- The Rust core (`rust/`) and Go module (`go/`), except where ffi/swift depend on them: the `Error` variants, the zeroisation derives and the `Prover`/`Verifier` layouts.
- Stack copies of secrets made by by-value `self` moves inside the core (core SP-3 territory).
- Miri: no nightly toolchain was tried in the container. The FFI unsafe code was checked by reading, by `cargo test`, and by Swift under ASan. The Rust staticlib itself is not instrumented; ASan sees only its malloc/free.
- `interop/run.sh` was not run. The Swift driver was checked against the SPEC driver contract by reading only. It matches, including `invalid_message` for a wrong-length `pbkdf_output` and `invalid_point` for a wrong-length share.
- Device builds: the iOS slices were not linked into an app or run on a device or simulator.
- Reproducibility of the `.a` files: two builds were not compared byte for byte.

---

## Disposition (2026-10-18, Claude)

All eleven fixed on `core-1` in the commit that adds this review, as the reviewer proposed. Re-run green after
the fixes: Rust 50 + 1 doctest, ffi 19 + the allocator test, `go test -race`, `swift test` 20, `interop/run.sh 2`
72/0. Notes:

- FS-1: `take_and_wipe` reads the state out, volatile-zeroes the block and frees it as `Box<MaybeUninit<T>>`, on
  both finish and both free paths. `ffi/tests/handle_free.rs` (counting allocator) checks all four paths plus the
  finish failures; it was seen to fail with the wipe removed. ffi builds an rlib too, for that test.
- FS-2: verified by a fake `xcodebuild` exiting 3 and by a bogus `DEVELOPER_DIR`: the script exits 1 both times.
- FS-5: an exported function cannot be made to panic from outside, so `panic_becomes_status` is renamed
  `guard_turns_a_panic_into_a_status` and tests `guard` only; the reviewer's `cargo miri test` is not set up (no CI).
- FS-9: the x86_64 simulator slice is built and lipo'd. FS-11: dropping `strip` makes the slices larger; the app's
  own link strips them.
- The design review's PD-12 (Loadmento) is fixed here too: the READMEs no longer advise a slow PBKDF in general.
