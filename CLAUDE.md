# CLAUDE.md

**Shared rules live in the `claude` repo, a sibling of this one** (`~/.claude/CLAUDE.md` links to
`../claude/CLAUDE.md`, made by `../claude/install.sh`). **If the word SHARED-RULES-LOADED is not in
your context above this file, the shared rules did not load: tell 9Reg before doing anything else.**

State is in `STATE.md`.

## Project

SPAKE2+ (RFC 9383), P256-SHA256-HKDF-SHA256-HMAC-SHA256, as an open-source library: a Rust crate
(`rust/`), a Go module (`go/`), and a Swift package (`swift/`) that wraps the Rust core through a C
ABI. The contract every implementation follows is [`SPEC.md`](SPEC.md); the RFC's vectors are in
`vectors/`. Built first for Loadmento/Lumento pairing (`../loadmento`, PAIRING-HARDEN-1), but it is
a general library: nothing Loadmento-specific goes in here.

Rules: no hand-written group arithmetic (RustCrypto `p256`, `filippo.io/nistec`); every SPEC.md
test exists in every implementation; `interop/run.sh` passes before a merge.

## Mechanics

- Rust: `docker run --rm -v /Users/greg/Dev/spake2p:/w -w /w/rust loadmento-devcontainer:354d4fc9d7b0 cargo test`.
  `cargo fmt` and `cargo clippy --all-targets -- -D warnings` before every Rust commit.
- Go: lumento's dev-container image (`docker images | grep vsc-lumento`), `-w /w/go`, `go test ./...`, `gofmt -l .` empty, `go vet ./...`.
- Swift: host, `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`.
- Never on `main`.
