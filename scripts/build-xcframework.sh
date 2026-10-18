#!/bin/sh
# Builds swift/CSpake2p.xcframework from ffi/: iOS device, iOS simulator, and a universal macOS slice.
#
# The staticlib is cross-compiled from the Rust dev container (pure-Rust dependencies need no Apple
# SDK); lipo and xcodebuild run on the host, headless. Output: swift/CSpake2p.xcframework
# (gitignored). Intermediate .a files: dist/xcframework-build/.
#
# Usage: scripts/build-xcframework.sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUST_IMAGE=${RUST_IMAGE:-loadmento-devcontainer:354d4fc9d7b0}
export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}
BUILD="$ROOT/dist/xcframework-build"
XCF="$ROOT/swift/CSpake2p.xcframework"
TARGETS="aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin x86_64-apple-darwin"

rm -rf "$BUILD" "$XCF"
mkdir -p "$BUILD"

echo "building staticlibs in the dev container: $TARGETS"
docker run --rm --user root -v "$ROOT:/w" -w /w/ffi \
	-v spake2p-rust-target:/t -v spake2p-cargo-registry:/usr/local/cargo/registry \
	-e CARGO_TARGET_DIR=/t "$RUST_IMAGE" sh -c "
set -eu
for t in $TARGETS; do
	rustup target add \$t >/dev/null 2>&1
	cargo build -q --release --target \$t
	mkdir -p /w/dist/xcframework-build/\$t
	cp /t/\$t/release/libspake2p_ffi.a /w/dist/xcframework-build/\$t/
done
"

echo "lipo macOS slices"
mkdir -p "$BUILD/macos-universal"
lipo -create "$BUILD/aarch64-apple-darwin/libspake2p_ffi.a" "$BUILD/x86_64-apple-darwin/libspake2p_ffi.a" \
	-output "$BUILD/macos-universal/libspake2p_ffi.a"

echo "creating xcframework"
xcodebuild -create-xcframework \
	-library "$BUILD/aarch64-apple-ios/libspake2p_ffi.a" -headers "$ROOT/ffi/include" \
	-library "$BUILD/aarch64-apple-ios-sim/libspake2p_ffi.a" -headers "$ROOT/ffi/include" \
	-library "$BUILD/macos-universal/libspake2p_ffi.a" -headers "$ROOT/ffi/include" \
	-output "$XCF" | grep -v '^$' || true

echo "slice sizes:"
find "$XCF" -name '*.a' -exec ls -l {} \; | awk '{print $5, $9}'
