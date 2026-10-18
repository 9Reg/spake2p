#!/bin/sh
# Builds swift/CSpake2p.xcframework from ffi/: iOS device, iOS simulator (arm64 + x86_64, lipo'd)
# and a universal macOS slice. Any failing step fails the script (nonzero exit).
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
TARGETS="aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin"

# Deployment targets come from swift/Package.swift (.iOS(.v18) -> 18.0) so the objects never claim
# a newer OS than the package does.
IOS_MIN=$(sed -n 's/.*\.iOS(\.v\([0-9][0-9]*\)).*/\1.0/p' "$ROOT/swift/Package.swift")
MAC_MIN=$(sed -n 's/.*\.macOS(\.v\([0-9][0-9]*\)).*/\1.0/p' "$ROOT/swift/Package.swift")
[ -n "$IOS_MIN" ] && [ -n "$MAC_MIN" ] || { echo "cannot read the platforms from swift/Package.swift" >&2; exit 1; }

rm -rf "$BUILD" "$XCF"
mkdir -p "$BUILD"

echo "building staticlibs in the dev container: $TARGETS"
docker run --rm --user root -v "$ROOT:/w" -w /w/ffi \
	-v spake2p-rust-target:/t -v spake2p-cargo-registry:/usr/local/cargo/registry \
	-e CARGO_TARGET_DIR=/t -e IPHONEOS_DEPLOYMENT_TARGET="$IOS_MIN" -e MACOSX_DEPLOYMENT_TARGET="$MAC_MIN" \
	"$RUST_IMAGE" sh -c "
set -eu
for t in $TARGETS; do
	rustup target add \$t >/dev/null 2>&1
	cargo build --locked -q --release --target \$t
	mkdir -p /w/dist/xcframework-build/\$t
	cp /t/\$t/release/libspake2p_ffi.a /w/dist/xcframework-build/\$t/
done
"

echo "lipo simulator and macOS slices"
mkdir -p "$BUILD/ios-sim-universal" "$BUILD/macos-universal"
lipo -create "$BUILD/aarch64-apple-ios-sim/libspake2p_ffi.a" "$BUILD/x86_64-apple-ios/libspake2p_ffi.a" \
	-output "$BUILD/ios-sim-universal/libspake2p_ffi.a"
lipo -create "$BUILD/aarch64-apple-darwin/libspake2p_ffi.a" "$BUILD/x86_64-apple-darwin/libspake2p_ffi.a" \
	-output "$BUILD/macos-universal/libspake2p_ffi.a"

echo "creating xcframework"
# Not piped: a pipe would hide xcodebuild's exit status (plain sh has no pipefail). Output goes to a
# log, shown only on failure.
LOG="$BUILD/xcodebuild.log"
if ! xcodebuild -create-xcframework \
	-library "$BUILD/aarch64-apple-ios/libspake2p_ffi.a" -headers "$ROOT/ffi/include" \
	-library "$BUILD/ios-sim-universal/libspake2p_ffi.a" -headers "$ROOT/ffi/include" \
	-library "$BUILD/macos-universal/libspake2p_ffi.a" -headers "$ROOT/ffi/include" \
	-output "$XCF" >"$LOG" 2>&1; then
	cat "$LOG" >&2
	echo "xcodebuild -create-xcframework failed" >&2
	exit 1
fi
[ -f "$XCF/Info.plist" ] || { echo "xcframework not created: $XCF/Info.plist missing" >&2; exit 1; }

# Which source built it (the tree may be dirty: noted).
{
	git -C "$ROOT" rev-parse --short HEAD
	git -C "$ROOT" diff --quiet HEAD -- ffi rust 2>/dev/null || echo "dirty"
} | tr '\n' ' ' >"$XCF/BUILD_INFO"
echo >>"$XCF/BUILD_INFO"

echo "slice sizes:"
find "$XCF" -name '*.a' -exec ls -l {} \; | awk '{print $5, $9}'
