#!/bin/sh
# Cross-language interop: Rust Prover <-> Go Verifier and Go Prover <-> Rust Verifier, each with a
# matching password (both sides must report ok with equal K_shared) and a mismatched one (both
# sides must report not ok). Drivers follow SPEC.md's "Driver contract".
#
# Runs headless in the dev containers. The two drivers live in different containers, so the host
# shell joins them: two FIFOs on the host carry each side's stdout to the other's stdin.
#
# On macOS with swift/CSpake2p.xcframework built (scripts/build-xcframework.sh), the Swift driver
# joins in too: swift<->go pairings. It runs on the host (headless, no window), the Go driver stays
# in its container.
#
# Usage: interop/run.sh [runs-per-case]   (default 3)
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUNS=${1:-3}
RUST_IMAGE=${RUST_IMAGE:-loadmento-devcontainer:354d4fc9d7b0}
GO_IMAGE=${GO_IMAGE:-$(docker images --format '{{.Repository}}' | grep -m1 '^vsc-lumento')}
OUT="$ROOT/dist/interop"
rm -rf "$OUT"
mkdir -p "$OUT/bin"

echo "building rust driver"
docker run --rm -v "$ROOT:/w" -w /w/rust --user root -v spake2p-rust-target:/t -v spake2p-cargo-registry:/usr/local/cargo/registry -e CARGO_TARGET_DIR=/t "$RUST_IMAGE" \
	sh -c 'cargo build -q --release --example interop_driver && cp /t/release/examples/interop_driver /w/dist/interop/bin/rust-driver'
echo "building go driver"
docker run --rm -v "$ROOT:/w" -w /w/go -v spake2p-gomod:/go/pkg/mod -e CGO_ENABLED=0 "$GO_IMAGE" \
	sh -c 'go build -o /w/dist/interop/bin/go-driver ./cmd/interop-driver'

SWIFT=0
if [ "$(uname -s)" = Darwin ] && [ -d "$ROOT/swift/CSpake2p.xcframework" ]; then
	echo "building swift driver"
	DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}
	export DEVELOPER_DIR
	(cd "$ROOT/swift" && swift build -q -c release --product spake2p-interop-driver)
	cp "$(cd "$ROOT/swift" && swift build -c release --product spake2p-interop-driver --show-bin-path)/spake2p-interop-driver" "$OUT/bin/swift-driver"
	SWIFT=1
fi

hex() { od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'; }

config() { # file context idProver idVerifier pbkdf_output
	printf '{"context":"%s","idProver":"%s","idVerifier":"%s","pbkdf_output":"%s"}\n' "$2" "$3" "$4" "$5" >"$1"
}

driver() { # lang role config -> runs the driver with stdin/stdout as given by the caller
	case $1 in
	rust) img=$RUST_IMAGE ;;
	go) img=$GO_IMAGE ;;
	swift) "$OUT/bin/swift-driver" "$2" "$3"; return ;; # on the host: $3 is already a host path
	esac
	docker run --rm -i -v "$OUT:/o" "$img" "/o/bin/$1-driver" "$2" "/o/$(basename "$3")"
}

pass=0
fail=0
run_case() { # proverLang verifierLang match|mismatch n [shape: normal|empty|long]
	shape=${5:-normal}
	tag="$1-$2-$3-$4"
	[ "$shape" = normal ] || tag="$tag-$shape"
	dir="$OUT/run-$tag"
	mkdir -p "$dir"
	case $shape in
	empty) ctx=""; idp=""; idv="" ;; # empty context and identities
	long) ctx=$(hex 300); idp=$(hex 300); idv=$(hex 301) ;; # fields of 300 bytes or more
	*)
		ctx=$(hex 24)
		idp=$(printf 'prover-%s' "$4" | od -An -tx1 | tr -d ' \n')
		idv=$(printf 'verifier-%s' "$4" | od -An -tx1 | tr -d ' \n')
		;;
	esac
	pw=$(hex 80)
	config "$OUT/p-$tag.json" "$ctx" "$idp" "$idv" "$pw"
	if [ "$3" = mismatch ]; then pw=$(hex 80); fi
	config "$OUT/v-$tag.json" "$ctx" "$idp" "$idv" "$pw"
	mkfifo "$dir/p2v" "$dir/v2p"
	driver "$2" verifier "$OUT/v-$tag.json" <"$dir/p2v" >"$dir/v2p" 2>"$dir/v.err" &
	vpid=$!
	# The prover opens its write end first: each side opening its read FIFO first would deadlock.
	driver "$1" prover "$OUT/p-$tag.json" >"$dir/p2v" <"$dir/v2p" 2>"$dir/p.err" || true
	wait "$vpid" || true
	p=$(tail -n1 "$dir/p.err")
	v=$(tail -n1 "$dir/v.err")
	if [ "$3" = match ]; then
		# Key order inside the JSON line is the driver's choice: test "ok" and read K_shared separately.
		pk=$(printf '%s' "$p" | grep '"ok": *true' | sed -n 's/.*"K_shared": *"\([0-9a-f]*\)".*/\1/p')
		vk=$(printf '%s' "$v" | grep '"ok": *true' | sed -n 's/.*"K_shared": *"\([0-9a-f]*\)".*/\1/p')
		if [ -n "$pk" ] && [ "$pk" = "$vk" ]; then ok=1; else ok=0; fi
	else
		# A wrong password is caught by the Prover (confirmV does not verify) and it aborts, so the
		# Verifier sees the abort: any other pair of failures means something else went wrong.
		if printf '%s' "$p" | grep -q '"ok": *false' && printf '%s' "$p" | grep -q '"error": *"confirmation_failed"' &&
			printf '%s' "$v" | grep -q '"ok": *false' && printf '%s' "$v" | grep -q '"error": *"peer_aborted"'; then ok=1; else ok=0; fi
	fi
	if [ $ok = 1 ]; then
		pass=$((pass + 1))
		echo "PASS $1-prover -> $2-verifier $3 $shape #$4"
	else
		fail=$((fail + 1))
		echo "FAIL $1-prover -> $2-verifier $3 $shape #$4"
		echo "  prover:   $p"
		echo "  verifier: $v"
	fi
}

set -- "rust go" "go rust" "rust rust" "go go"
if [ $SWIFT = 1 ]; then set -- "$@" "swift go" "go swift"; fi
for pair in "$@"; do
	set -- $pair
	i=1
	while [ $i -le "$RUNS" ]; do
		run_case "$1" "$2" match $i
		run_case "$1" "$2" mismatch $i
		run_case "$1" "$2" match $i empty
		run_case "$1" "$2" mismatch $i empty
		run_case "$1" "$2" match $i long
		run_case "$1" "$2" mismatch $i long
		i=$((i + 1))
	done
done

echo "interop: $pass passed, $fail failed"
[ $fail -eq 0 ]
