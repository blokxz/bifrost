#!/bin/sh
# Runs the pseudo-terminal test suites with the temporary directory at many path
# lengths, and fails if any test does.
#
# The screens Bifrost draws show paths (the keys folder, the ssh config, the store),
# and a path is one long word that a narrow screen cuts wherever the line ends. A
# temporary directory is a few dozen characters on Linux and much longer on macOS
# (`/var/folders/xx/<30 characters>/T/.tmpXXXXXX`), so a test that looks for a phrase
# next to a path passes with one length and fails with another. Which tests are
# affected changes with the length, and only some lengths show it, so this tries
# many. Where a test looks at text that includes or follows a path, it has to use
# `Screen::contains_wrapped` (tests/support/mod.rs).
#
# Usage: sh .github/scripts/pty-long-paths.sh [length ...]   (default: 24, 28, ... 108)

set -eu

suites="--test pty --test pty_connect --test pty_keys --test pty_sshconfig"
base=/tmp/pty-long-paths
lengths="$*"
[ -n "$lengths" ] || lengths=$(seq 24 4 108)

# shellcheck disable=SC2086  # the list of suites is meant to be split
cargo test --locked $suites --no-run

failed=""
for length in $lengths; do
    rm -rf "$base"
    pad=$((length - ${#base} - 1))
    if [ "$pad" -lt 1 ]; then
        echo "pty-long-paths: $length is too short for $base" >&2
        exit 2
    fi
    dir="$base/$(head -c "$pad" /dev/zero | tr '\0' 'p')"
    mkdir -p "$dir"
    # shellcheck disable=SC2086
    if TMPDIR="$dir" cargo test --locked --no-fail-fast $suites > "$base.log" 2>&1; then
        echo "temporary directory of $length characters: all pass"
    else
        echo "temporary directory of $length characters: FAILED" >&2
        grep -E '^test [a-z_0-9:]+ \.\.\. FAILED' "$base.log" >&2 || tail -n 20 "$base.log" >&2
        failed="$failed $length"
    fi
done
rm -rf "$base" "$base.log"

if [ -n "$failed" ]; then
    echo "pty-long-paths: tests depend on the length of a path, at:$failed" >&2
    exit 1
fi
