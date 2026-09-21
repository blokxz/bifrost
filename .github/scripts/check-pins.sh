#!/bin/sh
# Fails if any `uses:` in the workflows is not pinned to a full commit hash with the
# version in a comment on the same line:
#
#     uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0
#
# A tag or a branch can be moved to other code after it was read; a commit hash
# cannot. The comment is what tells a person (and Dependabot, which updates both
# together) which version the hash is. Local actions (`./...`) are not pinned.
#
# Usage: sh .github/scripts/check-pins.sh [workflows-folder]

set -eu

dir="${1:-.github/workflows}"

files=""
for file in "$dir"/*.yml "$dir"/*.yaml; do
    [ -e "$file" ] && files="$files $file"
done
if [ -z "$files" ]; then
    echo "check-pins: no workflow files in $dir" >&2
    exit 2
fi

# shellcheck disable=SC2086  # the list of files is meant to be split
uses=$(grep -nHE '^[[:space:]]*(-[[:space:]]+)?uses:' $files || true)

good='^[^:]+:[0-9]+:[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]+([^@[:space:]]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]*v[0-9][^[:space:]]*|\./[^[:space:]]*)[[:space:]]*$'

bad=$(printf '%s\n' "$uses" | grep -v '^$' | grep -vE "$good" || true)

if [ -n "$bad" ]; then
    echo "check-pins: these actions are not pinned to a full commit hash with a '# vX.Y.Z' comment:" >&2
    printf '%s\n' "$bad" >&2
    exit 1
fi

count=$(printf '%s\n' "$uses" | grep -c . || true)
echo "check-pins: all $count uses: lines are pinned by full commit hash."
