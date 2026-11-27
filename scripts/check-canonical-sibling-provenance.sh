#!/usr/bin/env bash
set -euo pipefail

# No path overrides are accepted: production provenance comes only from this
# tracked checkout and the sibling Cargo resolves from its own manifest.
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
sibling_root="$repo_root/../catbird-mls"
manifest="$repo_root/scripts/canonical-sibling-provenance.env"

if [[ $# -ne 0 ]]; then
  printf 'usage: %s\n' "$0" >&2
  exit 2
fi

[[ -f "$repo_root/Cargo.toml" ]] || { printf 'Cargo.toml not found: %s\n' "$repo_root/Cargo.toml" >&2; exit 1; }
[[ -f "$manifest" ]] || { printf 'provenance manifest not found: %s\n' "$manifest" >&2; exit 1; }
[[ -f "$repo_root/Cargo.lock" ]] || { printf 'tracked Cargo.lock not found: %s\n' "$repo_root/Cargo.lock" >&2; exit 1; }
[[ -d "$sibling_root" ]] || { printf 'catbird-mls sibling not found: %s\n' "$sibling_root" >&2; exit 1; }

manifest_value() {
  local key=$1 value
  value=$(awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$manifest")
  [[ -n "$value" ]] || { printf 'missing provenance value: %s\n' "$key" >&2; exit 1; }
  printf '%s' "$value"
}

expected_lock=$(manifest_value BIR_DAEMON_LOCK_SHA256)

actual_lock=$(shasum -a 256 "$repo_root/Cargo.lock" | awk '{print $1}')
if [[ "$actual_lock" != "$expected_lock" ]]; then
  printf 'Cargo.lock provenance mismatch: expected %s, got %s\n' "$expected_lock" "$actual_lock" >&2
  exit 1
fi

metadata=$(mktemp)
metadata_error=$(mktemp)
trap 'rm -f "$metadata" "$metadata_error"' EXIT
if ! CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo metadata \
  --manifest-path "$repo_root/Cargo.toml" --format-version 1 --locked > "$metadata" 2>"$metadata_error"; then
  printf 'locked Cargo metadata failed; refusing unverified sibling provenance\n' >&2
  cat "$metadata_error" >&2
  exit 1
fi
# Verify each repository against its immutable revision. Different jj workspaces
# can have different empty working-copy commit IDs for the exact same source.
verify_sibling() {
  local package=$1 prefix=$2 directory=$3 path=$4
  local resolved root commit tree gitdir current
  resolved=$(jq -er --arg name "$package" '
    [.packages[] | select(.name == $name and .source == null) | .manifest_path]
    | if length == 1 then .[0] else error("expected one local package " + $name) end' "$metadata")
  root=$(cd "$repo_root/../$directory" && pwd -P)
  [[ "$(cd "$(dirname "$resolved")" && pwd -P)/$(basename "$resolved")" == "$root/$path" ]] || {
    echo "Unexpected resolved manifest for $package" >&2
    return 1
  }
  commit=$(manifest_value "${prefix}_COMMIT")
  tree=$(manifest_value "${prefix}_TREE")
  if [[ -d "$root/.jj" ]]; then
    current=$(cd "$root" && jj log -r @ --no-graph -T commit_id)
    gitdir=$(cd "$root" && jj git root)
    [[ "$(cd "$root" && jj log -r "$commit & ::@" --no-graph -T commit_id)" == "$commit" ]]
    [[ -z "$(cd "$root" && jj diff --summary -r @)" ]]
  else
    gitdir=$(git -C "$root" rev-parse --absolute-git-dir)
    current=$(git -C "$root" rev-parse HEAD)
    [[ "$current" == "$commit" ]]
    [[ -z "$(git -C "$root" status --porcelain)" ]]
  fi
  [[ "$(git --git-dir="$gitdir" rev-parse "$current^{tree}")" == "$tree" ]]
  printf 'Verified %s %s\n' "$package" "$commit"
}

verify_sibling catbird_mls CATBIRD_MLS catbird-mls Cargo.toml
verify_sibling petrel PETREL Petrel rust/petrel/Cargo.toml
verify_sibling petrel-catbird PETREL_CATBIRD PetrelCatbird rust/petrel-catbird/Cargo.toml
verify_sibling atproto-spaces CATBIRD_ATPROTO catbird-atproto atproto-spaces/Cargo.toml
verify_sibling labyrinth LABYRINTH labyrinth Cargo.toml
expected_features=$(manifest_value CATBIRD_MLS_FEATURES_JSON)
jq -e --argjson expected "$expected_features" '
  (.packages[] | select(.name == "catbird_mls") | .id) as $id
  | (.resolve.nodes[] | select(.id == $id) | .features | sort) == ($expected | sort)
' "$metadata" >/dev/null
printf 'Verified lock %s and MLS features %s\n' "$actual_lock" "$expected_features"
