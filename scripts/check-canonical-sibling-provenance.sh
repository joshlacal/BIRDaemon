#!/usr/bin/env bash
set -euo pipefail

# Checks provenance of the canonical catbird-mls core dependency.
# Verifies the exact locked Cargo.lock hash, toolchain, resolved features,
# and either the immutable sibling repository or immutable Git dependency.
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$repo_root/scripts/canonical-sibling-provenance.env"

if [[ $# -ne 0 ]]; then
  printf 'usage: %s\n' "$0" >&2
  exit 2
fi
for required in Cargo.toml Cargo.lock scripts/canonical-sibling-provenance.env; do
  [[ -f "$repo_root/$required" ]] || { printf 'missing provenance input: %s\n' "$required" >&2; exit 1; }
done
manifest_value() {
  local key=$1 value
  value=$(awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$manifest")
  [[ -n "$value" ]] || { printf 'missing provenance value: %s\n' "$key" >&2; exit 1; }
  printf '%s' "$value"
}
expected_commit=$(manifest_value CATBIRD_MLS_COMMIT)
expected_repository=$(manifest_value CATBIRD_MLS_REPOSITORY)
expected_features=$(manifest_value CATBIRD_MLS_FEATURES_JSON)
expected_lock=$(manifest_value BIR_DAEMON_LOCK_SHA256)
expected_toolchain=$(manifest_value RUST_TOOLCHAIN)
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || { printf 'invalid immutable commit\n' >&2; exit 1; }
actual_lock=$(shasum -a 256 "$repo_root/Cargo.lock" | awk '{print $1}')
if [[ "$actual_lock" != "$expected_lock" ]]; then
  printf 'Cargo.lock provenance mismatch: expected %s, got %s\n' "$expected_lock" "$actual_lock" >&2
  exit 1
fi
# Retain diagnostic inputs in a private temporary directory; do not remove user
# files or mutate any repository while verifying provenance.
receipt_dir=$(mktemp -d "${TMPDIR:-/tmp}/bird-provenance.XXXXXX")
trap 'rm -rf "$receipt_dir"' EXIT
metadata="$receipt_dir/metadata.json"
if ! CMAKE_POLICY_VERSION_MINIMUM=3.5 rustup run "$expected_toolchain" cargo metadata \
  --manifest-path "$repo_root/Cargo.toml" --format-version 1 --locked > "$metadata" 2>"$receipt_dir/metadata.stderr"; then
  printf 'locked Cargo metadata failed; refusing unverified dependency provenance (%s)\n' "$receipt_dir" >&2
  cat "$receipt_dir/metadata.stderr" >&2
  exit 1
fi

jq -e --argjson expected_features "$expected_features" '
  [.packages[] | select(.name == "catbird_mls")] as $packages |
  if ($packages | length) != 1 then error("expected exactly one catbird_mls package") else
    $packages[0] as $package |
    [.resolve.nodes[] | select(.id == $package.id)] as $nodes |
    if ($nodes | length) != 1 then error("missing resolved catbird_mls feature node") else
      if ($nodes[0].features | sort) != ($expected_features | sort) then
        error("catbird_mls resolved feature set changed")
      else true end
    end
  end
' "$metadata" >/dev/null

package_source=$(jq -r '[.packages[] | select(.name == "catbird_mls")][0].source // "path"' "$metadata")
if [[ "$package_source" == "path" ]]; then
  expected_child=$(manifest_value CATBIRD_MLS_CHILD)
  expected_tree=$(manifest_value CATBIRD_MLS_TREE)
  sibling_root="$repo_root/../catbird-mls"
  [[ -d "$sibling_root" ]] || { printf 'catbird-mls sibling not found: %s\n' "$sibling_root" >&2; exit 1; }

  resolved_mls_manifest=$(jq -er '[.packages[] | select(.name == "catbird_mls") | .manifest_path] | if length == 1 then .[0] else error("expected one catbird_mls package") end' "$metadata")
  expected_mls_manifest=$(cd "$sibling_root" && pwd)/Cargo.toml
  if [[ "$resolved_mls_manifest" != "$expected_mls_manifest" ]]; then
    printf 'Cargo resolved catbird_mls outside checked sibling\nexpected: %s\nactual:   %s\n' \
      "$expected_mls_manifest" "$resolved_mls_manifest" >&2
    exit 1
  fi

  if [[ -d "$sibling_root/.jj" ]] && command -v jj >/dev/null 2>&1; then
    status_output=$(cd "$sibling_root" && jj st)
    if ! grep -Fq 'The working copy has no changes.' <<<"$status_output"; then
      printf 'catbird-mls sibling is dirty or conflicted: %s\n%s\n' "$sibling_root" "$status_output" >&2
      exit 1
    fi

    actual_child=$(cd "$sibling_root" && jj log -r '@' --no-graph -T 'commit_id')
    actual_parent=$(cd "$sibling_root" && jj log -r '@-' --no-graph -T 'commit_id')
    actual_tree=$(cd "$sibling_root" && jj debug object commit "$actual_child" | awk '/TreeId\(/ { getline; gsub(/[",[:space:]]/, ""); print; exit }')

    if [[ "$actual_child" != "$expected_child" || "$actual_parent" != "$expected_commit" || "$actual_tree" != "$expected_tree" ]]; then
      printf 'catbird-mls provenance mismatch\nexpected child: %s\nactual child:   %s\nexpected parent: %s\nactual parent:   %s\nexpected tree:   %s\nactual tree:     %s\n' \
        "$expected_child" "$actual_child" "$expected_commit" "$actual_parent" "$expected_tree" "$actual_tree" >&2
      exit 1
    fi
  else
    status_output=$(git -C "$sibling_root" status --porcelain --untracked-files=all)
    if [[ -n "$status_output" ]]; then
      printf 'catbird-mls sibling is dirty or conflicted: %s\n%s\n' "$sibling_root" "$status_output" >&2
      exit 1
    fi

    actual_parent=$(git -C "$sibling_root" rev-parse HEAD)
    actual_tree=$(git -C "$sibling_root" rev-parse 'HEAD^{tree}')
    actual_child="git-head:$actual_parent"

    if [[ "$actual_parent" != "$expected_commit" || "$actual_tree" != "$expected_tree" ]]; then
      printf 'catbird-mls provenance mismatch\nexpected commit: %s\nactual commit:   %s\nexpected tree:   %s\nactual tree:     %s\n' \
        "$expected_commit" "$actual_parent" "$expected_tree" "$actual_tree" >&2
      exit 1
    fi
  fi

  printf 'exact Cargo-resolved catbird-mls and lock provenance verified: manifest=%s commit=%s child=%s tree=%s features=%s lock=%s toolchain=%s\n' \
    "$resolved_mls_manifest" "$actual_parent" "$actual_child" "$actual_tree" "$expected_features" "$actual_lock" "$expected_toolchain"
else
  expected_source="git+$expected_repository?rev=$expected_commit#$expected_commit"
  if [[ "$package_source" != "$expected_source" ]]; then
    printf 'catbird_mls source mismatch: expected %s, got %s\n' "$expected_source" "$package_source" >&2
    exit 1
  fi
  printf 'immutable Cargo-resolved core verified: source=%s features=%s lock=%s toolchain=%s\n' \
    "$expected_source" "$expected_features" "$actual_lock" "$expected_toolchain"
fi
