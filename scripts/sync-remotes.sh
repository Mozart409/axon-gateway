#!/usr/bin/env bash
# sync-remotes.sh — keep both git remotes of this repo in sync without
# server-side mirroring.
#
#   origin = Forgejo (canonical)   github = GitHub (manual mirror)
#
# Pull phase: fetch both, fast-forward local onto whatever is newest, merging
#             in any commits that only exist on github (e.g. pushed from
#             another machine).
# Push phase: push origin FIRST, then github — sequentially, never via
#             multiple push URLs on one remote (that poisons the
#             remote-tracking reflog and can silently drop commits on the
#             next rebase; see AGENTS.md §3 "Git Remotes").
# Tags:       synced the same way, canonical first. Tags (e.g. cog's release
#             tags) don't fast-forward like branches — if a name resolves to
#             different commits on the two remotes, `git fetch`/`git push`
#             refuse to clobber it and the script aborts instead of guessing.
#
# Anything it cannot resolve safely (diverged history with the canonical
# remote, merge conflicts, dirty tree) aborts with instructions instead of
# guessing.

set -euo pipefail

branch="${1:-main}"
canonical="origin"
mirror="github"

info() { printf '==> %s\n' "$*"; }
err() { printf 'error: %s\n' "$*" >&2; }
is_ancestor() { git merge-base --is-ancestor "$1" "$2"; }

# --- guards ---------------------------------------------------------------

current=$(git symbolic-ref --short HEAD)
if [ "$current" != "$branch" ]; then
  err "you are on '$current', not '$branch' — switch first"
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  err "working tree has uncommitted changes — commit or stash first"
  exit 1
fi

# --- fetch ----------------------------------------------------------------

info "fetching $canonical and $mirror"
git fetch "$canonical" --tags --prune
git fetch "$mirror" --tags --prune

# The mirror branch may not exist yet on a fresh remote.
mirror_ref=""
if git rev-parse --verify --quiet "$mirror/$branch" >/dev/null; then
  mirror_ref="$mirror/$branch"
fi

# --- pull phase -----------------------------------------------------------

if [ "$(git rev-parse "$branch")" != "$(git rev-parse "$canonical/$branch")" ]; then
  if is_ancestor "$branch" "$canonical/$branch"; then
    info "fast-forwarding $branch to $canonical/$branch"
    git merge --ff-only "$canonical/$branch"
  elif is_ancestor "$canonical/$branch" "$branch"; then
    info "$branch has unpushed commits for $canonical — will push below"
  else
    err "local $branch and $canonical/$branch have diverged."
    err "resolve by hand: git rebase $canonical/$branch"
    exit 1
  fi
fi

if [ -n "$mirror_ref" ] && ! is_ancestor "$mirror_ref" "$branch"; then
  if is_ancestor "$branch" "$mirror_ref"; then
    info "fast-forwarding $branch to $mirror_ref"
    git merge --ff-only "$mirror_ref"
  else
    info "$mirror has commits $canonical lacks — merging them into $branch"
    if ! git merge "$mirror_ref" -m "chore(mirror): merge $mirror-only commits into $branch"; then
      err "merge conflict. Resolve, 'git commit', then re-run this script."
      exit 1
    fi
  fi
fi

# --- push phase: canonical first, mirror second ---------------------------
# Order matters: if the canonical push fails we stop before touching the
# mirror, so github can never end up ahead of Forgejo.

info "pushing $branch to $canonical"
git push "$canonical" "$branch"

info "pushing $branch to $mirror"
git push "$mirror" "$branch"

info "pushing tags to $canonical"
git push "$canonical" --tags

info "pushing tags to $mirror"
git push "$mirror" --tags

# --- verify -----------------------------------------------------------

head_sha=$(git rev-parse "$branch")
for ref in "$canonical/$branch" "$mirror/$branch"; do
  if [ "$(git rev-parse "$ref")" != "$head_sha" ]; then
    err "$ref does not match $branch — still out of sync"
    exit 1
  fi
done

# Every local tag must exist on both remotes (name -> same object).
remote_tag_names() {
  git ls-remote --tags "$1" | awk -F/ '{sub(/\^\{\}$/, "", $NF); print $NF}' | sort -u
}

local_tags=$(git tag -l | sort)
if [ -n "$local_tags" ]; then
  for remote in "$canonical" "$mirror"; do
    remote_tags=$(remote_tag_names "$remote")
    while IFS= read -r t; do
      [ -z "$t" ] && continue
      if ! printf '%s\n' "$remote_tags" | grep -qxF "$t"; then
        err "$remote is missing tag $t — still out of sync"
        exit 1
      fi
    done <<<"$local_tags"
  done
fi

info "in sync: $branch = $canonical/$branch = $mirror/$branch (${head_sha:0:7}); tags match on both remotes"
