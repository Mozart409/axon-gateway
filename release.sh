#!/bin/sh
set -eu

# Release via cocogitto (cog): it computes the next version from the
# conventional commits since the last tag, bumps Cargo.toml/Cargo.lock
# (pre_bump_hooks in cog.toml), updates CHANGELOG.md, and creates the
# bump commit + tag. This script adds the guardrails and pushes.

# Must be on main
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" != "main" ]; then
    echo "Error: releases must be cut from 'main' (currently on '$BRANCH')"
    exit 1
fi

# Working tree must be clean (cog creates the version-bump changes itself)
if [ -n "$(git status --porcelain)" ]; then
    echo "Error: working tree has uncommitted changes; commit or stash first"
    exit 1
fi

# Run tests before mutating anything
echo "Running cargo test..."
cargo test

# Let cog determine and perform the bump (version + changelog + commit + tag)
echo "Bumping version with cog..."
cog bump --auto

# cog created a commit + tag on the current branch; discover the new tag
TAG=$(git describe --tags --abbrev=0)
echo "Created release ${TAG}"

# Push the bump commit and the tag
echo "Pushing to origin..."
git push origin main
git push origin "${TAG}"

echo "Release ${TAG} complete!"
