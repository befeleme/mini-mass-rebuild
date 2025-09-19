#!/bin/bash
set -eu
set -o pipefail

pkg="$1"

echo "Processing package: $pkg"

# Find the latest koji build for the package in f43
latest_build="$(koji list-builds --quiet --package=$pkg --state=COMPLETE --sort-key=build_id | cut -f1 -d' ' | grep '.fc43$' | tail -n1 || true)"

if [[ -z "$latest_build" ]]; then
  echo "No complete f43 builds found for $pkg"
  echo "$pkg" >> bodhi-pending.pkgs
  exit 1
fi

echo "Found latest build: $latest_build"

# Check if the build is tagged with f43-updates-candidate
if ! (koji buildinfo "$latest_build" | grep '^Tags:' | grep -qE ' f43-updates-candidate( |$)'); then
  echo "Build $latest_build is not tagged with f43-updates-candidate"
  echo "$pkg" >> bodhi-pending.pkgs
  exit 1
fi

echo "Build $latest_build is properly tagged with f43-updates-candidate"

# Create bodhi update with type bugfix
echo "Creating bodhi update for $latest_build"
bodhi updates new --type bugfix --notes "Rebuilt for Python 3.14.0rc3 bytecode change" "$latest_build"

echo "Successfully created bodhi update for $latest_build"