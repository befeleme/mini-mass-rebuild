# generate list with $ koji list-builds --owner=ksurma --after='2025-09-19 00:00' --pattern='*.fc43' --state=COMPLETE --quiet | cut -f1 -d' ' | sort | uniq

#!/bin/bash
set -eu
set -o pipefail

latest_build="$1"

echo "Processing package: $latest_build"

# Check if the build is tagged with f43-updates-candidate
if ! (koji buildinfo "$latest_build" | grep '^Tags:' | grep -qE ' f43-updates-candidate( |$)'); then
  echo "Build $latest_build is not tagged with f43-updates-candidate"
  pkgname="$(echo $latest_build | pkgname)"
  echo "$pkgname f43 build complete but not tagged: $latest_build (bodhi)" >> ${pkgname}.log
  exit 1
fi

# Create bodhi update with type bugfix
echo "Creating bodhi update for $latest_build"
bodhi updates new --type bugfix --notes "Rebuilt for Python 3.14.0rc3 bytecode change" "$latest_build"

echo "Successfully created bodhi update for $latest_build"