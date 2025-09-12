set -eu
set -o pipefail

pkg="$1"

running_build="$(koji list-builds --quiet --package=$pkg --after='2025-08-12 14:00' --state=BUILDING  --sort-key=build_id | cut -f1 -d' ' | grep '.fc44$' | tail -n1 || true)"
if [[ ! -z "$running_build" ]]; then
  echo "$pkg f44 build running: $running_build" >> ${pkg}.log
  exit 0
fi

complete_build="$(koji list-builds --quiet --package=$pkg --after='2025-08-12 14:00' --state=COMPLETE  --sort-key=build_id | cut -f1 -d' ' | grep '.fc44$' | tail -n1 || true)"
if [[ ! -z "$complete_build" ]]; then
  if ! (koji buildinfo "$complete_build" | grep '^Tags:' | grep -qE ' f44(-updates-candidate)?( |$)'); then
    echo "$pkg f44 build complete but not tagged: $complete_build" >> ${pkg}.log
    exit 0
  fi
fi


fedpkg clone "$pkg" -- --branch rawhide 2>&1 | tee ${pkg}.log
cd "$pkg"

head="$(git rev-parse rawhide)"
f43="$(git rev-parse origin/f43)"


if [[ "$head" == "$f43" ]]; then
  ff="yes"
  running_build="$(koji list-builds --quiet --package=$pkg --after='2025-08-12 14:00' --state=BUILDING  --sort-key=build_id | cut -f1 -d' ' | grep '.fc43$' | tail -n1 || true)"
  if [[ ! -z "$running_build" ]]; then
    echo "$pkg f43 build running: $running_build" >> ../${pkg}.log
    ff="no"
  else
    complete_build="$(koji list-builds --quiet --package=$pkg --after='2025-08-12 14:00' --state=COMPLETE  --sort-key=build_id | cut -f1 -d' ' | grep '.fc43$' | tail -n1 || true)"
    if [[ ! -z "$complete_build" ]]; then
      if ! (koji buildinfo "$complete_build" | grep '^Tags:' | grep -qE ' f43( |$)'); then
        echo "$pkg f43 build complete but not tagged: $complete_build" >> ../${pkg}.log
        ff="no"
      else
        # Get the commit hash this build was made from
        build_commit="$(koji buildinfo "$complete_build" | grep '^Source:' | sed 's/.*#//')"
        if [[ "$head" != "$build_commit" ]]; then
          echo "$pkg f43 build complete but not from the latest commit from distgit: $complete_build" >> ../${pkg}.log
          ff="no"
        fi
      fi
    fi
  fi
else
  echo "$pkg f43 and rawhide branches differ" >> ../${pkg}.log
  ff="no"
fi

if ! git show --name-only | grep -F "Python 3.14.0rc3"; then
  rpmdev-bumpspec -c "Rebuilt for Python 3.14.0rc3 bytecode" --userstring="Python Maint <python-maint@redhat.com>" *.spec | tee -a ../${pkg}.log
  git commit -am "Rebuilt for Python 3.14.0rc3 bytecode" --author="Python Maint <python-maint@redhat.com>" --allow-empty | tee -a ../${pkg}.log
  git push --no-verify
  if [[ "$ff" == "yes" ]]; then
    git switch f43
    git merge rawhide
    git push --no-verify
  fi
fi
fedpkg --release rawhide build --fail-fast --nowait --background 2>&1 | tee -a ../${pkg}.log
if [[ "$ff" == "yes" ]]; then
  fedpkg --release f43 build --fail-fast --nowait --background 2>&1 | tee -a ../${pkg}.log
fi

cd ..
rm -rf "$pkg"
