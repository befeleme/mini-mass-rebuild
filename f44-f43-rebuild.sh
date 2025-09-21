set -eu
set -o pipefail

pkg="$1"
test -f ${pkg}.log2 || exit 0

for build in $(grep taskID= ${pkg}.log2 | cut -f2 -d=); do
  #grep $build open.lst || continue
  koji taskinfo --verbose $build > $build.info
  if grep -q '^State: failed$' $build.info; then
    source="$(grep '^  Source: ' $build.info | cut -d' ' -f4)"
    target="$(grep '^  Build Target: ' $build.info | cut -d' ' -f5)"
    koji build --nowait --fail-fast --background "$target" "$source" 2>&1 | tee -a ${pkg}.log3
  elif grep -q '^State: open$' $build.info; then
    echo $build >> open.lst
  fi
  rm -f $build.info
done
