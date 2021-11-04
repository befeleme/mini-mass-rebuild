set -o pipefail  # make tee preserve the exit code
fedpkg clone $1 -- --branch rawhide 2>&1 | tee ./${1}.log || exit $?

cd $1
  fedpkg build --fail-fast --nowait --background --scratch 2>&1 | tee -a ../${1}.log
cd -

rm -rf $1
