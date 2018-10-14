# This script takes care of packaging your binary for release

set -ex

local src=$(pwd) \
      stage=

case $TRAVIS_OS_NAME in
    linux)
        stage=$(mktemp -d)
        ;;
    osx)
        stage=$(mktemp -d -t tmp)
        ;;
esac

# TODO Update this to package the right artifacts
cp target/release/oktaws $stage/

TOOLCHAIN="$(rustup show active-toolchain)"

cd $stage
tar czf $src/$CRATE_NAME-$TRAVIS_TAG-$TOOLCHAIN.tar.gz *
cd $src

rm -rf $stage
