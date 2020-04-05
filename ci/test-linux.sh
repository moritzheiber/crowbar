#!/bin/bash

OS="${TRAVIS_OS_NAME:-linux}"

if [ "${OS}" == "linux" ] ; then
    # https://unix.stackexchange.com/a/548005
    eval "$(dbus-launch --sh-syntax)" && \
    mkdir -p ~/.cache ~/.local/share/keyrings && \
    eval "$(printf '\n' | gnome-keyring-daemon --unlock)" && \
    eval "$(printf '\n' | /usr/bin/gnome-keyring-daemon --start)" && \

    cargo test --release

else
    cargo test --release
fi
