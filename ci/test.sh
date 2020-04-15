#!/bin/bash

if [ "${GITHUB_ACTIONS_OS}" == "linux" ] ; then
    # https://unix.stackexchange.com/a/548005
    eval "$(dbus-launch --sh-syntax)" && \
    mkdir -p ~/.cache ~/.local/share/keyrings && \
    eval "$(printf '\n' | gnome-keyring-daemon --unlock)" && \
    eval "$(printf '\n' | /usr/bin/gnome-keyring-daemon --start)" && \

    cargo test --release --locked

else
    cargo test --release --locked
fi
