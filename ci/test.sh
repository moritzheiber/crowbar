#!/bin/bash

set -Eeux -o pipefail

# https://unix.stackexchange.com/a/548005
export $(dbus-launch) && \
mkdir -p ~/.cache ~/.local/share/keyrings && \
eval "$(printf '\n' | gnome-keyring-daemon --unlock)" && \
eval "$(printf '\n' | /usr/bin/gnome-keyring-daemon --start)"

sleep 5

cargo test --release --locked
