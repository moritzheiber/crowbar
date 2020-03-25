#!/bin/bash

set -Eeux -o pipefail

main() {
    local crate_name="$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[0].name')"
    local crate_version="$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[0].version')"
    local rustc_target="$(rustc -Vv | grep '^host: ' | cut -d' ' -f2)"

    local package_file_name="${crate_name}-v${crate_version}-${rustc_target}"

    local package_dir_path="target/package"
    local binary_dir_path="target/release"

    mkdir -p "${package_dir_path}"

    cp "${binary_dir_path}/${crate_name}" "${package_dir_path}/${package_file_name}"
}

main
