#!/usr/bin/env bash
# This script takes care of packaging (tar.gz and zip) your crate for release

set -ex

main() {
    local crate_name="$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[0].name')"
    local crate_version="$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[0].version')"
    local rustc_target="$(rustc -Vv | grep '^host: ' | cut -d' ' -f2)"

    local package_file_name="${crate_name}-v${crate_version}-${rustc_target}"

    local package_dir_path="target/package"
    local binary_dir_path="target/debug"

    mkdir -p "${package_dir_path}"

    tar -cvzf  "${package_dir_path}/${package_file_name}.tar.gz" -C "${binary_dir_path}" "${crate_name}"
    zip -j "${package_dir_path}/${package_file_name}.zip" "${binary_dir_path}/${crate_name}"
}

main
