#!/usr/bin/env bash
set -euo pipefail

readonly required_version="0.12.0"
readonly archive_name="bubblewrap-0.12.0.tar.xz"
readonly archive_url="https://github.com/containers/bubblewrap/releases/download/v0.12.0/${archive_name}"
# SHA-256 of the official bubblewrap 0.12.0 source archive.
readonly archive_sha256="9760d007363e3abba7c747489910f9f82d9fca53ba3bd3282e396fa3c97a3314"
readonly work_dir="$(mktemp -d)"

cleanup() {
    rm -rf "${work_dir}"
}
trap cleanup EXIT

sudo apt-get update
sudo apt-get install --yes bubblewrap curl

installed_version=""
if command -v bwrap >/dev/null 2>&1; then
    installed_version="$(bwrap --version | awk 'NR == 1 { print $2 }')"
fi

assert_non_setuid() {
    local bwrap_path
    bwrap_path="$(command -v bwrap)"
    [[ "$(stat --format='%A' "${bwrap_path}")" != *s* ]]
}

if [[ -n "${installed_version}" ]] && dpkg --compare-versions "${installed_version}" ge "${required_version}"; then
    assert_non_setuid
    bwrap --version
    exit 0
fi

sudo apt-get install --yes \
    docbook-xsl \
    libcap-dev \
    libselinux1-dev \
    libxslt1-dev \
    meson \
    ninja-build \
    pkg-config \
    xsltproc

curl --fail --silent --show-error --location "${archive_url}" --output "${work_dir}/${archive_name}"
printf '%s  %s\n' "${archive_sha256}" "${work_dir}/${archive_name}" | sha256sum --check --status

tar --extract --file "${work_dir}/${archive_name}" --directory "${work_dir}"
meson setup "${work_dir}/build" "${work_dir}/bubblewrap-0.12.0" --prefix=/usr --wrap-mode=nodownload -Dtests=false -Dman=disabled
meson compile -C "${work_dir}/build"
sudo meson install -C "${work_dir}/build"

installed_version="$(/usr/bin/bwrap --version | awk 'NR == 1 { print $2 }')"
dpkg --compare-versions "${installed_version}" ge "${required_version}"
assert_non_setuid
/usr/bin/bwrap --version
