#!/bin/bash

set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
    echo "Run this script as root." >&2
    exit 1
fi

name="plat"
path="/var/dns.example.com"
conf_dir="${path}/conf"

sysusers_file="/etc/sysusers.d/${name}.conf"

if [ -L "${path}" ] || [ ! -d "${path}" ]; then
    echo "Service path must be an existing, real directory: ${path}" >&2
    exit 1
fi

script_root=$(realpath "$(dirname "${BASH_SOURCE[0]}")/..")
service_root=$(realpath "${path}")

if [ "${script_root}" != "${service_root}" ]; then
    echo "Run the setup script from ${path}/conf." >&2
    exit 1
fi

# A writable ancestor would let another user replace the root-owned log hierarchy.
if [ "${service_root}" != "${path}" ]; then
    echo "File logging requires a canonical service path without symlinks: ${path}" >&2
    exit 1
fi

parent=$(dirname "${path}")

while true; do
    read -r owner mode < <(stat -c '%u %a' "${parent}")

    if [ "${owner}" -ne 0 ] || (( (8#${mode} & 0022) != 0 )); then
        echo "File logging requires root-owned ancestors without group/other write access: ${parent}" >&2
        exit 1
    fi

    if [ "${parent}" = / ]; then
        break
    fi

    parent=$(dirname "${parent}")
done

for file in "${conf_dir}/${name}.conf" "${conf_dir}/${name}.service" "${conf_dir}/${name}_logs.conf"; do
    if [ -L "${file}" ] || [ ! -f "${file}" ]; then
        echo "Missing or unsafe generated file: ${file}" >&2
        exit 1
    fi
done

# Rotation is required for file logging, before stopping the existing service.
if ! command -v logrotate >/dev/null 2>&1; then
    echo "File logging requires logrotate." >&2
    exit 1
fi

(
    rotation_check=$(mktemp)
    trap 'rm -f -- "${rotation_check}"' EXIT
    install -o root -g root -m 0600 "${conf_dir}/${name}_logs.conf" "${rotation_check}"
    logrotate --debug "${rotation_check}"
)

if [ -L "${path}/${name}" ] || [ ! -f "${path}/${name}" ]; then
    echo "Missing or unsafe service executable: ${path}/${name}" >&2
    exit 1
fi

echo "Stopping existing service..."

load_state=$(systemctl show --property=LoadState --value "${name}.service")

if [ "${load_state}" != not-found ]; then
    systemctl stop "${name}.service"
fi

# Lock the parent before migrating any service-owned log directory.
chown root:root "${path}"
chmod 0755 "${path}"

echo "Installing sysusers config..."

if [ -e "${sysusers_file}" ] || [ -L "${sysusers_file}" ]; then
    if [ -L "${sysusers_file}" ] || [ ! -f "${sysusers_file}" ] || ! cmp -s "${conf_dir}/${name}.conf" "${sysusers_file}"; then
        echo "Refusing to replace conflicting sysusers policy: ${sysusers_file}" >&2
        exit 1
    fi

    systemd-sysusers "${sysusers_file}"
else
    if getent passwd "${name}" >/dev/null || getent group "${name}" >/dev/null; then
        passwd_entry=$(getent passwd "${name}" || true)
        group_entry=$(getent group "${name}" || true)
        user_home=$(printf '%s' "${passwd_entry}" | cut -d: -f6)
        user_shell=$(printf '%s' "${passwd_entry}" | cut -d: -f7)

        if [ -z "${passwd_entry}" ] || [ -z "${group_entry}" ] || [ "${user_home}" != "${path}" ] || \
            { [ "${user_shell}" != "/sbin/nologin" ] && [ "${user_shell}" != "/usr/sbin/nologin" ]; }; then
            echo "Refusing to reuse existing user or group: ${name}" >&2
            exit 1
        fi

        echo "Adopting service identity created by an older release..."
    fi

    install -o root -g root -m 0644 "${conf_dir}/${name}.conf" "${sysusers_file}"
    systemd-sysusers "${sysusers_file}"
fi

passwd_entry=$(getent passwd "${name}" || true)
group_entry=$(getent group "${name}" || true)
user_home=$(printf '%s' "${passwd_entry}" | cut -d: -f6)
user_shell=$(printf '%s' "${passwd_entry}" | cut -d: -f7)

if [ -z "${passwd_entry}" ] || [ -z "${group_entry}" ] || [ "${user_home}" != "${path}" ] || \
    { [ "${user_shell}" != "/sbin/nologin" ] && [ "${user_shell}" != "/usr/sbin/nologin" ]; }; then
    echo "Service identity does not match generated policy: ${name}" >&2
    exit 1
fi

echo "Installing unit..."

install -o root -g root -m 0644 "${conf_dir}/${name}.service" "/etc/systemd/system/${name}.service"

echo "Setting permissions..."

if [[ -f "${conf_dir}/svc.yml" ]]; then
    chown root:root "${conf_dir}/svc.yml"
    chmod 0700 "${conf_dir}/svc.yml"
fi

chown root:root "${path}" "${conf_dir}" "${path}/${name}" "${conf_dir}/${name}.conf" "${conf_dir}/${name}.service" "${conf_dir}/${name}_logs.conf" "${conf_dir}/setup.sh" "${conf_dir}/uninstall.sh"
chmod 0755 "${path}"
chmod 0755 "${conf_dir}"
chmod 0755 "${path}/${name}"
chmod 0644 "${conf_dir}/${name}.conf" "${conf_dir}/${name}.service" "${conf_dir}/${name}_logs.conf"
chmod 0700 "${conf_dir}/setup.sh" "${conf_dir}/uninstall.sh"

# The service must never be able to replace a pathname opened by systemd as root.
log_dir="${path}/logs"
log_file="${log_dir}/${name}.log"

if [ -L "${log_dir}" ] || { [ -e "${log_dir}" ] && [ ! -d "${log_dir}" ]; }; then
    echo "Refusing unsafe log directory: ${log_dir}" >&2
    exit 1
fi

# Also migrates older service-owned log directories, without removing their contents.
install -d -o root -g "${name}" -m 0750 "${log_dir}"

check_log_file() {
    if [ -L "$1" ] || { [ -e "$1" ] && [ ! -f "$1" ]; }; then
        echo "Refusing unsafe log file: $1" >&2
        exit 1
    fi

    if [ -e "$1" ] && [ "$(stat -c %h "$1")" -ne 1 ]; then
        echo "Refusing hard-linked log file: $1" >&2
        exit 1
    fi
}

check_log_file "${log_file}"

if [ ! -e "${log_file}" ]; then
    (umask 0077; set -o noclobber; : > "${log_file}")
fi

chown "root:${name}" "${log_file}"
chmod 0660 "${log_file}"

# Rotation now runs as root; reject unsafe legacy archives before enabling it.
for archive in "${log_file}".[0-9]*; do
    if [ ! -e "${archive}" ] && [ ! -L "${archive}" ]; then
        continue
    fi

    check_log_file "${archive}"
    chown "root:${name}" "${archive}"
    chmod 0640 "${archive}"
done

echo "Installing logrotate config for the host's existing rotation schedule..."

install -o root -g root -m 0644 "${conf_dir}/${name}_logs.conf" "/etc/logrotate.d/${name}"

# A data-directory symlink must not undo log-directory ownership established above.
if [ -L "${path}/data" ] || { [ -e "${path}/data" ] && [ ! -d "${path}/data" ]; }; then
    echo "Refusing unsafe data directory: ${path}/data" >&2
    exit 1
fi

install -d -o "${name}" -g "${name}" -m 0750 "${path}/data"

echo "Reloading daemon..."

systemctl daemon-reload
systemctl enable "${name}"

echo "Setup complete, starting service..."

systemctl restart "${name}"

echo "Done."
