#!/bin/bash

set -euo pipefail

echo "Stopping service..."
systemctl stop "plat" 2>/dev/null || true

echo "Disabling service..."
systemctl disable "plat" 2>/dev/null || true

echo "Removing unit file..."
rm -f "/etc/systemd/system/plat.service"

echo "Removing sysusers config..."
rm -f "/etc/sysusers.d/plat.conf"

if [ -f "/etc/logrotate.d/plat" ]; then
    echo "Removing logrotate config..."
    rm -f "/etc/logrotate.d/plat"
fi

echo "Reloading daemon..."
systemctl daemon-reload
systemctl reset-failed "plat" 2>/dev/null || true

echo "Removing user and group..."
if id "plat" &>/dev/null; then
    userdel "plat" 2>/dev/null || true
fi

if getent group "plat" &>/dev/null; then
    groupdel "plat" 2>/dev/null || true
fi

echo "Uninstall complete."
