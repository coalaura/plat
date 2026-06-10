#!/bin/bash

set -euo pipefail

# --- HARDWARE PERMISSIONS ---
# If this service requires hardware access, you likely need a udev rule
# to assign ownership to the 'plat' user.
# Example: /etc/udev/rules.d/99-plat.rules
# SUBSYSTEM=="usb", ATTRS{idVendor}=="XXXX", OWNER="plat"
# ----------------------------

echo "Linking sysusers config..."

mkdir -p /etc/sysusers.d

if [ -f /etc/sysusers.d/plat.conf ]; then
    rm /etc/sysusers.d/plat.conf
fi

ln -s "/var/plat.example.com/conf/plat.conf" /etc/sysusers.d/plat.conf

echo "Creating user..."

systemd-sysusers

echo "Linking unit..."

if [ -f /etc/systemd/system/plat.service ]; then
    rm /etc/systemd/system/plat.service
fi

systemctl link "/var/plat.example.com/conf/plat.service"

if command -v logrotate >/dev/null 2>&1; then
    echo "Linking logrotate config..."

    if [ -f /etc/logrotate.d/plat ]; then
        rm /etc/logrotate.d/plat
    fi

    ln -s "/var/plat.example.com/conf/plat_logs.conf" /etc/logrotate.d/plat
else
    echo "Logrotate not found, skipping..."
fi

echo "Reloading daemon..."

systemctl daemon-reload
systemctl enable plat

echo "Fixing initial permissions..."chown -R plat:plat "/var/plat.example.com"

find "/var/plat.example.com" -type d -exec chmod 755 {} +
find "/var/plat.example.com" -type f -exec chmod 644 {} +

chmod +x "/var/plat.example.com/plat"

echo "Setup complete, starting service..."

service plat restart

echo "Done."
