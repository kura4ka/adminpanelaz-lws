#!/bin/sh
set -eu

build=${1:-build}
deploy_dir=$(dirname "$0")
socket=adminpanelaz-lws-client.socket
panel=adminpanelaz-lws.service
groups=adminpanelaz-lws-client
if [ "$(id -u)" -ne 0 ]; then
    echo 'Run as root.' >&2
    exit 2
fi
test -x "$build/adminpanelaz-client"
test -x /root/antizapret/client.sh
systemctl cat "$panel" >/dev/null

getent group "$groups" >/dev/null || groupadd --system "$groups"
install -d -m 0755 /usr/local/libexec "/etc/systemd/system/$panel.d"
install -m 0755 "$build/adminpanelaz-client" /usr/local/libexec/adminpanelaz-client.next
mv -f /usr/local/libexec/adminpanelaz-client.next /usr/local/libexec/adminpanelaz-client
install -m 0644 "$deploy_dir/$socket" /etc/systemd/system/
install -m 0644 "$deploy_dir/adminpanelaz-lws-client@.service" /etc/systemd/system/
install -m 0644 "$deploy_dir/adminpanelaz-lws-client.conf" "/etc/systemd/system/$panel.d/local-vpn-client.conf"
systemctl daemon-reload
systemctl enable --now "$socket"
systemctl restart "$panel"
