#!/bin/sh
set -eu

domain=${1:?usage: sudo sh deploy/install-systemd.sh domain [build-dir]}
build=${2:-build}
case "$domain" in *[!A-Za-z0-9.-]*|.*|-*|*.) echo 'Invalid certificate domain' >&2; exit 2 ;; esac
if [ "$(id -u)" -ne 0 ]; then
    echo 'Run as root.' >&2
    exit 2
fi
cert=/etc/letsencrypt/live/$domain
test -r "$cert/fullchain.pem"
test -r "$cert/privkey.pem"
test -x "$build/adminpanelaz-lws"
test -x "$build/adminpanelaz-openvpn-snapshot"

group=adminpanelaz-lws-vpn
getent group "$group" >/dev/null || groupadd --system "$group"
install -d -m 0755 /usr/local/bin /usr/local/libexec
install -d -m 0700 /etc/adminpanelaz-lws
if [ ! -s /etc/adminpanelaz-lws/auth.env ]; then
    token=$(openssl rand -hex 32)
    (umask 077; printf 'APAZ_AUTH_TOKEN=%s\n' "$token" > /etc/adminpanelaz-lws/auth.env)
    unset token
fi

install -m 0755 "$build/adminpanelaz-lws" /usr/local/bin/adminpanelaz-lws.next
mv -f /usr/local/bin/adminpanelaz-lws.next /usr/local/bin/adminpanelaz-lws
install -m 0755 "$build/adminpanelaz-openvpn-snapshot" /usr/local/libexec/adminpanelaz-openvpn-snapshot
install -m 0755 "$(dirname "$0")/vpn-snapshot.sh" /usr/local/libexec/adminpanelaz-lws-vpn-snapshot

cat > /etc/systemd/system/adminpanelaz-lws-vpn.service <<'UNIT'
[Unit]
Description=AdminPanelAZ LWS VPN status snapshot

[Service]
Type=oneshot
Group=adminpanelaz-lws-vpn
RuntimeDirectory=adminpanelaz-lws-vpn
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
TimeoutStartSec=20
ExecStart=/usr/local/libexec/adminpanelaz-lws-vpn-snapshot /run/adminpanelaz-lws-vpn
UNIT

cat > /etc/systemd/system/adminpanelaz-lws-vpn.timer <<'UNIT'
[Unit]
Description=Refresh AdminPanelAZ LWS VPN status

[Timer]
OnBootSec=5s
OnUnitInactiveSec=10s
AccuracySec=1s

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/adminpanelaz-lws.service <<UNIT
[Unit]
Description=AdminPanelAZ LWS
After=network.target

[Service]
DynamicUser=yes
SupplementaryGroups=$group
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
StateDirectory=adminpanelaz-lws
StateDirectoryMode=0700
EnvironmentFile=/etc/adminpanelaz-lws/auth.env
BindReadOnlyPaths=-/root/antizapret/client:/run/adminpanelaz-lws-profiles
LoadCredential=fullchain.pem:$cert/fullchain.pem
LoadCredential=privkey.pem:$cert/privkey.pem
ExecStart=/usr/local/bin/adminpanelaz-lws --bind 0.0.0.0 --port 443 --data-dir /var/lib/adminpanelaz-lws --tls-cert %d/fullchain.pem --tls-key %d/privkey.pem \\
  --auth-db /var/lib/private/adminpanelaz-lws/auth.db --profiles-dir /run/adminpanelaz-lws-profiles \\
  --openvpn-status /run/adminpanelaz-lws-vpn/openvpn-antizapret-udp.status \\
  --openvpn-status /run/adminpanelaz-lws-vpn/openvpn-antizapret-tcp.status \\
  --openvpn-status /run/adminpanelaz-lws-vpn/openvpn-vpn-udp.status \\
  --openvpn-status /run/adminpanelaz-lws-vpn/openvpn-vpn-tcp.status \\
  --wireguard-status /run/adminpanelaz-lws-vpn/wireguard.status
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
UNIT

install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/adminpanelaz-lws <<HOOK
#!/bin/sh
if [ "\${RENEWED_LINEAGE:-}" = "$cert" ]; then
    systemctl try-restart adminpanelaz-lws.service
fi
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/adminpanelaz-lws

systemctl daemon-reload
systemctl enable --now adminpanelaz-lws-vpn.timer
systemctl start adminpanelaz-lws-vpn.service
systemctl enable adminpanelaz-lws.service
systemctl reset-failed adminpanelaz-lws.service
systemctl restart adminpanelaz-lws.service
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if curl --fail --silent --max-time 2 --resolve "$domain:443:127.0.0.1" "https://$domain/api/health" >/dev/null; then
        exit 0
    fi
    sleep 1
done
systemctl --no-pager --lines=8 status adminpanelaz-lws.service >&2 || :
exit 1
