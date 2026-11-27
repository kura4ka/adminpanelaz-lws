#!/bin/sh
set -eu

state=${1:?specify the snapshot directory}
openvpn=${OPENVPN_SOCKET_DIR:-/run/openvpn-server}
reader=${OPENVPN_SNAPSHOT_BIN:-/usr/local/libexec/adminpanelaz-openvpn-snapshot}
umask 027
work=$(mktemp -d "$state/.snapshot.XXXXXX")
trap 'rm -f "$work"/openvpn.status "$work"/wireguard.status "$work"/allowed "$work"/endpoint "$work"/counters "$work"/handshake; rmdir "$work"' EXIT

for profile in antizapret-udp antizapret-tcp vpn-udp vpn-tcp; do
    destination=$state/openvpn-$profile.status
    if [ -S "$openvpn/$profile.sock" ] && "$reader" "$openvpn/$profile.sock" > "$work/openvpn.status"; then
        mv -f "$work/openvpn.status" "$destination"
    else
        rm -f "$destination"
    fi
done

if command -v wg >/dev/null 2>&1 &&
    wg show all allowed-ips > "$work/allowed" &&
    wg show all endpoints > "$work/endpoint" &&
    wg show all transfer > "$work/counters" &&
    wg show all latest-handshakes > "$work/handshake"; then
    awk -F '\t' '
        BEGIN { print "WIREGUARD_STATUS_V1" }
        FILENAME == ARGV[1] { key = $1 SUBSEP $2; endpoints[key] = $3; next }
        FILENAME == ARGV[2] { key = $1 SUBSEP $2; rx[key] = $3; tx[key] = $4; next }
        FILENAME == ARGV[3] { key = $1 SUBSEP $2; handshake[key] = $3; next }
        NF >= 2 {
            key = $1 SUBSEP $2
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $1, substr($2, 1, 12),
                (key in endpoints ? endpoints[key] : "(none)"), ($3 != "" ? $3 : "(none)"),
                (key in rx ? rx[key] : "0"), (key in tx ? tx[key] : "0"),
                (key in handshake ? handshake[key] : "0")
        }
        END { print "END" }
    ' "$work/endpoint" "$work/counters" "$work/handshake" "$work/allowed" > "$work/wireguard.status"
    mv -f "$work/wireguard.status" "$state/wireguard.status"
else
    rm -f "$state/wireguard.status"
fi
