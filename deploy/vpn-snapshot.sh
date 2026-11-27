#!/bin/sh
set -eu

state=${1:?specify the snapshot directory}
openvpn=${OPENVPN_SOCKET_DIR:-/run/openvpn-server}
reader=${OPENVPN_SNAPSHOT_BIN:-/usr/local/libexec/adminpanelaz-openvpn-snapshot}
umask 027
work=$(mktemp -d "$state/.snapshot.XXXXXX")
trap 'rm -f "$work"/openvpn.status "$work"/wireguard.status "$work"/allowed "$work"/endpoint "$work"/counters "$work"/handshake "$work"/config-list; rmdir "$work"' EXIT

config_source=${APAZ_ANTIZAPRET_CONFIG_DIR:-/root/antizapret/config}
config_snapshot=$state/configs
snapshot_ready=0
if [ "${APAZ_SNAPSHOT_VPN_LISTS:-0}" = 1 ] &&
    [ -d "$config_source" ] && [ ! -L "$config_source" ]; then
    snapshot_ready=1
    mkdir -m 0750 -p "$config_snapshot"
fi

if [ -d "$config_snapshot" ]; then
    # Only plain routing lists and RPZ data. Knot Resolver Lua files are not copied.
    for name in include-hosts.txt exclude-hosts.txt include-ips.txt exclude-ips.txt \
        allow-ips.txt drop-ips.txt forward-ips.txt include-adblock-hosts.txt \
        exclude-adblock-hosts.txt remove-hosts.txt deny-ips.txt include-warp-hosts.txt \
        exclude-warp-hosts.txt deny-rpz.txt deny2-rpz.txt deny3-rpz.txt warp-rpz.txt proxy-rpz.txt; do
        source=$config_source/$name
        destination=$config_snapshot/$name
        if [ "$snapshot_ready" = 1 ] && [ -f "$source" ] && [ ! -L "$source" ] &&
            [ "$(stat -c '%h' -- "$source")" = 1 ] &&
            dd if="$source" of="$work/config-list" iflag=nofollow,nonblock,count_bytes,fullblock \
                count=32769 status=none; then
            # One byte beyond the editor limit lets it report an oversized source.
            if ! cmp -s "$work/config-list" "$destination"; then
                mv -f "$work/config-list" "$destination"
            fi
        else
            rm -f "$destination"
        fi
    done
    if [ "$snapshot_ready" != 1 ]; then
        rmdir "$config_snapshot" 2>/dev/null || :
    fi
fi

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
