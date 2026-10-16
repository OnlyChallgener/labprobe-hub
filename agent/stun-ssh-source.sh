#!/bin/sh
# Reconcile only TCP SSH STUN rules whose destination is reached through LAN.
# This separate service does not restart LabRelay or its traffic recognition.
set -u
CONFIG=${SHINYA_STUN_CONFIG:-/etc/labprobe/relay.json}
LAN=${SHINYA_STUN_LAN:-br-lan}
STATE=${SHINYA_STUN_STATE:-/tmp/shinya-stun-ssh}
IPTABLES=${SHINYA_STUN_IPTABLES:-iptables}
IP=${SHINYA_STUN_IP:-ip}
JQ=${SHINYA_STUN_JQ:-jq}
TAG=shinya-ssh-stun
A=SHINYA_SSH_A
B=SHINYA_SSH_B
mkdir -p "$STATE"

ipv4() {
    printf '%s\n' "$1" | awk -F. 'NF!=4{exit 1}{for(i=1;i<=4;i++)if($i!~/^[0-9]+$/||$i>255)exit 1}'
}
private4() {
    ipv4 "$1" || return 1
    printf '%s\n' "$1" | awk -F. '!(($1==10)||($1==192&&$2==168)||($1==172&&$2>=16&&$2<=31)){exit 1}'
}
plan() {
    "$JQ" -e '(.rules|type)=="array"' "$CONFIG" >/dev/null 2>&1 || return 1
    "$JQ" -r '.rules[] | select(.kind=="stun" and .serviceType=="SSH" and .transportProtocol=="TCP" and .enabled==true and .forwardMode=="router_native" and ((.expiresAt//0)==0 or .expiresAt>now)) | [.id,.targetIpv4,.targetPort,.listenPort] | @tsv' "$CONFIG" >"$STATE/candidates" || return 1
    : >"$STATE/next"
    while IFS="$(printf '\t')" read -r id dest port listen; do
        case "$id" in ''|*[!a-zA-Z0-9_-]*) continue;; esac
        [ ${#id} -le 100 ] || continue
        private4 "$dest" || continue
        case "$port:$listen" in *[!0-9:]*) continue;; esac
        [ "$port" -ge 1 ] && [ "$port" -le 65535 ] && [ "$listen" -ge 1 ] && [ "$listen" -le 65535 ] || continue
        route=$("$IP" -4 route get "$dest" 2>/dev/null) || continue
        dev=$(printf '%s\n' "$route" | awk '{for(i=1;i<NF;i++)if($i=="dev"){print $(i+1);exit}}')
        src=$(printf '%s\n' "$route" | awk '{for(i=1;i<NF;i++)if($i=="src"){print $(i+1);exit}}')
        [ "$dev" = "$LAN" ] && private4 "$src" || continue
        printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$dest" "$port" "$listen" "$src" >>"$STATE/next"
    done <"$STATE/candidates"
}
jump_present() { "$IPTABLES" -t nat -C POSTROUTING -m comment --comment "$TAG" -j "$1" 2>/dev/null; }
reconcile() {
    mkdir "$STATE/lock" 2>/dev/null || return 0
    plan || { rmdir "$STATE/lock"; return 1; }
    old=$(cat "$STATE/active" 2>/dev/null || true)
    if [ "$old" = "$A" ] || [ "$old" = "$B" ]; then
        if cmp -s "$STATE/current" "$STATE/next" && jump_present "$old"; then rmdir "$STATE/lock"; return 0; fi
    fi
    next=$A;[ "$old" != "$A" ] || next=$B
    "$IPTABLES" -t nat -N "$next" 2>/dev/null || true
    "$IPTABLES" -t nat -F "$next" || { rmdir "$STATE/lock"; return 1; }
    while IFS="$(printf '\t')" read -r id dest port listen src; do
        [ -n "$id" ] || continue
        "$IPTABLES" -t nat -A "$next" -p tcp -d "$dest" --dport "$port" -m conntrack --ctstate DNAT --ctorigdstport "$listen" -m comment --comment "$TAG:$id" -j SNAT --to-source "$src" || { rmdir "$STATE/lock"; return 1; }
    done <"$STATE/next"
    jump_present "$next" || "$IPTABLES" -t nat -I POSTROUTING 1 -m comment --comment "$TAG" -j "$next" || { rmdir "$STATE/lock"; return 1; }
    for chain in "$A" "$B"; do
        [ "$chain" != "$next" ] || continue
        while jump_present "$chain"; do "$IPTABLES" -t nat -D POSTROUTING -m comment --comment "$TAG" -j "$chain" || break; done
        "$IPTABLES" -t nat -F "$chain" 2>/dev/null || true
    done
    printf '%s\n' "$next" >"$STATE/active"
    cp "$STATE/next" "$STATE/current"
    rmdir "$STATE/lock"
}
case "${1:-}" in
    --plan) plan && cat "$STATE/next";;
    --once) reconcile;;
    '') while :; do reconcile || logger -t "$TAG" 'SSH source conversion could not be reconciled'; sleep 3; done;;
    *) exit 2;;
esac
