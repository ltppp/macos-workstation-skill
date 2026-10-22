#!/bin/bash
# Deliberately fixed operations: safe to grant to the guest administrator via sudo.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
[[ $(id -u) = 0 && $(uname -s) = Darwin ]] || exit 1
label=local.us-workstation.network
plist=/Library/LaunchDaemons/$label.plist
case "${1:-status}" in
  firewall)
    loaded=false
    for attempt in {1..50}; do
      if pfctl -f /etc/pf.conf; then loaded=true; break; fi
      sleep 0.2
    done
    "$loaded" || exit 1
    pfctl -e 2>/dev/null || pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'
    # Ethernet has IPv4 and IPv6 disabled persistently. Give it only an
    # ephemeral management address after PF has been enabled successfully.
    if ! ifconfig en0 | grep -q 'inet 192.168.5.15 '; then
      ifconfig en0 inet 192.168.5.15 netmask 255.255.255.0 up
    fi
    ;;
  initialize) launchctl kickstart -k system/io.lima-vm.lima-macos-init ;;
  publish-tun)
    ifconfig utun8 >/dev/null
    route -n add default -interface utun8 2>/dev/null || true
    scutil <<'EOF'
d.init
d.add Addresses * 172.19.0.1
d.add SubnetMasks * 255.255.255.252
d.add Router 172.19.0.1
d.add InterfaceName utun8
d.add OverridePrimary # 1
set State:/Network/Service/us-workstation/IPv4
d.init
d.add PrimaryInterface utun8
d.add PrimaryService us-workstation
d.add Router 172.19.0.1
set State:/Network/Global/IPv4
d.init
d.add ServerAddresses * 172.19.0.2
d.add SupplementalMatchDomains * ""
d.add SupplementalMatchDomainsNoSearch # 1
set State:/Network/Service/us-workstation/DNS
set State:/Network/Global/DNS
quit
EOF
    killall -HUP mDNSResponder
    ;;
  audit)
    pfctl -s info 2>/dev/null
    pfctl -sr 2>/dev/null
    pfctl -a us-workstation -sr 2>/dev/null
    /usr/libexec/PlistBuddy -c 'Print :NetworkServices' /Library/Preferences/SystemConfiguration/preferences.plist
    shasum -a 256 /usr/local/libexec/us-workstation/control /usr/local/libexec/us-workstation/run /etc/us-workstation/config.json
    ;;
  status)
    pfctl -s info 2>/dev/null | head -n 2
    pfctl -a us-workstation -sr 2>/dev/null
    launchctl print system/$label | grep -E 'state =|pid =|last exit code'
    networksetup -getinfo Ethernet
    scutil --dns | head -n 25
    ;;
  stop) launchctl bootout system/$label; echo 'proxy=stopped; firewall=retained' ;;
  start) launchctl print system/$label >/dev/null 2>&1 || launchctl bootstrap system "$plist" ;;
  block-host)
    { echo 'block drop out quick on en0 proto tcp to 192.168.5.2 port @@SOCKS_PORT@@'; cat /etc/pf.anchors/us-workstation; } | pfctl -a us-workstation -f -
    pfctl -k 192.168.5.15 -k 192.168.5.2 >/dev/null
    ;;
  unblock-host) pfctl -a us-workstation -f /etc/pf.anchors/us-workstation ;;
  capture)
    # IPv4 packet headers only. Exclude ARP used to resolve the permitted host
    # gateway; tcpdump's bare "src host" also matches ARP sender addresses.
    mkdir -p /var/log/us-workstation
    chmod 700 /var/log/us-workstation
    tcpdump -n -l -i en0 'ip and src host 192.168.5.15 and not (dst host 192.168.5.2 and (tcp port 22 or tcp port @@SOCKS_PORT@@))' > /var/log/us-workstation/egress.txt 2>/var/log/us-workstation/capture.err &
    pid=$!
    sleep 25
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" || true
    # tcpdump emits a blank line on SIGINT; count actual packet lines only.
    echo "unexpected_egress_packets=$(grep -c '[^[:space:]]' /var/log/us-workstation/egress.txt || true)"
    cat /var/log/us-workstation/egress.txt
    ;;
  *) echo 'Expected status|start|stop|block-host|unblock-host|capture|publish-tun|firewall|initialize' >&2; exit 2 ;;
esac
