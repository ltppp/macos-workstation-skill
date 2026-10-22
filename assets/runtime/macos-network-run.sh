#!/bin/bash
# Runs only inside the macOS guest, as root. No direct outbound fallback.
set -euo pipefail
base=/usr/local/libexec/us-workstation
"$base/control" firewall
# A routerless Ethernet service is not selected as macOS's primary DNS service.
# Publish a catch-all supplemental resolver, independent of Ethernet's router.
/usr/sbin/scutil <<'EOF'
d.init
d.add ServerAddresses * 172.19.0.2
d.add SupplementalMatchDomains * ""
d.add SupplementalMatchDomainsNoSearch # 1
set State:/Network/Service/us-workstation/DNS
quit
EOF
# Persistent Ethernet configuration has no router. Publish the ephemeral TUN as
# the primary service so native macOS consumers see a reachable DNS resolver.
"$base/sing-box" run -c /etc/us-workstation/config.json &
child=$!
cleanup() {
  kill -TERM "$child" 2>/dev/null || true
  wait "$child" || true
  /usr/sbin/scutil <<'EOF'
remove State:/Network/Service/us-workstation/IPv4
remove State:/Network/Service/us-workstation/DNS
remove State:/Network/Global/IPv4
remove State:/Network/Global/DNS
quit
EOF
}
trap cleanup EXIT
trap 'exit 0' TERM INT
for attempt in {1..50}; do
  kill -0 "$child" 2>/dev/null || exit 1
  if /sbin/ifconfig utun8 >/dev/null 2>&1; then
    "$base/control" publish-tun
    break
  fi
  sleep 0.2
done
# configd may rebuild its dynamic store when Lima initializes Ethernet or wakes.
# Re-publish only when our virtual primary service disappears; never restore an
# Ethernet default route. During recovery PF remains closed to direct traffic.
while kill -0 "$child" 2>/dev/null; do
  if ! printf 'show State:/Network/Global/IPv4\nquit\n' | /usr/sbin/scutil | /usr/bin/grep -q 'PrimaryInterface : utun8'; then
    /sbin/ifconfig utun8 >/dev/null 2>&1 && "$base/control" publish-tun
  fi
  sleep 2
done
wait "$child"
