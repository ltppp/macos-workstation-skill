#!/bin/bash
# Installed through the guest's own administrator authorization dialog.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
[[ $(id -u) = 0 && $(uname -s) = Darwin ]] || exit 1
stage="${1:?staging directory required}"
[[ "$stage" = /Users/@@GUEST_USER@@/.us-network-stage ]] || exit 1
base=/usr/local/libexec/us-workstation
backup=/var/root/us-workstation-network-before
mkdir -p "$backup" "$base" /etc/us-workstation /var/log/us-workstation
chmod 700 "$backup" /etc/us-workstation /var/log/us-workstation
if [[ ! -f "$backup/pf.conf" ]]; then
  cp -p /etc/pf.conf "$backup/pf.conf"
  cp -p /Library/Preferences/SystemConfiguration/preferences.plist "$backup/preferences.plist"
fi
install -o root -g wheel -m 755 "$stage/sing-box" "$base/sing-box"
install -o root -g wheel -m 755 "$stage/macos-network-run.sh" "$base/run"
install -o root -g wheel -m 755 "$stage/macos-network-control.sh" "$base/control"
if [[ -f "$stage/config.json" ]]; then
  install -o root -g wheel -m 600 "$stage/config.json" /etc/us-workstation/config.json
fi
[[ -f /etc/us-workstation/config.json ]]
"$base/sing-box" check -c /etc/us-workstation/config.json
cat > /etc/pf.anchors/us-workstation <<'EOF'
pass quick on lo0 all
pass quick on utun8 all
pass in quick on en0 inet proto tcp from 192.168.5.2 to (en0) port 22 flags any keep state
pass out quick on en0 inet proto tcp from (en0) to 192.168.5.2 port @@SOCKS_PORT@@ user root flags S/SA keep state
block drop quick all
EOF
# Keep Apple's anchors, inserting ours before its filter anchor.
awk '/^anchor "us-workstation"/ || /^load anchor "us-workstation"/ {next} /^anchor "com.apple\/\*"/ {print "anchor \"us-workstation\" quick"; print "load anchor \"us-workstation\" from \"/etc/pf.anchors/us-workstation\""} {print}' /etc/pf.conf > "$backup/pf.next"
grep -q '^anchor "us-workstation" quick' "$backup/pf.next"
pfctl -nf "$backup/pf.next"
install -o root -g wheel -m 644 "$backup/pf.next" /etc/pf.conf
pfctl -f /etc/pf.conf
pfctl -e 2>/dev/null || pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'
pfctl -F states
# No layer-3 address or DHCP is brought up automatically before PF at boot.
networksetup -setv4off Ethernet
networksetup -setv6off Ethernet
networksetup -setdnsservers Ethernet 172.19.0.2
networksetup -setwebproxystate Ethernet off
networksetup -setsecurewebproxystate Ethernet off
networksetup -setsocksfirewallproxystate Ethernet off
networksetup -setautoproxystate Ethernet off
networksetup -setproxyautodiscovery Ethernet off
"$base/control" firewall
# Protect Lima's boot-time DNS changes before its guest agent starts.
init=/usr/local/sbin/lima-macos-init.sh
if [[ -f "$init" ]]; then
  [[ -f "$backup/lima-macos-init.sh" ]] || cp -p "$init" "$backup/lima-macos-init.sh"
  { head -n 1 "$backup/lima-macos-init.sh"; cat <<'EARLY'
# us-workstation early PF
/usr/local/libexec/us-workstation/control firewall || exit 1
EARLY
    tail -n +2 "$backup/lima-macos-init.sh"; } > "$backup/init.next"
  install -o root -g wheel -m 755 "$backup/init.next" "$init"
fi
cat > /Library/LaunchDaemons/local.us-workstation.network.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>local.us-workstation.network</string>
<key>ProgramArguments</key><array><string>/usr/local/libexec/us-workstation/run</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>5</integer>
<key>StandardOutPath</key><string>/var/log/us-workstation/network.log</string>
<key>StandardErrorPath</key><string>/var/log/us-workstation/network.log</string>
</dict></plist>
EOF
chown root:wheel /Library/LaunchDaemons/local.us-workstation.network.plist
chmod 644 /Library/LaunchDaemons/local.us-workstation.network.plist
plutil -lint /Library/LaunchDaemons/local.us-workstation.network.plist
mkdir -p /etc/sudoers.d
echo '@@GUEST_USER@@ ALL=(root) NOPASSWD: /usr/local/libexec/us-workstation/control' > "$backup/sudoers.next"
visudo -cf "$backup/sudoers.next"
install -o root -g wheel -m 440 "$backup/sudoers.next" /etc/sudoers.d/us-workstation-control
launchctl bootout system/local.us-workstation.network 2>/dev/null || true
started=false
for attempt in {1..20}; do
  if launchctl bootstrap system /Library/LaunchDaemons/local.us-workstation.network.plist; then
    started=true
    break
  fi
  sleep 0.5
done
"$started" || { echo 'Network service registration failed; PF remains enabled.' >&2; exit 1; }
launchctl kickstart -k system/io.lima-vm.lima-macos-init
rm -f "$stage/config.json"
echo 'network=installed; acceptance=pending'
