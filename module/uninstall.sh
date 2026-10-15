#!/system/bin/sh
# AEGIS // FIREWALL - remove all rules. Config in /data/adb/aegis is kept for reinstalls.
pid=$(cat /data/adb/aegis/cache/daemon.pid 2>/dev/null)
[ -n "$pid" ] && kill "$pid" 2>/dev/null
pkill -f "aegis.sh daemon" 2>/dev/null
for T in iptables ip6tables; do
  W=""; $T -w -n -L OUTPUT >/dev/null 2>&1 && W="-w"
  while $T $W -D OUTPUT -j aegis >/dev/null 2>&1; do :; done
  for c in aegis aegis-wifi aegis-mobile aegis-vpn aegis-lan aegis-scr aegis-reject; do $T $W -F $c >/dev/null 2>&1; done
  for c in aegis aegis-wifi aegis-mobile aegis-vpn aegis-lan aegis-scr aegis-reject; do $T $W -X $c >/dev/null 2>&1; done
done
rm -rf /data/adb/aegis/cache
