#!/system/bin/sh
# AEGIS // FIREWALL - boot service
MODDIR=${0%/*}
DATA=/data/adb/aegis
rm -rf "$DATA/cache/.lock" "$DATA/cache/caps" "$DATA/cache/screen" 2>/dev/null
# Wait until netd has built its own OUTPUT chains, then hook in right away.
n=0
while [ $n -lt 120 ]; do
  iptables -w -S OUTPUT 2>/dev/null | grep -qE -- '-j (oem_out|fw_OUTPUT|bw_OUTPUT|st_OUTPUT)' && break
  iptables -S OUTPUT 2>/dev/null | grep -qE -- '-j (oem_out|fw_OUTPUT|bw_OUTPUT|st_OUTPUT)' && break
  sleep 1; n=$((n + 1))
done
sh "$MODDIR/aegis.sh" apply boot >/dev/null 2>&1
nohup sh "$MODDIR/aegis.sh" daemon >/dev/null 2>&1 &
