#!/system/bin/sh
# AEGIS // FIREWALL - Action button: toggle Lockdown
MODDIR=${0%/*}
v=$(sh "$MODDIR/aegis.sh" lockdown toggle)
if [ "$v" = 1 ]; then
  echo "LOCKDOWN ON"
  echo "All app traffic is blocked. Press Action again to restore your rules."
else
  echo "LOCKDOWN OFF"
  echo "Normal firewall rules restored."
fi
