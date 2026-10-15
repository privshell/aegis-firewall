#!/system/bin/sh
# AEGIS // FIREWALL - installer
SKIPUNZIP=0
ui_print " "
ui_print "  AEGIS // FIREWALL"
ui_print "  Kernel-level per-app firewall"
ui_print " "
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/aegis.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
DATA=/data/adb/aegis
mkdir -p "$DATA/profiles/default" "$DATA/cache"
[ -f "$DATA/settings.conf" ] || printf 'ENABLED=1\nMODE=blacklist\n' > "$DATA/settings.conf"
[ -f "$DATA/active_profile" ] || echo default > "$DATA/active_profile"
touch "$DATA/profiles/default/rules.conf" "$DATA/profiles/default/custom.conf"
rm -f "$DATA/cache/caps"
ui_print "- Probing kernel netfilter support..."
caps=$(AEGIS_MODDIR="$MODPATH" sh "$MODPATH/aegis.sh" doctor 2>/dev/null)
has() { echo "$caps" | grep -q "\"$1\":1"; }
if has owner; then ui_print "  [ok] owner match (per-app rules)"; else
  ui_print "  [!!] owner match missing"
  abort "  This kernel cannot do per-app iptables filtering."
fi
has ipv6 && ui_print "  [ok] IPv6 filtering" || ui_print "  [--] IPv6 filtering unavailable"
has reject && ui_print "  [ok] REJECT (apps fail fast)" || ui_print "  [--] REJECT missing, using DROP"
has log && ui_print "  [ok] kernel LOG (live block log)" || ui_print "  [--] kernel LOG missing, using per-app counters"
ui_print " "
ui_print "- Rules apply on boot. Open the WebUI to configure."
ui_print "- Default mode: blacklist (nothing blocked yet)."
ui_print " "
