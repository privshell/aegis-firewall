#!/system/bin/sh
# AEGIS // FIREWALL - core engine and CLI
# Usage: aegis.sh <command> [args]   (run as root)

if [ -z "$AEGIS_SH" ]; then
  for b in /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox; do
    [ -x "$b" ] && AEGIS_SH=1 ASH_STANDALONE=1 exec "$b" sh "$0" "$@"
  done
fi
export PATH="/system/bin:/system/xbin:/vendor/bin:/data/adb/ksu/bin:$PATH"

MODDIR="${AEGIS_MODDIR:-/data/adb/modules/aegis_firewall}"
DATA="${AEGIS_DATA:-/data/adb/aegis}"
CACHE="$DATA/cache"
PKGLIST="${AEGIS_PKGLIST:-/data/system/packages.list}"
SETTINGS="$DATA/settings.conf"
TEMPF="$DATA/temp.conf"
CHAINS="aegis aegis-wifi aegis-mobile aegis-vpn aegis-lan aegis-scr aegis-reject"

IF_WIFI="wlan+ v4-wlan+ eth+ v4-eth+ ra+ mlan+ wigig+"
IF_MOBILE="rmnet+ v4-rmnet+ ccmni+ v4-ccmni+ pdp+ uwbr+ wimax+ vsnet+ rev_rmnet+ seth+ wwan+ cdma_rmnet+ qmimux+"
IF_VPN="tun+ tap+ ppp+ wg+ ipsec+ l2tp+"

mkdir -p "$CACHE/resolved" "$DATA/profiles/default" 2>/dev/null

# ---------- helpers ----------
log() {
  echo "$(date '+%m-%d %H:%M:%S') $*" >> "$CACHE/daemon.log"
  if [ "$(wc -l < "$CACHE/daemon.log")" -gt 600 ]; then tail -n 300 "$CACHE/daemon.log" > "$CACHE/daemon.log.tmp" && mv "$CACHE/daemon.log.tmp" "$CACHE/daemon.log"; fi
}
uptime_ms() { awk '{printf "%d", $1 * 1000}' /proc/uptime; }
valid_name() { echo "$1" | grep -Eq '^[A-Za-z0-9_-]{1,24}$'; }
valid_pkg() { echo "$1" | grep -Eq '^([A-Za-z0-9_.]+|uid:[0-9]+|\*)$'; }
valid_host() { echo "$1" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$'; }
is_addr() {
  case "$1" in
    '*') return 0 ;;
    *:*) echo "$1" | grep -Eq '^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$' ;;
    *) echo "$1" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' ;;
  esac
}
tmo() { if command -v timeout >/dev/null 2>&1; then timeout "$@"; else shift; "$@"; fi; }

lock_acquire() {
  n=0
  while ! mkdir "$CACHE/.lock" 2>/dev/null; do
    n=$((n + 1)); [ $n -gt 100 ] && rm -rf "$CACHE/.lock"
    sleep 0.1
  done
}
lock_release() { rmdir "$CACHE/.lock" 2>/dev/null; }

load_settings() {
  ENABLED=1; MODE=blacklist; LOCKDOWN=0; REJECT=1; LOGGING=1; STATS=1
  LAN=1; ROAMING=0; SCREEN=1; SCREEN_DELAY=10; ALL_USERS=1; NEWAPP_BLOCK=0; NOTIFY=1
  [ -f "$SETTINGS" ] && . "$SETTINGS"
  PROFILE=$(cat "$DATA/active_profile" 2>/dev/null)
  { [ -n "$PROFILE" ] && [ -d "$DATA/profiles/$PROFILE" ]; } || PROFILE=default
  PDIR="$DATA/profiles/$PROFILE"; CUSTOM="$PDIR/custom.conf"
  # each mode keeps its own selection: rules.conf = blocked (blacklist), allow.conf = allowed (whitelist)
  RULES="$PDIR/rules.conf"; [ "$MODE" = whitelist ] && RULES="$PDIR/allow.conf"
  mkdir -p "$PDIR"; touch "$PDIR/rules.conf" "$PDIR/allow.conf" "$CUSTOM" "$TEMPF" 2>/dev/null
}

probe() { T=$1; shift; $T $IPTW -F aegis-probe >/dev/null 2>&1; $T $IPTW -A aegis-probe "$@" >/dev/null 2>&1 && echo 1 || echo 0; }

doctor() {
  IPTW=""; iptables -w -n -L OUTPUT >/dev/null 2>&1 && IPTW="-w"
  RW=""; printf '*filter\nCOMMIT\n' | iptables-restore -w --noflush >/dev/null 2>&1 && RW="-w"
  iptables $IPTW -N aegis-probe >/dev/null 2>&1
  C_OWNER=$(probe iptables -m owner --uid-owner 10000 -j RETURN)
  C_REJECT=$(probe iptables -p tcp -j REJECT --reject-with tcp-reset)
  C_LIMIT=$(probe iptables -m limit --limit 5/sec --limit-burst 10 -j RETURN)
  C_LOG=$(probe iptables -j LOG --log-prefix "AEGIS " --log-uid)
  iptables $IPTW -F aegis-probe >/dev/null 2>&1; iptables $IPTW -X aegis-probe >/dev/null 2>&1
  C_V6=0; C_REJECT6=0; C_LOG6=0
  ip6tables $IPTW -N aegis-probe >/dev/null 2>&1
  C_V6=$(probe ip6tables -m owner --uid-owner 10000 -j RETURN)
  if [ "$C_V6" = 1 ]; then
    C_REJECT6=$(probe ip6tables -p tcp -j REJECT --reject-with tcp-reset)
    C_LOG6=$(probe ip6tables -j LOG --log-prefix "AEGIS " --log-uid)
  fi
  ip6tables $IPTW -F aegis-probe >/dev/null 2>&1; ip6tables $IPTW -X aegis-probe >/dev/null 2>&1
  cat > "$CACHE/caps" <<CAPS
IPTW="$IPTW"
RW="$RW"
C_OWNER=$C_OWNER
C_REJECT=$C_REJECT
C_LIMIT=$C_LIMIT
C_LOG=$C_LOG
C_V6=$C_V6
C_REJECT6=$C_REJECT6
C_LOG6=$C_LOG6
CAPS
  printf '{"owner":%s,"reject":%s,"limit":%s,"log":%s,"ipv6":%s,"reject6":%s,"log6":%s,"wait":%s,"kernel":"%s","sdk":"%s","device":"%s","busybox":%s}\n' \
    "$C_OWNER" "$C_REJECT" "$C_LIMIT" "$C_LOG" "$C_V6" "$C_REJECT6" "$C_LOG6" "$([ -n "$IPTW" ] && echo 1 || echo 0)" \
    "$(uname -r)" "$(getprop ro.build.version.sdk)" "$(getprop ro.product.device)" "$([ -n "$AEGIS_SH" ] && echo 1 || echo 0)"
}
load_caps() { [ -f "$CACHE/caps" ] || doctor >/dev/null; . "$CACHE/caps"; }

users() {
  u=""
  if [ "$ALL_USERS" = 1 ]; then u=$(ls /data/user 2>/dev/null | grep -E '^[0-9]+$' | tr '\n' ' '); fi
  [ -n "$AEGIS_USERS" ] && u="$AEGIS_USERS"
  [ -n "$u" ] && echo "$u" || echo 0
}
is_roaming() {
  [ "$ROAMING" = 1 ] || { echo 0; return; }
  case "$(getprop gsm.operator.isroaming)" in *true*) echo 1 ;; *) echo 0 ;; esac
}
screen_state() {
  case "$(dumpsys power 2>/dev/null | grep -m1 -o 'mWakefulness=[A-Za-z]*')" in
    *Awake*) echo on ;; '') echo on ;; *) echo off ;;
  esac
}
has_screen_rules() { awk '$1 !~ /^#/ && $2 ~ /s/ {f=1} END {exit !f}' "$RULES"; }

# ---------- host resolution (uses the system resolver through iptables) ----------
resolve_host() {
  h=$1; f="$CACHE/resolved/$h"; : > "$f.tmp"
  for T in iptables ip6tables; do
    $T $IPTW -N aegis-dns >/dev/null 2>&1; $T $IPTW -F aegis-dns >/dev/null 2>&1
    tmo 6 $T $IPTW -A aegis-dns -d "$h" -j RETURN >/dev/null 2>&1
    $T $IPTW -S aegis-dns 2>/dev/null | awk '$1=="-A"{for(i=1;i<=NF;i++) if($i=="-d"){x=$(i+1); sub(/\/(32|128)$/,"",x); print x}}' >> "$f.tmp"
    $T $IPTW -F aegis-dns >/dev/null 2>&1; $T $IPTW -X aegis-dns >/dev/null 2>&1
  done
  if [ -s "$f.tmp" ]; then sort -u "$f.tmp" > "$f"; rm -f "$f.tmp"; return 0; fi
  rm -f "$f.tmp"; return 1
}
custom_hosts() {
  awk '$1 !~ /^#/ && NF >= 3 {print $3}' "$CUSTOM" | sort -u | while read -r h; do
    is_addr "$h" && continue; valid_host "$h" && echo "$h"
  done
}
pending_hosts() { custom_hosts | while read -r h; do [ -s "$CACHE/resolved/$h" ] || echo "$h"; done; }

prepare_custom() {
  out="$CACHE/custom.resolved"; : > "$out.tmp"
  while read -r pkg act dest port proto rest; do
    case "$pkg" in '' | \#*) continue ;; esac
    case "$act" in allow | block) ;; *) continue ;; esac
    [ -z "$port" ] && port='*'; [ -z "$proto" ] && proto='*'
    if is_addr "$dest"; then echo "$pkg $act $dest $port $proto" >> "$out.tmp"; continue; fi
    valid_host "$dest" || continue
    f="$CACHE/resolved/$dest"
    if [ ! -s "$f" ] && [ "$1" != noresolve ]; then resolve_host "$dest"; fi
    if [ -s "$f" ]; then
      while read -r ip; do [ -n "$ip" ] && echo "$pkg $act $ip $port $proto"; done < "$f" >> "$out.tmp"
    fi
  done < "$CUSTOM"
  mv "$out.tmp" "$out"
}

# ---------- compile and apply ----------
build() { # $1 = 4|6
  fam=$1; lg=$LOGT4; rj=$REJ4
  [ "$fam" = 6 ] && { lg=$LOGT6; rj=$REJ6; }
  awk -v fam="$fam" -v mode="$MODE" -v roam="$ROAM" -v lan="$LAN" -v lock="$LOCKDOWN" -v scr="$SCR" \
      -v stats="$STATS" -v rej="$rj" -v logt="$lg" -v users="$(users)" -v now="$(date +%s)" \
      -v ifw="$IF_WIFI" -v ifm="$IF_MOBILE" -v ifv="$IF_VPN" \
      -v pkgf="$PKGLIST" -v rulef="$RULES" -v tmpf="$TEMPF" -v custf="$CACHE/custom.resolved" \
      -f "$MODDIR/lib/build.awk"
}
restore() { # $1 fam, $2 file
  R=iptables-restore; [ "$1" = 6 ] && R=ip6tables-restore
  $R $RW --noflush < "$2" 2> "$CACHE/restore$1.err"
}
hook_one() {
  T=$1
  [ "$($T $IPTW -S OUTPUT 2>/dev/null | sed -n '2p')" = "-A OUTPUT -j aegis" ] && return 0
  while $T $IPTW -D OUTPUT -j aegis >/dev/null 2>&1; do :; done
  $T $IPTW -I OUTPUT 1 -j aegis >/dev/null 2>&1
  return 1
}
hook() { r=0; hook_one iptables || r=1; [ "$C_V6" = 1 ] && { hook_one ip6tables || r=1; }; return $r; }
unhook() { for T in iptables ip6tables; do while $T $IPTW -D OUTPUT -j aegis >/dev/null 2>&1; do :; done; done; }
teardown() {
  unhook
  for T in iptables ip6tables; do
    for c in $CHAINS; do $T $IPTW -F "$c" >/dev/null 2>&1; done
    for c in $CHAINS; do $T $IPTW -X "$c" >/dev/null 2>&1; done
  done
}
set_description() {
  [ -w "$MODDIR/module.prop" ] || return 0
  awk -v d="$1" '/^description=/ {print "description=" d; next} {print}' "$MODDIR/module.prop" > "$MODDIR/module.prop.tmp" 2>/dev/null \
    && mv "$MODDIR/module.prop.tmp" "$MODDIR/module.prop"
}

apply() {
  how=$1
  lock_acquire
  load_settings; load_caps
  if [ "$C_OWNER" != 1 ]; then
    lock_release
    set_description "Unsupported kernel: iptables owner match is missing."
    echo '{"ok":false,"error":"Kernel lacks the iptables owner match (xt_owner)."}'; return 1
  fi
  if [ "$ENABLED" != 1 ]; then
    unhook; lock_release
    set_description "Disabled. Open the WebUI to turn the firewall on."
    echo '{"ok":true,"enabled":false}'; return 0
  fi
  t0=$(uptime_ms)
  if [ "$how" = boot ]; then prepare_custom noresolve; else prepare_custom; fi
  SCR=0; [ "$SCREEN" = 1 ] && [ "$(cat "$CACHE/screen" 2>/dev/null)" = off ] && SCR=1
  ROAM=$(is_roaming)
  LOGT4=0; [ "$LOGGING" = 1 ] && [ "$C_LOG" = 1 ] && [ "$C_LIMIT" = 1 ] && LOGT4=1
  LOGT6=0; [ "$LOGGING" = 1 ] && [ "$C_LOG6" = 1 ] && [ "$C_LIMIT" = 1 ] && LOGT6=1
  REJ4=0; [ "$REJECT" = 1 ] && [ "$C_REJECT" = 1 ] && REJ4=1
  REJ6=0; [ "$REJECT" = 1 ] && [ "$C_REJECT6" = 1 ] && REJ6=1
  err=""
  build 4 > "$CACHE/rules4" && restore 4 "$CACHE/rules4" || err="ipv4"
  if [ "$C_V6" = 1 ]; then build 6 > "$CACHE/rules6" && restore 6 "$CACHE/rules6" || err="$err ipv6"; fi
  hook
  echo "$ROAM" > "$CACHE/roam_state"
  n4=$(grep -c '^-A' "$CACHE/rules4")
  ms=$(( $(uptime_ms) - t0 ))
  date +%s > "$CACHE/last_apply"
  lock_release
  st="Active"; [ "$LOCKDOWN" = 1 ] && st="LOCKDOWN"
  if [ -n "$err" ]; then
    set_description "Error applying rules ($err). Open the WebUI for diagnostics."
    log "apply failed: $err"
    printf '{"ok":false,"error":"iptables-restore failed for %s","detail":"%s"}\n' "$err" "$(head -c 300 "$CACHE/restore4.err" "$CACHE/restore6.err" 2>/dev/null | tr '"\n\\' "' /")"
    return 1
  fi
  set_description "$st | $MODE mode | profile: $PROFILE | $n4 rules | applied in ${ms}ms"
  [ "$how" = quiet ] || [ "$how" = boot ] && log "applied ($how) $n4 rules in ${ms}ms"
  printf '{"ok":true,"rules":%s,"ms":%s,"roaming":%s,"screenOff":%s}\n' "$n4" "$ms" "$ROAM" "$SCR"
}

# ---------- data / config commands ----------
apps_json() {
  sysf="$CACHE/system.txt"
  if [ ! -s "$sysf" ] || [ "$PKGLIST" -nt "$sysf" ]; then
    pm list packages -s 2>/dev/null | sed 's/^package://' > "$sysf.tmp" && mv "$sysf.tmp" "$sysf"
  fi
  awk -v sysf="$sysf" 'BEGIN { while ((getline l < sysf) > 0) S[l] = 1; printf "[" }
    $2 ~ /^[0-9]+$/ { inet = 0; for (i = 6; i <= NF; i++) if ($i ~ /(^|,)3003(,|$)/) inet = 1
      printf "%s{\"p\":\"%s\",\"u\":%d,\"s\":%d,\"i\":%d}", (n++ ? "," : ""), $1, $2, ($1 in S) ? 1 : 0, inet }
    END { print "]" }' "$PKGLIST"
}
settings_json() {
  load_settings
  printf '{"ENABLED":"%s","MODE":"%s","LOCKDOWN":"%s","REJECT":"%s","LOGGING":"%s","STATS":"%s","LAN":"%s","ROAMING":"%s","SCREEN":"%s","SCREEN_DELAY":"%s","ALL_USERS":"%s","NEWAPP_BLOCK":"%s","NOTIFY":"%s"}\n' \
    "$ENABLED" "$MODE" "$LOCKDOWN" "$REJECT" "$LOGGING" "$STATS" "$LAN" "$ROAMING" "$SCREEN" "$SCREEN_DELAY" "$ALL_USERS" "$NEWAPP_BLOCK" "$NOTIFY"
}
status_json() {
  load_settings; load_caps
  h4=0; iptables $IPTW -C OUTPUT -j aegis >/dev/null 2>&1 && h4=1
  h6=0; [ "$C_V6" = 1 ] && ip6tables $IPTW -C OUTPUT -j aegis >/dev/null 2>&1 && h6=1
  d=0; pid=$(cat "$CACHE/daemon.pid" 2>/dev/null); [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && d=1
  n4=$(grep -c '^-A' "$CACHE/rules4" 2>/dev/null); [ -z "$n4" ] && n4=0
  printf '{"version":"%s","enabled":%s,"mode":"%s","profile":"%s","lockdown":%s,"hook4":%s,"hook6":%s,"daemon":%s,"screen":"%s","roaming":%s,"users":"%s","rules":%s,"lastApply":%s,"caps":{"owner":%s,"reject":%s,"log":%s,"ipv6":%s}}\n' \
    "$(sed -n 's/^version=//p' "$MODDIR/module.prop")" "$ENABLED" "$MODE" "$PROFILE" "$LOCKDOWN" "$h4" "$h6" "$d" \
    "$(cat "$CACHE/screen" 2>/dev/null || echo on)" "$(cat "$CACHE/roam_state" 2>/dev/null || echo 0)" "$(users)" "$n4" \
    "$(cat "$CACHE/last_apply" 2>/dev/null || echo 0)" "$C_OWNER" "$C_REJECT" "$C_LOG" "$C_V6"
}
set_kv() {
  k=$1; v=$2
  case "$k" in ENABLED | MODE | LOCKDOWN | REJECT | LOGGING | STATS | LAN | ROAMING | SCREEN | SCREEN_DELAY | ALL_USERS | NEWAPP_BLOCK | NOTIFY) ;;
    *) echo '{"ok":false,"error":"unknown key"}'; return 1 ;; esac
  echo "$v" | grep -Eq '^[A-Za-z0-9_]{1,16}$' || { echo '{"ok":false,"error":"bad value"}'; return 1; }
  touch "$SETTINGS"
  if grep -q "^$k=" "$SETTINGS"; then sed -i "s/^$k=.*/$k=$v/" "$SETTINGS"; else echo "$k=$v" >> "$SETTINGS"; fi
  echo '{"ok":true}'
}
put_file() { # rules|custom <base64>
  load_settings
  case "$1" in rules) f=$RULES ;; custom) f=$CUSTOM ;; *) echo '{"ok":false}'; return 1 ;; esac
  if echo "$2" | base64 -d > "$f.tmp" 2>/dev/null; then mv "$f.tmp" "$f"; echo '{"ok":true}'; else rm -f "$f.tmp"; echo '{"ok":false,"error":"decode failed"}'; return 1; fi
}
temp_allow() { # pkg minutes
  valid_pkg "$1" || return 1
  awk -v p="$1" '$1 != p' "$TEMPF" > "$TEMPF.tmp"
  [ "${2:-0}" -gt 0 ] && echo "$1 $(( $(date +%s) + $2 * 60 ))" >> "$TEMPF.tmp"
  mv "$TEMPF.tmp" "$TEMPF"
  apply
}
expire_temps() {
  now=$(date +%s)
  awk -v now="$now" 'NF >= 2 && $2 <= now {e = 1} END {exit !e}' "$TEMPF" || return 1
  awk -v now="$now" 'NF >= 2 && $2 > now' "$TEMPF" > "$TEMPF.tmp" && mv "$TEMPF.tmp" "$TEMPF"
  return 0
}
lockdown() {
  load_settings
  case "$1" in on) v=1 ;; off) v=0 ;; *) if [ "$LOCKDOWN" = 1 ]; then v=0; else v=1; fi ;; esac
  set_kv LOCKDOWN "$v" >/dev/null; apply quiet >/dev/null; echo "$v"
}
profiles_json() {
  load_settings
  printf '{"active":"%s","list":[' "$PROFILE"; s=""
  for d in "$DATA"/profiles/*/; do
    [ -d "$d" ] || continue; n=$(basename "$d")
    rf="$d/rules.conf"; [ "$MODE" = whitelist ] && rf="$d/allow.conf"
    c=$(grep -c '^[^#]' "$rf" 2>/dev/null); [ -z "$c" ] && c=0
    printf '%s{"name":"%s","rules":%s}' "$s" "$n" "$c"; s=","
  done
  printf ']}\n'
}
profile_cmd() {
  load_settings
  case "$1" in
    switch) valid_name "$2" && [ -d "$DATA/profiles/$2" ] || { echo '{"ok":false,"error":"no such profile"}'; return 1; }
      echo "$2" > "$DATA/active_profile"; apply ;;
    new) valid_name "$2" && [ ! -d "$DATA/profiles/$2" ] || { echo '{"ok":false,"error":"invalid or existing name"}'; return 1; }
      mkdir -p "$DATA/profiles/$2"
      if [ -n "$3" ] && valid_name "$3" && [ -d "$DATA/profiles/$3" ]; then cp "$DATA/profiles/$3/"*.conf "$DATA/profiles/$2/" 2>/dev/null; fi
      touch "$DATA/profiles/$2/rules.conf" "$DATA/profiles/$2/allow.conf" "$DATA/profiles/$2/custom.conf"; echo '{"ok":true}' ;;
    delete) valid_name "$2" && [ "$2" != "$PROFILE" ] && [ "$2" != default ] || { echo '{"ok":false,"error":"cannot delete this profile"}'; return 1; }
      rm -rf "$DATA/profiles/$2"; echo '{"ok":true}' ;;
    *) echo '{"ok":false}'; return 1 ;;
  esac
}
backup_export() {
  dir=/sdcard/Download; mkdir -p "$dir"
  f="$dir/aegis-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  tar -czf "$f" -C "$DATA" settings.conf profiles active_profile 2>/dev/null || tar -czf "$f" -C "$DATA" settings.conf profiles
  printf '{"ok":true,"file":"%s"}\n' "$f"
}
backup_list() { printf '['; s=""; for f in /sdcard/Download/aegis-backup-*.tar.gz; do [ -f "$f" ] && printf '%s"%s"' "$s" "$f" && s=","; done; printf ']\n'; }
backup_import() {
  echo "$1" | grep -Eq '^/sdcard/Download/aegis-backup-[0-9-]+\.tar\.gz$' && [ -f "$1" ] || { echo '{"ok":false,"error":"invalid file"}'; return 1; }
  tar -xzf "$1" -C "$DATA" && apply
}
stats_json() {
  load_caps
  for T in iptables ip6tables; do
    for n in wifi mobile vpn lan scr; do
      $T $IPTW -nvxL "aegis-$n" 2>/dev/null | awk -v n="$n" '$3 == "aegis-reject" && $1 > 0 { u = "*"; for (i = 1; i <= NF; i++) if ($i == "match") u = $(i + 1); print n, u, $1 }'
    done
    $T $IPTW -nvxL aegis 2>/dev/null | awk '$3 == "aegis-reject" && $1 > 0 { u = "*"; for (i = 1; i <= NF; i++) if ($i == "match") u = $(i + 1); print "rule", u, $1 }'
  done | awk 'BEGIN { printf "[" } { k = $1 " " $2; c[k] += $3 } END { for (k in c) { split(k, a, " "); printf "%s{\"net\":\"%s\",\"uid\":\"%s\",\"pkts\":%d}", (n++ ? "," : ""), a[1], a[2], c[k] } print "]" }'
}
klog() { dmesg 2>/dev/null | grep 'AEGIS ' | tail -n 400; echo "#UPTIME $(cut -d' ' -f1 /proc/uptime) $(date +%s)"; }
conns() { for f in tcp tcp6 udp udp6; do echo "#$f"; cat "/proc/net/$f" 2>/dev/null; done; }
notify() { [ "$NOTIFY" = 1 ] || return 0; cmd notification post -S bigtext -t "$1" "$3" "$2" >/dev/null 2>&1; }

# ---------- daemon ----------
packages_changed() {
  known="$CACHE/known.txt"; cur="$CACHE/current.txt"
  awk '{ for (i = 6; i <= NF; i++) if ($i ~ /(^|,)3003(,|$)/) { print $1; break } }' "$PKGLIST" | sort > "$cur"
  if [ -f "$known" ]; then
    comm -13 "$known" "$cur" | while read -r p; do new_app "$p"; done
  fi
  mv "$cur" "$known"
  rm -f "$CACHE/system.txt"
  apply quiet >/dev/null
}
new_app() {
  p=$1; load_settings
  if [ "$MODE" = blacklist ] && [ "$NEWAPP_BLOCK" = 1 ]; then
    awk -v p="$p" '$1 == p {f = 1} END {exit f}' "$RULES" && echo "$p wmvlr" >> "$RULES"
    notify "AEGIS // FIREWALL" "New app $p is blocked on all networks. Open AEGIS to allow it." "aegis_new"
    log "new app blocked: $p"
  elif [ "$MODE" = whitelist ]; then
    notify "AEGIS // FIREWALL" "New app $p has no network access until you allow it in AEGIS." "aegis_new"
    log "new app (whitelist, blocked by default): $p"
  fi
}
screen_check() {
  load_settings
  st=$(screen_state); prev=$(cat "$CACHE/screen" 2>/dev/null || echo on)
  [ "$st" = "$prev" ] && return 0
  if [ "$st" = off ] && [ "${SCREEN_DELAY:-0}" -gt 0 ]; then
    sleep "$SCREEN_DELAY"; st=$(screen_state); [ "$st" = "$prev" ] && return 0
  fi
  echo "$st" > "$CACHE/screen"
  [ "$SCREEN" = 1 ] && [ "$ENABLED" = 1 ] && has_screen_rules && apply quiet >/dev/null && log "screen $st"
  return 0
}
screen_watch() {
  while :; do
    logcat -b events -v raw -T 1 -s screen_toggled 2>/dev/null | while read -r _l; do screen_check; done
    sleep 5
  done
}
daemon() {
  pidf="$CACHE/daemon.pid"
  old=$(cat "$pidf" 2>/dev/null)
  if [ -n "$old" ] && [ "$old" != "$$" ] && kill -0 "$old" 2>/dev/null; then echo "daemon already running ($old)"; return 0; fi
  echo $$ > "$pidf"
  log "daemon started (pid $$)"
  screen_watch &
  i=0; pk=$(stat -c %Y "$PKGLIST" 2>/dev/null); last_dns=$(date +%s)
  [ -f "$CACHE/known.txt" ] || packages_changed
  while :; do
    if [ $i -lt 90 ]; then sleep 2; else sleep 15; fi
    i=$((i + 1))
    load_settings
    [ "$ENABLED" = 1 ] || continue
    load_caps
    if ! iptables $IPTW -S aegis >/dev/null 2>&1; then log "chains missing, re-applying"; apply quiet >/dev/null; continue; fi
    hook || log "OUTPUT hook was removed by the system, restored"
    npk=$(stat -c %Y "$PKGLIST" 2>/dev/null)
    if [ "$npk" != "$pk" ]; then pk=$npk; packages_changed; continue; fi
    if [ "$(is_roaming)" != "$(cat "$CACHE/roam_state" 2>/dev/null)" ]; then log "roaming state changed"; apply quiet >/dev/null; continue; fi
    if expire_temps; then log "temporary allow expired"; apply quiet >/dev/null; continue; fi
    if [ $((i % 4)) -eq 0 ]; then
      now=$(date +%s)
      if [ $((now - last_dns)) -gt 21600 ]; then
        last_dns=$now; for h in $(custom_hosts); do resolve_host "$h"; done; apply quiet >/dev/null
      elif [ -n "$(pending_hosts)" ]; then
        got=0; for h in $(pending_hosts); do resolve_host "$h" && got=1; done
        [ $got = 1 ] && { log "resolved pending hosts"; apply quiet >/dev/null; }
      fi
      [ "$SCREEN" = 1 ] && has_screen_rules && screen_check
    fi
  done
}

# ---------- entry ----------
cmd_=$1; [ $# -gt 0 ] && shift
case "$cmd_" in
  apply) apply "$1" ;;
  build) load_settings; load_caps; prepare_custom noresolve; SCR=0; ROAM=0; LOGT4=$C_LOG; LOGT6=$C_LOG6; REJ4=$C_REJECT; REJ6=$C_REJECT6; build "${1:-4}" ;;
  enable) set_kv ENABLED 1 >/dev/null; apply ;;
  disable) set_kv ENABLED 0 >/dev/null; apply ;;
  status) status_json ;;
  settings) settings_json ;;
  set) set_kv "$1" "$2" ;;
  apps) apps_json ;;
  rules) load_settings; cat "$RULES" ;;
  custom) load_settings; cat "$CUSTOM" ;;
  temps) cat "$TEMPF" 2>/dev/null ;;
  put) put_file "$1" "$2" ;;
  temp) temp_allow "$1" "$2" ;;
  lockdown) lockdown "$1" ;;
  profiles) profiles_json ;;
  profile) profile_cmd "$@" ;;
  export) backup_export ;;
  backups) backup_list ;;
  import) backup_import "$1" ;;
  stats) stats_json ;;
  log) klog ;;
  conns) conns ;;
  doctor) doctor ;;
  daemonlog) tail -n 120 "$CACHE/daemon.log" 2>/dev/null ;;
  errors) cat "$CACHE/restore4.err" "$CACHE/restore6.err" 2>/dev/null ;;
  daemon) daemon ;;
  resolve) load_settings; load_caps; for h in $(custom_hosts); do resolve_host "$h" && echo "$h: $(tr '\n' ' ' < "$CACHE/resolved/$h")"; done ;;
  teardown) load_caps; teardown ;;
  *) echo "AEGIS // FIREWALL"
     echo "commands: apply enable disable status settings set apps rules custom temps put temp lockdown"
     echo "          profiles profile export backups import stats log conns doctor daemonlog errors resolve teardown" ;;
esac
