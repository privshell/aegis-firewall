# AEGIS // FIREWALL rule compiler
# Emits a complete iptables-restore payload for one address family.
# Inputs (-v): fam mode roam lan lock scr stats rej logt users now ifw ifm ifv pkgf rulef tmpf custf

function slurp(f, arr,   n, l) { n = 0; if (f == "") return 0; while ((getline l < f) > 0) arr[++n] = l; close(f); return n }
function uidof(p) { if (p ~ /^uid:[0-9]+$/) return substr(p, 5) + 0; if (p in APP) return APP[p] + 0; return -1 }
function emit(chain, a, rest,   i) { for (i = 1; i <= NU; i++) printf "-A %s -m owner --uid-owner %d %s\n", chain, U[i] * 100000 + a, rest }
function famok(addr) { if (addr == "*") return 1; if (fam == 6) return index(addr, ":") > 0; return index(addr, ":") == 0 }

BEGIN {
  NU = split(users, U, " "); if (NU == 0) { NU = 1; U[1] = 0 }

  n = slurp(pkgf, PL)
  for (i = 1; i <= n; i++) {
    k = split(PL[i], f, " ")
    if (k < 2 || f[2] !~ /^[0-9]+$/) continue
    APP[f[1]] = f[2] + 0
    inet = 0
    for (j = 6; j <= k; j++) if (f[j] ~ /(^|,)3003(,|$)/) inet = 1
    if (inet && !((f[2] + 0) in SEEN)) { SEEN[f[2] + 0] = 1; INET[++NI] = f[2] + 0 }
  }

  n = slurp(rulef, RL)
  for (i = 1; i <= n; i++) {
    k = split(RL[i], f, " ")
    if (k < 2 || f[1] ~ /^#/) continue
    a = uidof(f[1]); if (a < 0) continue
    if (!(a in FL)) { ORD[++NO] = a; FL[a] = "" }
    FL[a] = FL[a] f[2]
  }

  ntmp = slurp(tmpf, TL)
  ncus = slurp(custf, CL)

  LET["wifi"] = "w"; LET["mobile"] = (roam ? "r" : "m"); LET["vpn"] = "v"; LET["lan"] = "l"

  print "*filter"
  nch = split("aegis aegis-wifi aegis-mobile aegis-vpn aegis-lan aegis-scr aegis-reject", CH, " ")
  for (i = 1; i <= nch; i++) print ":" CH[i] " - [0:0]"
  for (i = 1; i <= nch; i++) print "-F " CH[i]

  print "-A aegis -o lo -j RETURN"
  if (lock) print "-A aegis -j aegis-reject"
  print "-A aegis -j aegis-scr"

  # temporary allows
  for (i = 1; i <= ntmp; i++) {
    k = split(TL[i], f, " "); if (k < 2 || f[2] + 0 <= now) continue
    a = uidof(f[1]); if (a >= 0) emit("aegis", a, "-j RETURN")
  }

  # custom host / address rules (evaluated before network policy)
  for (i = 1; i <= ncus; i++) {
    k = split(CL[i], f, " "); if (k < 5) continue
    if (f[2] != "allow" && f[2] != "block") continue
    if (!famok(f[3])) continue
    port = f[4]; gsub("-", ":", port); proto = f[5]
    if (port !~ /^(\*|[0-9]+(:[0-9]+)?)$/) continue
    if (proto !~ /^(\*|tcp|udp)$/) continue
    a = -2; if (f[1] != "*") { a = uidof(f[1]); if (a < 0) continue }
    tgt = (f[2] == "allow") ? "-j RETURN" : "-j aegis-reject"
    d = (f[3] == "*") ? "" : "-d " f[3] " "
    np = 0
    if (port == "*") { if (proto == "*") P[++np] = ""; else P[++np] = "-p " proto " " }
    else if (proto == "*") { P[++np] = "-p tcp --dport " port " "; P[++np] = "-p udp --dport " port " " }
    else P[++np] = "-p " proto " --dport " port " "
    for (j = 1; j <= np; j++) { spec = d P[j] tgt; if (a == -2) print "-A aegis " spec; else emit("aegis", a, spec) }
  }

  # interface dispatch
  nw = split(ifw, W, " "); for (i = 1; i <= nw; i++) print "-A aegis -o " W[i] " -j aegis-wifi"
  nm = split(ifm, M, " "); for (i = 1; i <= nm; i++) print "-A aegis -o " M[i] " -j aegis-mobile"
  nv = split(ifv, V, " "); for (i = 1; i <= nv; i++) print "-A aegis -o " V[i] " -j aegis-vpn"

  if (lan) {
    if (fam == 6) nl = split("fe80::/10 fc00::/7 ff00::/8", L, " ")
    else nl = split("10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 224.0.0.0/4 255.255.255.255/32", L, " ")
    for (i = 1; i <= nl; i++) print "-A aegis-wifi -d " L[i] " -j aegis-lan"
  }

  nn = split("wifi mobile vpn lan", NETS, " ")
  for (ni = 1; ni <= nn; ni++) {
    net = NETS[ni]; ch = "aegis-" net; c = LET[net]
    if (net == "lan" && !lan) continue
    split("", DONE)
    for (i = 1; i <= NO; i++) {
      a = ORD[i]; sel = index(FL[a], c) > 0
      if (mode == "whitelist") { if (sel) { emit(ch, a, "-j RETURN"); DONE[a] = 1 } }
      else if (sel) emit(ch, a, "-j aegis-reject")
    }
    if (mode == "whitelist") {
      if (stats) for (i = 1; i <= NI; i++) { a = INET[i]; if (!(a in DONE)) emit(ch, a, "-j aegis-reject") }
      print "-A " ch " -j aegis-reject"
    }
  }

  # screen-off blocking
  if (scr) for (i = 1; i <= NO; i++) { a = ORD[i]; if (index(FL[a], "s")) emit("aegis-scr", a, "-j aegis-reject") }

  # terminal reject chain
  if (logt) print "-A aegis-reject -m limit --limit 5/sec --limit-burst 10 -j LOG --log-prefix \"AEGIS \" --log-uid"
  if (rej) { print "-A aegis-reject -p tcp -j REJECT --reject-with tcp-reset"; print "-A aegis-reject -j REJECT" }
  print "-A aegis-reject -j DROP"
  print "COMMIT"
}
