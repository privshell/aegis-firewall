'use strict';
/* AEGIS // FIREWALL WebUI */
const MOD = '/data/adb/modules/aegis_firewall';
const CLI = `sh ${MOD}/aegis.sh`;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const HAS_KSU = typeof window.ksu !== 'undefined' && typeof window.ksu.exec === 'function';

/* ---------- shell bridge ---------- */
let cbn = 0;
function exec(cmd) {
  return new Promise(resolve => {
    if (!HAS_KSU) return resolve(mock(cmd));
    const name = `__aegis_cb_${Date.now()}_${cbn++}`;
    window[name] = (errno, stdout, stderr) => { delete window[name]; resolve({ errno, stdout: stdout || '', stderr: stderr || '' }); };
    try { window.ksu.exec(cmd, '{}', name); } catch (e) { delete window[name]; resolve({ errno: 1, stdout: '', stderr: String(e) }); }
  });
}
const cli = args => exec(`${CLI} ${args}`);
async function cliJSON(args, fallback) {
  const r = await cli(args);
  const lines = r.stdout.trim().split('\n').filter(Boolean);
  try { return JSON.parse(lines[lines.length - 1]); } catch (e) { return fallback; }
}
const b64 = s => btoa(unescape(encodeURIComponent(s)));

/* ---------- constants ---------- */
const SPECIAL = {
  0: 'Root (kernel and su)', 1000: 'Android System', 1001: 'Phone services', 1013: 'Media server', 1014: 'DHCP client',
  1019: 'DRM server', 1020: 'mDNS / multicast', 1021: 'GPS (A-GPS / SUPL)', 1029: 'CLAT (464xlat)', 1051: 'DNS resolver',
  1052: 'DNS tethering', 1073: 'Network stack', 2000: 'ADB shell', 9999: 'Nobody / isolated'
};
const ESSENTIALS = ['uid:1051', 'uid:1073', 'uid:1014', 'uid:1021', 'uid:1029', 'uid:1000'];
const ICON = {
  w: '<svg viewBox="0 0 24 24"><path d="M2 8.8a15 15 0 0 1 20 0M5 12.3a10 10 0 0 1 14 0M8.5 15.8a5 5 0 0 1 7 0"/><path d="M12 19.5h.01"/></svg>',
  m: '<svg viewBox="0 0 24 24"><path d="M4 20v-3M9 20v-7M14 20V9M19 20V4"/></svg>',
  v: '<svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
  l: '<svg viewBox="0 0 24 24"><path d="M3 11 12 4l9 7M5 10v10h14V10"/></svg>',
  r: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>',
  s: '<svg viewBox="0 0 24 24"><path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5Z"/></svg>',
  x: '<svg viewBox="0 0 24 24"><path d="M18 6 6 18M6 6l12 12"/></svg>'
};
const NETNAME = { w: 'Wi-Fi', m: 'Mobile', v: 'VPN', l: 'LAN', r: 'Roaming', s: 'Screen off' };
const ROW_NETS = ['w', 'm', 'v'];
const TCP_ST = { '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT', '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING' };

/* ---------- state ---------- */
const S = {
  groups: [], byKey: new Map(), byUid: new Map(), pkgToKey: new Map(), labels: new Map(),
  flags: new Map(), orphans: [], custom: [], temps: new Map(), settings: {}, status: {}, caps: null,
  stats: [], conns: [], filter: 'user', q: '', showNoNet: false, tab: 'apps',
  liveFilter: 'active', livePaused: false, logFilter: 'counters'
};
const mode = () => S.settings.MODE === 'whitelist' ? 'whitelist' : 'blacklist';
const on = k => S.settings[k] === '1';

/* ---------- ui helpers ---------- */
let toastT;
function toast(msg, action) {
  const t = $('#toast');
  t.innerHTML = esc(msg) + (action ? ` <button class="ghost" style="margin-left:8px;padding:4px 10px">${esc(action.label)}</button>` : '');
  t.style.pointerEvents = action ? 'auto' : 'none';
  if (action) $('button', t).onclick = () => { t.classList.remove('on'); action.fn(); };
  t.classList.add('on'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('on'), action ? 5000 : 2400);
}
const busy = v => $('#busy').classList.toggle('on', v);
function openSheet(html, bind) { $('#sheet').innerHTML = html; $('#sheetBg').classList.add('on'); if (bind) bind($('#sheet')); }
function closeSheet() { $('#sheetBg').classList.remove('on'); }
$('#sheetBg').addEventListener('click', e => { if (e.target.id === 'sheetBg') closeSheet(); });
function confirmSheet(title, text, okLabel, danger) {
  return new Promise(res => {
    openSheet(`<h2>${esc(title)}</h2><p class="hint">${esc(text)}</p><div class="row2"><button class="${danger ? 'danger' : 'primary'}" id="cOk" style="flex:1">${esc(okLabel)}</button><button class="ghost" id="cNo" style="flex:1">Cancel</button></div>`, s => {
      $('#cOk', s).onclick = () => { closeSheet(); res(true); };
      $('#cNo', s).onclick = () => { closeSheet(); res(false); };
    });
  });
}
function prettyPkg(p) {
  const skip = new Set(['com', 'org', 'net', 'io', 'me', 'de', 'app', 'apps', 'android', 'www', 'co', 'mobile']);
  const parts = p.split('.').filter(x => !skip.has(x.toLowerCase()));
  const pick = (parts.length ? parts : p.split('.')).slice(-2);
  return pick.map(x => x.charAt(0).toUpperCase() + x.slice(1)).join(' ');
}
const label = p => S.labels.get(p) || prettyPkg(p);
function hue(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) % 360; return h; }
function avatar(g) {
  const name = g.label || '?';
  const img = !g.special && g.pkgs[0] ? `<img loading="lazy" src="ksu://icon/${esc(g.pkgs[0])}" onerror="this.remove()">` : '';
  return `<div class="av" style="background:hsl(${hue(g.key)} 70% 70%)">${esc(name.charAt(0).toUpperCase())}${img}</div>`;
}
function userTag(uid) { const u = Math.floor(uid / 100000); if (!u) return ''; return `<span class="tag">${u === 999 ? 'Dual app' : 'User ' + u}</span>`; }
function fmtAgo(sec) { if (sec < 60) return `${sec | 0}s ago`; if (sec < 3600) return `${(sec / 60) | 0}m ago`; if (sec < 86400) return `${(sec / 3600) | 0}h ago`; return `${(sec / 86400) | 0}d ago`; }

/* ---------- loading ---------- */
async function loadStatus() {
  S.status = await cliJSON('status', {});
  S.settings = await cliJSON('settings', S.settings);
  renderHeader();
}
async function loadApps() {
  const apps = await cliJSON('apps', []);
  const m = new Map();
  for (const a of apps) {
    let g = m.get(a.u);
    if (!g) { g = { uid: a.u, pkgs: [], sys: true, inet: false }; m.set(a.u, g); }
    g.pkgs.push(a.p); if (!a.s) g.sys = false; if (a.i) g.inet = true;
  }
  for (const u of Object.keys(SPECIAL)) if (!m.has(+u)) m.set(+u, { uid: +u, pkgs: [], sys: true, inet: true });
  S.groups = []; S.byKey.clear(); S.byUid.clear(); S.pkgToKey.clear();
  for (const g of m.values()) {
    g.pkgs.sort();
    g.special = g.uid < 10000;
    if (g.special) { g.sys = true; g.inet = true; }
    g.key = g.special ? `uid:${g.uid}` : g.pkgs[0];
    S.groups.push(g); S.byKey.set(g.key, g); S.byUid.set(g.uid, g);
    for (const p of g.pkgs) S.pkgToKey.set(p, g.key);
  }
  relabel();
}
function relabel() {
  for (const g of S.groups) {
    if (g.special && SPECIAL[g.uid]) g.label = SPECIAL[g.uid];
    else if (g.pkgs.length) g.label = label(g.pkgs[0]) + (g.pkgs.length > 1 ? ` +${g.pkgs.length - 1}` : '');
    else g.label = `UID ${g.uid}`;
  }
}
async function loadLabels() {
  try {
    if (!HAS_KSU || typeof window.ksu.getPackagesInfo !== 'function') return;
    const pkgs = S.groups.flatMap(g => g.pkgs);
    for (let i = 0; i < pkgs.length; i += 40) {
      const raw = window.ksu.getPackagesInfo(JSON.stringify(pkgs.slice(i, i + 40)));
      const arr = typeof raw === 'string' ? JSON.parse(raw) : raw;
      for (const it of (Array.isArray(arr) ? arr : Object.values(arr || {}))) {
        const p = it.packageName || it.package || it.pkg; const l = it.appLabel || it.label || it.name;
        if (p && l) S.labels.set(p, l);
      }
      await new Promise(r => setTimeout(r, 0));
    }
    relabel(); renderApps(); fillAppOptions();
  } catch (e) { /* labels are optional */ }
}
function keyFor(p) {
  if (p === '*') return '*';
  if (/^uid:\d+$/.test(p)) { const g = S.byUid.get(+p.slice(4)); return g ? g.key : null; }
  return S.pkgToKey.get(p) || null;
}
async function loadRules() {
  const r = await cli('rules');
  S.flags = new Map(); S.orphans = [];
  for (const line of r.stdout.split('\n')) {
    const t = line.trim(); if (!t || t[0] === '#') continue;
    const [p, f = ''] = t.split(/\s+/);
    const k = keyFor(p);
    if (!k) { S.orphans.push(t); continue; }
    const cur = S.flags.get(k) || '';
    S.flags.set(k, [...new Set((cur + f).split(''))].join(''));
  }
  const c = await cli('custom');
  S.custom = [];
  for (const line of c.stdout.split('\n')) {
    const t = line.trim().split(/\s+/); if (!t[0] || t[0][0] === '#' || t.length < 3) continue;
    S.custom.push({ pkg: t[0], act: t[1], dest: t[2], port: t[3] || '*', proto: t[4] || '*' });
  }
  const tm = await cli('temps');
  S.temps = new Map(); const now = Date.now() / 1000;
  for (const line of tm.stdout.split('\n')) { const [p, e] = line.trim().split(/\s+/); if (p && +e > now) S.temps.set(p, +e); }
}
async function loadAll() {
  await loadStatus();
  await loadApps();
  await loadRules();
  renderAll();
  loadLabels();
}

/* ---------- rules logic ---------- */
const sel = (key, k) => (S.flags.get(key) || '').includes(k);
const blocked = (key, k) => k === 's' ? sel(key, k) : (mode() === 'whitelist' ? !sel(key, k) : sel(key, k));
function activeNets() { const n = ['w', 'm', 'v']; if (on('LAN')) n.push('l'); if (on('ROAMING')) n.push('r'); return n; }
function setBlocked(key, k, want) {
  const want_sel = k === 's' ? want : (mode() === 'whitelist' ? !want : want);
  let f = S.flags.get(key) || '';
  f = want_sel ? (f.includes(k) ? f : f + k) : f.replace(k, '');
  if (f) S.flags.set(key, f); else S.flags.delete(key);
}
function serializeRules() {
  const out = [`# AEGIS ${mode()} rules (letters: w wifi, m mobile, v vpn, l lan, r roaming, s screen-off block)`];
  for (const [k, f] of S.flags) if (f && k !== '*') out.push(`${k} ${f}`);
  return out.concat(S.orphans).join('\n') + '\n';
}
const serializeCustom = () => S.custom.map(c => `${c.pkg} ${c.act} ${c.dest} ${c.port} ${c.proto}`).join('\n') + '\n';
let saveT = null;
function scheduleSave() { clearTimeout(saveT); saveT = setTimeout(saveRules, 650); }
async function applyNow() {
  busy(true);
  const a = await cliJSON('apply', { ok: false, error: 'No response from the engine' });
  busy(false);
  if (!a.ok) toast(a.error || 'Apply failed'); else if (a.enabled === false) toast('Firewall is disabled');
  await loadStatus();
  return a;
}
async function saveRules() { busy(true); await cli(`put rules '${b64(serializeRules())}'`); await applyNow(); }
async function saveCustom() { busy(true); await cli(`put custom '${b64(serializeCustom())}'`); await applyNow(); }

/* ---------- header ---------- */
function renderHeader() {
  const st = S.status, p = $('#statePill');
  let cls = 'ok', txt = 'ACTIVE';
  if (!st.enabled) { cls = 'off'; txt = 'OFF'; }
  else if (st.lockdown) { cls = 'lock'; txt = 'LOCKDOWN'; }
  else if (!st.hook4) { cls = 'off'; txt = 'NOT HOOKED'; }
  p.className = 'pill ' + cls; p.textContent = txt;
  $('#subline').textContent = st.mode ? `${st.mode === 'whitelist' ? 'Whitelist' : 'Blacklist'} | ${st.profile} | ${st.rules} rules` : 'Engine not reachable';
}
$('#statePill').onclick = () => {
  openSheet(`<h2>Quick controls</h2><p class="hint">Lockdown cuts every app off the network instantly. The module Action button in your root manager does the same.</p>
    <div class="set"><div class="l"><b>Firewall</b><small>Apply rules at kernel level</small></div><label class="sw"><input type="checkbox" id="qE" ${on('ENABLED') ? 'checked' : ''}><span></span></label></div>
    <div class="set"><div class="l"><b>Lockdown</b><small>Block all app traffic now</small></div><label class="sw"><input type="checkbox" id="qL" ${on('LOCKDOWN') ? 'checked' : ''}><span></span></label></div>`, s => {
    $('#qE', s).onchange = e => setSetting('ENABLED', e.target.checked ? '1' : '0');
    $('#qL', s).onchange = e => setSetting('LOCKDOWN', e.target.checked ? '1' : '0');
  });
};

/* ---------- apps tab ---------- */
function anyBlocked(g) { return activeNets().some(k => blocked(g.key, k)) || sel(g.key, 's'); }
function visibleGroups() {
  const q = S.q.trim().toLowerCase();
  return S.groups.filter(g => {
    if (!S.showNoNet && !g.inet) return false;
    if (S.filter === 'user' && g.sys) return false;
    if (S.filter === 'system' && !g.sys) return false;
    if (S.filter === 'blocked' && !anyBlocked(g)) return false;
    if (q && !(`${g.label} ${g.pkgs.join(' ')} ${g.uid}`.toLowerCase().includes(q))) return false;
    return true;
  }).sort((a, b) => a.label.localeCompare(b.label));
}
function rowTags(g) {
  const t = [];
  if (on('LAN') && blocked(g.key, 'l')) t.push('LAN blocked');
  if (on('ROAMING') && blocked(g.key, 'r')) t.push('Roaming blocked');
  if (on('SCREEN') && sel(g.key, 's')) t.push('Screen-off block');
  const tmp = S.temps.get(g.key);
  let h = t.map(x => `<span class="tag">${x}</span>`).join('');
  if (tmp) h += `<span class="tag t">Allowed ${Math.max(1, Math.round((tmp - Date.now() / 1000) / 60))}m</span>`;
  if (S.custom.some(c => c.pkg === g.key)) h += '<span class="tag">Host rules</span>';
  return h;
}
function appRow(g) {
  const chips = ROW_NETS.map(k => `<button class="chip ${blocked(g.key, k) ? 'blk' : ''}" data-k="${k}" aria-label="${NETNAME[k]}">${ICON[k]}</button>`).join('');
  return `<div class="app" data-key="${esc(g.key)}">${avatar(g)}<div class="meta"><div class="name">${esc(g.label)}</div><div class="pkg">${esc(g.special ? 'UID ' + g.uid : g.pkgs[0])}${rowTags(g)}</div></div><div class="chips">${chips}</div></div>`;
}
function renderApps() {
  const list = visibleGroups();
  $('#appList').innerHTML = list.length ? list.map(appRow).join('') : '<div class="empty">No apps match.</div>';
  const wl = mode() === 'whitelist';
  $('#legend').innerHTML = `<span><i style="background:var(--ac)"></i>Allowed</span><span><i style="background:var(--bad)"></i>Blocked</span><span>${wl ? 'Whitelist: apps are blocked unless you allow them' : 'Blacklist: apps are allowed unless you block them'}</span>`;
  $('#colhead').innerHTML = ROW_NETS.map(k => `<button data-k="${k}">${NETNAME[k]}</button>`).join('');
}
$('#appList').addEventListener('click', e => {
  const row = e.target.closest('.app'); if (!row) return;
  const key = row.dataset.key; const chip = e.target.closest('.chip');
  if (chip) {
    const k = chip.dataset.k; setBlocked(key, k, !blocked(key, k));
    chip.classList.toggle('blk', blocked(key, k));
    $('.pkg', row).innerHTML = esc(S.byKey.get(key).special ? 'UID ' + S.byKey.get(key).uid : S.byKey.get(key).pkgs[0]) + rowTags(S.byKey.get(key));
    scheduleSave(); return;
  }
  openApp(key);
});
$('#colhead').addEventListener('click', async e => {
  const b = e.target.closest('button'); if (!b) return;
  const k = b.dataset.k, list = visibleGroups();
  const block = list.some(g => !blocked(g.key, k));
  const ok = await confirmSheet(`${block ? 'Block' : 'Allow'} ${NETNAME[k]}`, `${block ? 'Block' : 'Allow'} ${NETNAME[k]} for all ${list.length} apps in the current view?`, block ? 'Block all' : 'Allow all', block);
  if (!ok) return;
  const before = new Map(S.flags);
  list.forEach(g => setBlocked(g.key, k, block));
  renderApps(); scheduleSave();
  toast(`${list.length} apps updated`, { label: 'Undo', fn: () => { S.flags = before; renderApps(); scheduleSave(); } });
});
$('#q').addEventListener('input', e => { S.q = e.target.value; renderApps(); });
$('#appFilter').addEventListener('click', e => { const b = e.target.closest('button'); if (!b) return; $$('#appFilter button').forEach(x => x.classList.toggle('on', x === b)); S.filter = b.dataset.f; renderApps(); });
$('#showNoNet').addEventListener('change', e => { S.showNoNet = e.target.checked; renderApps(); });

function openApp(key) {
  const g = S.byKey.get(key); if (!g) return;
  const nets = [...activeNets()]; if (on('SCREEN')) nets.push('s');
  const myRules = S.custom.map((c, i) => [c, i]).filter(([c]) => c.pkg === key);
  const st = S.stats.filter(x => x.uid !== '*' && (+x.uid % 100000) === g.uid);
  const total = st.reduce((a, b) => a + b.pkts, 0);
  const myConns = S.conns.filter(c => c.uid % 100000 === g.uid && c.active);
  const tmp = S.temps.get(key);
  openSheet(`
    <div class="gh" style="display:flex;gap:12px;align-items:center">${avatar(g)}<div><h2>${esc(g.label)}</h2><div class="pkg">UID ${g.uid}${g.sys ? ' | system' : ''}${g.inet ? '' : ' | no INTERNET permission'}</div></div></div>
    ${g.pkgs.length > 1 ? `<p class="hint">Shared UID: ${g.pkgs.map(esc).join(', ')}</p>` : (g.pkgs[0] ? `<p class="hint mono">${esc(g.pkgs[0])}</p>` : '')}
    <h4>Networks</h4>
    <div class="netrow">${nets.map(k => `<button class="netbtn ${k === 's' ? 'scr' : ''} ${blocked(key, k) ? 'blk' : ''}" data-k="${k}">${ICON[k]}${NETNAME[k]}<small>${k === 's' ? (sel(key, 's') ? 'Blocked when off' : 'Not affected') : (blocked(key, k) ? 'Blocked' : 'Allowed')}</small></button>`).join('')}</div>
    <h4>Temporary access</h4>
    <div class="row2">${[15, 60, 480].map(m => `<button class="ghost" data-tmp="${m}">${m < 60 ? m + ' min' : m / 60 + ' h'}</button>`).join('')}${tmp ? '<button class="danger" data-tmp="0">End now</button>' : ''}</div>
    <p class="hint">${tmp ? `Full access until ${new Date(tmp * 1000).toLocaleTimeString()}.` : 'Grants full network access, then restores your rules automatically.'}</p>
    <h4>Host rules</h4>
    <div class="list">${myRules.map(([c, i]) => ruleRow(c, i)).join('') || '<div class="hint">None. Block or allow specific domains or IPs for this app.</div>'}</div>
    <div class="grid2" style="margin-top:8px"><input id="qDest" placeholder="domain or IP"><select id="qAct"><option value="block">Block</option><option value="allow">Allow only this</option></select></div>
    <button class="ghost" id="qAdd" style="margin-top:8px;width:100%">Add host rule</button>
    <h4>Blocked since last apply</h4>
    <div>${total ? `<div class="nets">${st.map(x => `<span>${esc(netLabel(x.net))}: ${x.pkts}</span>`).join('')}</div>` : '<div class="hint">Nothing blocked yet.</div>'}</div>
    <h4>Live connections</h4>
    <div>${myConns.length ? myConns.slice(0, 30).map(c => `<div class="conn mono"><span class="st">${c.proto} ${c.state}</span><span>${esc(c.rip)}:${c.rport}</span></div>`).join('') : '<div class="hint">No active connections in the last snapshot.</div>'}</div>
  `, s => {
    $$('.netbtn', s).forEach(b => b.onclick = () => { const k = b.dataset.k; setBlocked(key, k, !blocked(key, k)); scheduleSave(); renderApps(); openApp(key); });
    $$('[data-tmp]', s).forEach(b => b.onclick = async () => {
      const m = +b.dataset.tmp; busy(true);
      await cli(`temp '${key}' ${m}`); busy(false);
      await loadRules(); await loadStatus(); renderApps(); openApp(key);
      toast(m ? `Allowed for ${m < 60 ? m + ' minutes' : m / 60 + ' hours'}` : 'Temporary access ended');
    });
    $$('.rule .x', s).forEach(b => b.onclick = () => { S.custom.splice(+b.dataset.i, 1); saveCustom(); renderRules(); openApp(key); });
    $('#qAdd', s).onclick = () => {
      const d = $('#qDest', s).value.trim();
      if (!validDest(d)) return toast('Enter a valid domain, IP or CIDR');
      S.custom.push({ pkg: key, act: $('#qAct', s).value, dest: d, port: '*', proto: '*' });
      saveCustom(); renderRules(); openApp(key);
    };
  });
}

/* ---------- rules tab ---------- */
const validDest = d => /^(\*|(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?|[0-9a-fA-F:.]*:[0-9a-fA-F:.]*(\/\d{1,3})?|[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+)$/.test(d);
const validPort = p => p === '' || p === '*' || /^\d{1,5}(-\d{1,5})?$/.test(p);
function appName(key) { if (key === '*') return 'All apps'; const g = S.byKey.get(key); return g ? g.label : key; }
function ruleRow(c, i) {
  const pp = c.port === '*' ? (c.proto === '*' ? '' : c.proto.toUpperCase()) : `${c.proto === '*' ? 'TCP+UDP' : c.proto.toUpperCase()} ${c.port}`;
  return `<div class="rule"><span class="act ${c.act}">${c.act.toUpperCase()}</span><div class="meta"><div class="name mono">${esc(c.dest)}${pp ? ' <span class="tag">' + esc(pp) + '</span>' : ''}</div><div class="pkg">${esc(appName(c.pkg))}</div></div><button class="x" data-i="${i}">${ICON.x}</button></div>`;
}
function renderRules() {
  $('#ruleList').innerHTML = S.custom.length ? S.custom.map(ruleRow).join('') : '<div class="empty">No host rules yet.</div>';
}
function fillAppOptions() {
  $('#appOptions').innerHTML = '<option value="*">All apps</option>' + S.groups.filter(g => g.inet).sort((a, b) => a.label.localeCompare(b.label)).map(g => `<option value="${esc(g.key)}">${esc(g.label)}</option>`).join('');
}
$('#ruleList').addEventListener('click', e => { const b = e.target.closest('.x'); if (!b) return; S.custom.splice(+b.dataset.i, 1); renderRules(); saveCustom(); });
$('#rAdd').onclick = () => {
  let app = $('#rApp').value.trim(); const dest = $('#rDest').value.trim(); const port = $('#rPort').value.trim();
  if (app === '') app = '*';
  const key = keyFor(app) || (S.groups.find(g => g.label.toLowerCase() === app.toLowerCase()) || {}).key;
  if (!key) return toast('Unknown app. Pick one from the list or use *');
  if (!validDest(dest) || dest === '*' && port === '') return toast('Enter a valid domain, IP or CIDR');
  if (!validPort(port)) return toast('Port must be a number or a range like 8000-9000');
  S.custom.push({ pkg: key, act: $('#rAct').value, dest, port: port || '*', proto: $('#rProto').value });
  $('#rDest').value = ''; $('#rPort').value = '';
  renderRules(); saveCustom(); toast('Rule added');
};

/* ---------- live tab ---------- */
function ip4(h) { const n = parseInt(h, 16); return [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255].join('.'); }
function ip6(h) {
  const g = [];
  for (let i = 0; i < 4; i++) { const w = h.substr(i * 8, 8); g.push(w.substr(6, 2) + w.substr(4, 2), w.substr(2, 2) + w.substr(0, 2)); }
  if (g.slice(0, 5).every(x => x === '0000') && g[5].toUpperCase() === 'FFFF') return ip4(g[7].substr(2, 2) + g[7].substr(0, 2) + g[6].substr(2, 2) + g[6].substr(0, 2));
  const p = g.map(x => parseInt(x, 16).toString(16));
  let bs = -1, bl = 0;
  for (let i = 0; i < 8;) { if (p[i] === '0') { let j = i; while (j < 8 && p[j] === '0') j++; if (j - i > bl && j - i > 1) { bs = i; bl = j - i; } i = j; } else i++; }
  if (bs < 0) return p.join(':');
  return (p.slice(0, bs).join(':') + '::' + p.slice(bs + bl).join(':'));
}
function parseConns(txt) {
  const out = []; let proto = '';
  for (const line of txt.split('\n')) {
    if (line.startsWith('#')) { proto = line.slice(1); continue; }
    const t = line.trim().split(/\s+/); if (t.length < 8 || t[0] === 'sl') continue;
    const [lh, lp] = t[1].split(':'), [rh, rp] = t[2].split(':');
    const v6 = proto.endsWith('6');
    const rip = v6 ? ip6(rh) : ip4(rh), lip = v6 ? ip6(lh) : ip4(lh);
    const st = proto.startsWith('tcp') ? (TCP_ST[t[3]] || t[3]) : 'UDP';
    const rport = parseInt(rp, 16), uid = +t[7];
    const zero = rip === '0.0.0.0' || rip === '::';
    const loop = rip.startsWith('127.') || rip === '::1' || lip.startsWith('127.') || lip === '::1';
    out.push({ proto: proto.replace('6', '').toUpperCase(), v6, rip, rport, lport: parseInt(lp, 16), state: st, uid, active: !zero && !loop && st !== 'LISTEN' && st !== 'TIME_WAIT' && st !== 'CLOSE' });
  }
  return out;
}
function uidLabel(uid) {
  const g = S.byUid.get(uid % 100000);
  return { g, name: g ? g.label : `UID ${uid}`, tag: userTag(uid) };
}
async function loadLive() {
  const r = await cli('conns');
  S.conns = parseConns(r.stdout);
  if (S.tab === 'live') renderLive();
}
function renderLive() {
  const list = S.conns.filter(c => S.liveFilter === 'all' || c.active);
  const by = new Map();
  for (const c of list) { if (!by.has(c.uid)) by.set(c.uid, []); by.get(c.uid).push(c); }
  const groups = [...by.entries()].sort((a, b) => b[1].length - a[1].length);
  $('#liveList').innerHTML = groups.length ? groups.map(([uid, cs]) => {
    const { g, name, tag } = uidLabel(uid);
    return `<div class="grp"><div class="gh">${g ? avatar(g) : ''}<div class="meta"><div class="name">${esc(name)}${tag}</div><div class="pkg">UID ${uid}</div></div><span class="count" style="color:var(--ac)">${cs.length}</span></div>
      ${cs.slice(0, 40).map(c => `<div class="conn mono"><span class="st">${c.proto} ${c.state}</span><button class="rm" data-uid="${uid}" data-ip="${esc(c.rip)}" data-port="${c.rport}">${esc(c.rip)}${c.rport ? ':' + c.rport : ''}</button></div>`).join('')}</div>`;
  }).join('') : '<div class="empty">No active connections.</div>';
}
$('#liveList').addEventListener('click', e => {
  const b = e.target.closest('.rm'); if (!b) return;
  const uid = +b.dataset.uid, ip = b.dataset.ip, port = b.dataset.port;
  const { g, name } = uidLabel(uid);
  if (ip === '0.0.0.0' || ip === '::') return;
  openSheet(`<h2 class="mono">${esc(ip)}:${esc(port)}</h2><p class="hint">Seen from ${esc(name)}</p>
    <div class="list">
      ${g ? `<button class="danger" id="bApp">Block this address for ${esc(name)}</button>` : ''}
      <button class="danger" id="bAll">Block this address for all apps</button>
      ${g ? `<button class="ghost" id="oApp">Open ${esc(name)}</button>` : ''}
    </div>`, s => {
    const add = pkg => { S.custom.push({ pkg, act: 'block', dest: ip, port: '*', proto: '*' }); closeSheet(); renderRules(); saveCustom(); toast('Blocked ' + ip); };
    if (g) { $('#bApp', s).onclick = () => add(g.key); $('#oApp', s).onclick = () => openApp(g.key); }
    $('#bAll', s).onclick = () => add('*');
  });
});
$('#liveFilter').addEventListener('click', e => { const b = e.target.closest('button'); if (!b) return; $$('#liveFilter button').forEach(x => x.classList.toggle('on', x === b)); S.liveFilter = b.dataset.f; renderLive(); });
$('#livePause').onclick = e => { S.livePaused = !S.livePaused; e.target.textContent = S.livePaused ? 'Resume' : 'Pause'; };
setInterval(() => { if (S.tab === 'live' && !S.livePaused && !document.hidden) loadLive(); }, 2500);

/* ---------- activity tab ---------- */
function netLabel(n) { return { wifi: 'Wi-Fi', mobile: 'Mobile', vpn: 'VPN', lan: 'LAN', scr: 'Screen off', rule: 'Host rule' }[n] || n; }
async function loadActivity() {
  if (S.logFilter === 'counters') {
    S.stats = await cliJSON('stats', []);
    const by = new Map();
    for (const x of S.stats) { if (!by.has(x.uid)) by.set(x.uid, []); by.get(x.uid).push(x); }
    const rows = [...by.entries()].map(([uid, xs]) => ({ uid, xs, total: xs.reduce((a, b) => a + b.pkts, 0) })).sort((a, b) => b.total - a.total);
    $('#logHint').textContent = 'Packets blocked per app since the rules were last applied. Tap an app to change its rules.';
    $('#logList').innerHTML = rows.length ? rows.map(r => {
      const info = r.uid === '*' ? { g: null, name: 'Other apps (catch-all)', tag: '' } : uidLabel(+r.uid);
      return `<div class="grp" data-key="${info.g ? esc(info.g.key) : ''}"><div class="gh">${info.g ? avatar(info.g) : ''}<div class="meta"><div class="name">${esc(info.name)}${info.tag}</div><div class="nets">${r.xs.map(x => `<span>${netLabel(x.net)} ${x.pkts}</span>`).join('')}</div></div><span class="count">${r.total}</span></div></div>`;
    }).join('') : '<div class="empty">Nothing blocked since the last apply.</div>';
  } else {
    const r = await cli('log');
    const lines = r.stdout.split('\n');
    const up = lines.find(l => l.startsWith('#UPTIME'));
    const [, upt, now] = up ? up.split(' ') : [0, 0, Date.now() / 1000];
    const re = /\[\s*([\d.]+)\].*AEGIS .*?OUT=(\S*).*?DST=(\S+).*?PROTO=(\S+)(?:.*?DPT=(\d+))?.*?UID=(\d+)/;
    const ev = lines.map(l => re.exec(l)).filter(Boolean).map(m => ({ t: +now - (+upt - +m[1]), out: m[2], dst: m[3], proto: m[4], port: m[5] || '', uid: +m[6] })).reverse();
    $('#logHint').textContent = S.status.caps && S.status.caps.log ? 'Recent blocked attempts from the kernel log (rate limited).' : 'This kernel has no LOG target, so the live log is unavailable. Use Blocked per app instead.';
    $('#logList').innerHTML = ev.length ? ev.slice(0, 200).map(x => {
      const info = uidLabel(x.uid);
      return `<div class="grp" data-key="${info.g ? esc(info.g.key) : ''}"><div class="gh"><div class="meta"><div class="name">${esc(info.name)}${info.tag}</div><div class="pkg mono">${esc(x.proto)} ${esc(x.dst)}${x.port ? ':' + x.port : ''} via ${esc(x.out)}</div></div><span class="tiny">${fmtAgo(Date.now() / 1000 - x.t)}</span></div></div>`;
    }).join('') : '<div class="empty">No log entries.</div>';
  }
}
$('#logList').addEventListener('click', e => { const g = e.target.closest('.grp'); if (g && g.dataset.key) openApp(g.dataset.key); });
$('#logFilter').addEventListener('click', e => { const b = e.target.closest('button'); if (!b) return; $$('#logFilter button').forEach(x => x.classList.toggle('on', x === b)); S.logFilter = b.dataset.f; loadActivity(); });
$('#logRefresh').onclick = loadActivity;

/* ---------- settings tab ---------- */
function sw(key, title, desc) {
  return `<div class="set"><div class="l"><b>${title}</b><small>${desc}</small></div><label class="sw"><input type="checkbox" data-set="${key}" ${on(key) ? 'checked' : ''}><span></span></label></div>`;
}
async function setSetting(k, v) {
  busy(true); await cli(`set ${k} ${v}`); S.settings[k] = v;
  await applyNow();
  if (k === 'MODE') await loadRules();
  renderAll();
}
async function renderSettings() {
  const prof = await cliJSON('profiles', { active: 'default', list: [] });
  const wl = mode() === 'whitelist';
  $('#settingsBox').innerHTML = `
  <div class="card"><h3>Firewall</h3>
    ${sw('ENABLED', 'Enabled', 'Hook the AEGIS chains into the kernel')}
    <div class="set"><div class="l"><b>Mode</b><small>${wl ? 'Whitelist: every app is blocked unless allowed.' : 'Blacklist: every app is allowed unless blocked.'} Each mode keeps its own rule set.</small></div></div>
    <div class="seg" id="modeSeg"><button data-m="blacklist" class="${wl ? '' : 'on'}">Blacklist</button><button data-m="whitelist" class="${wl ? 'on' : ''}">Whitelist</button></div>
    ${wl ? '<button class="ghost" id="essentials" style="width:100%;margin-top:10px">Allow essentials (DNS, network stack, DHCP, GPS, CLAT, Android System)</button>' : ''}
    ${sw('LOCKDOWN', 'Lockdown', 'Block all app traffic immediately')}
  </div>
  <div class="card"><h3>Networks</h3>
    ${sw('LAN', 'Separate LAN control', 'Treat local network (192.168.x, 10.x, mDNS) apart from internet over Wi-Fi')}
    ${sw('ROAMING', 'Separate roaming control', 'Use different mobile rules while roaming')}
    ${sw('SCREEN', 'Screen-off blocking', 'Cut selected apps off the network while the screen is off')}
    <div class="set"><div class="l"><b>Screen-off delay</b><small>Wait before blocking, so quick screen toggles do not drop connections</small></div>
      <select id="scrDelay" style="width:auto">${[0, 10, 30, 60, 300].map(v => `<option value="${v}" ${S.settings.SCREEN_DELAY == v ? 'selected' : ''}>${v ? (v < 60 ? v + ' s' : v / 60 + ' min') : 'None'}</option>`).join('')}</select></div>
  </div>
  <div class="card"><h3>Behavior</h3>
    ${sw('ALL_USERS', 'All profiles and users', 'Apply rules to Dual apps, Second space, work profiles and other users')}
    ${sw('NEWAPP_BLOCK', 'Block new apps', 'Blacklist mode: newly installed apps start blocked (whitelist mode always does)')}
    ${sw('NOTIFY', 'New app notifications', 'Notify when a newly installed app is cut off')}
    ${sw('REJECT', 'Fail fast (REJECT)', 'Apps get an instant error instead of waiting on a silent DROP')}
    ${sw('STATS', 'Per-app block counters', 'Count blocked packets per app (adds a few rules in whitelist mode)')}
    ${sw('LOGGING', 'Kernel log', 'Write blocked attempts to the kernel log when supported')}
  </div>
  <div class="card"><h3>Profiles</h3>
    <div class="list">${prof.list.map(p => `<div class="rule"><span class="act ${p.name === prof.active ? 'allow' : ''}" style="${p.name === prof.active ? '' : 'background:var(--s3);color:var(--mu)'}">${p.name === prof.active ? 'ACTIVE' : 'IDLE'}</span><div class="meta"><div class="name">${esc(p.name)}</div><div class="pkg">${p.rules} app rules</div></div>${p.name === prof.active ? '' : `<button class="ghost" data-psw="${esc(p.name)}">Use</button>${p.name === 'default' ? '' : `<button class="x" data-pdel="${esc(p.name)}">${ICON.x}</button>`}`}</div>`).join('')}</div>
    <div class="grid2" style="margin-top:10px"><input id="pName" placeholder="New profile name"><button class="ghost" id="pNew">Copy current</button></div>
  </div>
  <div class="card"><h3>Backup</h3><p class="hint">Settings, profiles and rules are saved to Download.</p>
    <div class="row2"><button class="ghost" id="bExp" style="flex:1">Export</button><button class="ghost" id="bImp" style="flex:1">Import</button></div></div>
  <div class="card"><h3>Diagnostics</h3><div id="diag" class="kv"><span>Status</span><span>Loading...</span></div>
    <div class="row2" style="margin-top:12px"><button class="ghost" id="dApply" style="flex:1">Re-apply rules</button><button class="ghost" id="dLog" style="flex:1">Daemon log</button></div>
    <button class="danger" id="dReset" style="width:100%;margin-top:8px">Reset rules in this profile</button></div>
  <div class="card"><h3>About</h3><div class="kv"><span>Version</span><span>${esc(S.status.version || '-')}</span><span>Engine</span><span>iptables owner match, atomic iptables-restore</span><span>Author</span><span>kreza6173-pixel</span></div></div>`;

  const box = $('#settingsBox');
  $$('[data-set]', box).forEach(i => i.onchange = () => setSetting(i.dataset.set, i.checked ? '1' : '0'));
  $('#scrDelay', box).onchange = e => setSetting('SCREEN_DELAY', e.target.value);
  $$('#modeSeg button', box).forEach(b => b.onclick = async () => {
    const m = b.dataset.m; if (m === mode()) return;
    if (m === 'whitelist') {
      const ok = await confirmSheet('Switch to whitelist', 'Every app without an allow rule loses network access right away, including system services. You can add essentials in one tap afterwards.', 'Switch');
      if (!ok) return;
    }
    setSetting('MODE', m);
  });
  const ess = $('#essentials', box);
  if (ess) ess.onclick = () => { ESSENTIALS.forEach(k => { if (S.byKey.has(k)) for (const n of ['w', 'm', 'v', 'l', 'r']) setBlocked(k, n, false); }); renderApps(); saveRules(); toast('Essentials allowed'); };
  $$('[data-psw]', box).forEach(b => b.onclick = async () => { busy(true); await cli(`profile switch ${b.dataset.psw}`); busy(false); await loadStatus(); await loadRules(); renderAll(); toast('Profile: ' + b.dataset.psw); });
  $$('[data-pdel]', box).forEach(b => b.onclick = async () => { if (await confirmSheet('Delete profile', `Delete "${b.dataset.pdel}" and its rules?`, 'Delete', true)) { await cli(`profile delete ${b.dataset.pdel}`); renderSettings(); } });
  $('#pNew', box).onclick = async () => {
    const n = $('#pName', box).value.trim();
    if (!/^[A-Za-z0-9_-]{1,24}$/.test(n)) return toast('Use letters, numbers, - or _ (max 24)');
    const r = await cliJSON(`profile new ${n} ${S.status.profile || 'default'}`, { ok: false });
    if (!r.ok) return toast(r.error || 'Could not create profile');
    toast('Profile created'); renderSettings();
  };
  $('#bExp', box).onclick = async () => { const r = await cliJSON('export', { ok: false }); toast(r.ok ? 'Saved ' + r.file.split('/').pop() : 'Export failed'); };
  $('#bImp', box).onclick = async () => {
    const files = await cliJSON('backups', []);
    if (!files.length) return toast('No aegis-backup files in Download');
    openSheet(`<h2>Import backup</h2><p class="hint">This replaces current settings and profiles.</p><div class="list">${files.reverse().map(f => `<button class="ghost" data-f="${esc(f)}" style="text-align:left">${esc(f.split('/').pop())}</button>`).join('')}</div>`, s => {
      $$('[data-f]', s).forEach(b => b.onclick = async () => { closeSheet(); busy(true); await cli(`import '${b.dataset.f}'`); busy(false); await loadAll(); toast('Backup restored'); });
    });
  };
  $('#dApply', box).onclick = async () => { const a = await applyNow(); if (a.ok) toast(`Applied ${a.rules} rules in ${a.ms} ms`); renderSettings(); };
  $('#dLog', box).onclick = async () => { const r = await cli('daemonlog'); const e = await cli('errors'); openSheet(`<h2>Daemon log</h2><pre class="mono" style="white-space:pre-wrap;color:var(--mu)">${esc(r.stdout || 'Empty')}${e.stdout ? '\n\nLast iptables-restore errors:\n' + esc(e.stdout) : ''}</pre>`); };
  $('#dReset', box).onclick = async () => { if (await confirmSheet('Reset rules', `Clear every app rule in "${S.status.profile}" for ${mode()} mode? Host rules are kept.`, 'Reset', true)) { S.flags.clear(); S.orphans = []; renderApps(); saveRules(); } };

  if (!S.caps) S.caps = await cliJSON('doctor', {});
  const c = S.caps, st = S.status, yn = v => v ? '<span class="okc">yes</span>' : '<span class="badc">no</span>';
  $('#diag', box).innerHTML = `<span>OUTPUT hook</span><span>IPv4 ${yn(st.hook4)} | IPv6 ${yn(st.hook6)}</span><span>Daemon</span><span>${yn(st.daemon)}</span>
    <span>Owner match</span><span>${yn(c.owner)}</span><span>IPv6 filtering</span><span>${yn(c.ipv6)}</span><span>REJECT</span><span>${yn(c.reject)}</span><span>Kernel LOG</span><span>${yn(c.log)}</span>
    <span>Users</span><span>${esc(st.users || '0')}</span><span>Screen</span><span>${esc(st.screen || '-')}</span><span>Roaming</span><span>${st.roaming ? 'yes' : 'no'}</span>
    <span>Kernel</span><span class="mono">${esc(c.kernel || '-')}</span><span>Device</span><span>${esc(c.device || '-')} | SDK ${esc(c.sdk || '-')}</span>
    <span>Last apply</span><span>${st.lastApply ? fmtAgo(Date.now() / 1000 - st.lastApply) : 'never'}</span>`;
}

/* ---------- nav ---------- */
$$('nav.bottom button').forEach(b => b.onclick = () => {
  S.tab = b.dataset.tab;
  $$('nav.bottom button').forEach(x => x.classList.toggle('on', x === b));
  $$('.tab').forEach(t => t.classList.toggle('active', t.id === 'tab-' + S.tab));
  window.scrollTo(0, 0);
  if (S.tab === 'live') loadLive();
  if (S.tab === 'log') loadActivity();
  if (S.tab === 'rules') renderRules();
  if (S.tab === 'settings') renderSettings();
});
function renderAll() { renderHeader(); renderApps(); renderRules(); fillAppOptions(); if (S.tab === 'settings') renderSettings(); }

/* ---------- browser preview mock ---------- */
function mock(cmd) {
  const a = cmd.replace(CLI + ' ', '').split(' ')[0];
  const out = {
    status: '{"version":"v1.0.0","enabled":1,"mode":"blacklist","profile":"default","lockdown":0,"hook4":1,"hook6":1,"daemon":1,"screen":"on","roaming":0,"users":"0 999","rules":64,"lastApply":' + ((Date.now() / 1000 | 0) - 90) + ',"caps":{"owner":1,"reject":1,"log":0,"ipv6":1}}',
    settings: '{"ENABLED":"1","MODE":"blacklist","LOCKDOWN":"0","REJECT":"1","LOGGING":"1","STATS":"1","LAN":"1","ROAMING":"0","SCREEN":"1","SCREEN_DELAY":"10","ALL_USERS":"1","NEWAPP_BLOCK":"0","NOTIFY":"1"}',
    apps: JSON.stringify([['org.telegram.messenger', 10201, 0], ['com.whatsapp', 10150, 0], ['com.instagram.android', 10233, 0], ['com.google.android.youtube', 10120, 1], ['com.android.chrome', 10111, 1], ['com.miui.analytics', 10090, 1], ['com.xiaomi.joyose', 10099, 1], ['com.spotify.music', 10240, 0], ['com.android.settings', 1000, 1], ['com.google.android.gms', 10105, 1]].map(([p, u, s]) => ({ p, u, s, i: 1 }))),
    rules: 'com.miui.analytics wmvlr\ncom.xiaomi.joyose wmv\ncom.instagram.android ms\n',
    custom: 'com.whatsapp block graph.facebook.com * *\n* block 157.240.0.0/16 443 tcp\n',
    temps: '', profiles: '{"active":"default","list":[{"name":"default","rules":3},{"name":"travel","rules":12}]}',
    stats: '[{"net":"wifi","uid":"10090","pkts":312},{"net":"mobile","uid":"10233","pkts":41},{"net":"rule","uid":"10150","pkts":9}]',
    conns: '#tcp\n  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0F02000A:A1B2 2200F09D:01BB 01 00000000:00000000 00:00000000 00000000 10150 0 1\n   1: 0F02000A:A1B3 4A7D4D8E:01BB 01 00000000:00000000 00:00000000 00000000 10201 0 2\n#tcp6\n   0: 0000000000000000FFFF00000F02000A:B1B2 0000000000000000FFFF0000AB4C7D8E:01BB 01 0 0 0 10120 0 3\n#udp\n#udp6\n',
    doctor: '{"owner":1,"reject":1,"limit":1,"log":0,"ipv6":1,"kernel":"5.10.226-android12-9","sdk":"36","device":"tanzanite"}',
    backups: '[]', log: '#UPTIME 1000 ' + (Date.now() / 1000 | 0)
  }[a];
  return { errno: 0, stdout: out !== undefined ? out : '{"ok":true,"rules":64,"ms":38}', stderr: '' };
}

loadAll();
