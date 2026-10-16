# AEGIS // FIREWALL

A kernel-level, per-app firewall for rooted Android, shipped as a KernelSU module with a full WebUI.
No VPN slot, no companion app, no background Java service: rules live in netfilter, the engine is a small shell daemon.

## Why another firewall
AEGIS targets the long-standing gaps people keep reporting in existing iptables firewalls:

| Pain point | AEGIS answer |
| --- | --- |
| Per-app address filtering | Host rules: block or allow a domain, IP or CIDR, optionally per port and protocol, per app or for every app |
| Separate screen-on / screen-off rules | Screen-off blocking per app, event driven, with a configurable delay |
| Rules break on connectivity change | Wildcard interface chains: nothing to re-apply when you switch Wi-Fi, mobile or VPN |
| Rules missing until the phone is unlocked | Applied at boot from the root service, before you unlock |
| Work profile / Dual apps / multi-user apps missing | Rules are expanded for every Android user (HyperOS Dual apps = user 999) |
| Half-applied rules, slowdowns | One atomic `iptables-restore` per address family, about 40 ms |
| Logs that never show anything | Per-app blocked counters that work on any kernel, plus kernel LOG when available |
| New profiles start empty | Profiles can be copied from the current one |
| Bloat apps silently installed | Optional "block new apps" plus notifications |
| No quick kill switch | Lockdown from the WebUI or the module Action button |
| netd wiping the hook | Watchdog re-hooks the OUTPUT chain automatically |

Extra: a Live view of every socket per app (read straight from `/proc/net`), with one-tap "block this address".

## Features
- Blacklist or whitelist mode, each with its own rule set
- Per-app control for Wi-Fi, mobile data, VPN, LAN and roaming
- IPv4 and IPv6
- Host rules (domains are resolved through the system resolver and refreshed every 6 hours)
- Temporary access: 15 min, 1 h, 8 h, auto-revert
- Screen-off blocking
- Profiles, backup and restore to `Download`
- Lockdown kill switch, also on the KernelSU Action button
- Diagnostics: kernel capability probe, hook state, daemon log, last restore errors

## Requirements
- KernelSU (or KernelSU Next / APatch / Magisk with a WebUI-capable manager)
- Kernel with the iptables `owner` match (all GKI kernels have it). The installer checks this and aborts if it is missing.

## Install
Install from [KernelSU Modules](https://modules.kernelsu.org) or download the ZIP from [Releases](https://github.com/privshell/aegis-firewall/releases) and flash it in your root manager. Reboot, then open the WebUI from the module card.

Default mode is blacklist with nothing blocked, so installing changes nothing until you add rules.

## CLI
```
sh /data/adb/modules/aegis_firewall/aegis.sh <command>
```
`apply`, `status`, `enable`, `disable`, `lockdown on|off|toggle`, `stats`, `doctor`, `conns`, `log`, `profiles`, `profile switch|new|delete`, `export`, `import <file>`, `resolve`, `teardown`.

## Files
Config lives in `/data/adb/aegis` and survives module updates and uninstalls.
- `settings.conf` global settings
- `profiles/<name>/rules.conf` blacklist selections, `allow.conf` whitelist selections
- `profiles/<name>/custom.conf` host rules: `<package|*> <allow|block> <host|ip|cidr|*> <port|*> <tcp|udp|*>`

Rule letters: `w` Wi-Fi, `m` mobile, `v` VPN, `l` LAN, `r` roaming, `s` block when the screen is off.

## Notes
- Domain rules match the resolved IPs, so shared CDN addresses can affect other sites on the same IP. Subdomains need their own rule.
- Uninstalling removes every rule from the kernel. Delete `/data/adb/aegis` to wipe the config too.

## Releasing (maintainers)
Bump `version` and `versionCode` in `module/module.prop`, then run the **Release** workflow from the Actions tab (or push a `v*` tag). It tags the commit, validates the ZIP with the KernelSU Modules validator and publishes an immutable release.

## Support
AEGIS is free and open source, built in spare time. If it saved you time, you can [support the work with a small crypto donation](https://github.com/privshell/privshell/blob/main/DONATE.md) (USDT on TRC20, or USDC / SOL on Solana). Starring the repo or opening a clear issue helps just as much.

## License
MIT
