## AEGIS // FIREWALL v1.0.0

First public release.

- Blacklist and whitelist modes, each with its own rule set
- Per-app control for Wi-Fi, mobile data, VPN, LAN and roaming, IPv4 and IPv6
- Host rules: block or allow a domain, IP or CIDR, optionally per port and protocol, per app or for all apps
- Temporary access (15 min, 1 h, 8 h) that reverts on its own
- Screen-off blocking with a configurable delay
- Rules for every Android user: Dual apps, Second space, work profiles
- Rules applied at boot, before the device is unlocked, in one atomic iptables-restore per address family
- Watchdog that restores the OUTPUT hook if the system removes it
- Live connections per app with one-tap address blocking
- Per-app blocked counters on any kernel, plus kernel LOG when available
- Profiles, backup and restore
- Lockdown kill switch in the WebUI and on the module Action button
- Diagnostics: kernel capability probe, hook state, daemon log, restore errors

Requires a kernel with the iptables owner match (all GKI kernels). The installer checks this and aborts if it is missing.
