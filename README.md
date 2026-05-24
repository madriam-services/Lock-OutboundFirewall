# Lock-OutboundFirewall

Network isolation for legacy Windows Server recovery. These scripts apply a Windows Firewall outbound lockdown so a server can be brought online, started, and validated without reaching production domain controllers or other sensitive infrastructure.

## Background and design intent

The original use case was **Active Roles disaster recovery**: bringing a legacy recovery server online to work with Active Roles data or services, while preventing it from communicating with live production domain controllers. In that scenario the goal is a server that is **functional but not operational**—services can start, databases can be queried, and administrators can connect, but the host cannot participate in normal domain or enterprise traffic.

This approach is **not specific to or dependent on Active Roles**. It applies to any situation where you need a Windows Server host online for recovery, migration, forensic, or validation work, but want to limit what it can reach on the network.

## What it does

`Lock-OutboundFirewall.ps1` sets the default **outbound** firewall action to **Block** on Domain, Private, and Public profiles, then adds narrowly scoped allow rules for essential recovery traffic:

| Traffic | Direction | Ports / scope |
|---------|-----------|----------------|
| RDP | Inbound and outbound | TCP/UDP 3389 |
| SQL Server | Outbound (to specified host) | TCP (default 1433) |
| DNS | Outbound | UDP/TCP 53 |
| HTTP / HTTPS | Outbound | TCP 80 / 443 |
| Loopback | Outbound | 127.0.0.1 |

Everything else outbound is blocked. Inbound traffic remains at the profile default (Allow) except where Windows Firewall already restricts it; RDP inbound is explicitly allowed.

Before applying changes, the script backs up the current firewall profile settings and records state under `C:\ProgramData\OutboundFirewallLockdown`.

## Requirements

- Windows Server (or Windows client) with the **NetSecurity** PowerShell module
- **Administrator** privileges
- PowerShell 5.1 or later

## Usage

### Apply lockdown

Run from an elevated PowerShell session. `-SqlServer` is required and identifies the remote SQL host the server may connect to (hostname or IP):

```powershell
.\Lock-OutboundFirewall.ps1 -SqlServer 10.20.30.40
```

Optional: specify a non-default SQL port:

```powershell
.\Lock-OutboundFirewall.ps1 -SqlServer sql-recovery.contoso.local -SqlPort 1433
```

The script resolves hostnames via DNS. Because outbound DNS (port 53) is always permitted, name resolution can succeed even while other outbound traffic is blocked.

### Revert lockdown

Three tiers, from preferred to last resort:

1. **Tier 1 — restore from backup** (recommended):

   ```powershell
   .\Lock-OutboundFirewall.ps1 -Remove
   ```

   Alias: `-Revert`. Removes all `OFL-*` rules and restores firewall profiles from the most recent backup.

2. **Tier 2 — convenience wrapper**:

   ```powershell
   .\Unlock-OutboundFirewall.ps1
   ```

   Delegates to `Lock-OutboundFirewall.ps1 -Remove`.

3. **Tier 3 — manual** (if no backup exists and automated revert fails):

   - Open `wf.msc` and adjust profile defaults and rules, or
   - Run: `netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound`

To revert from a specific backup folder:

```powershell
.\Lock-OutboundFirewall.ps1 -Remove -BackupPath "C:\ProgramData\OutboundFirewallLockdown\backup-20260523-143022"
```

If no valid backup is available, use `-Force` for a last-resort revert that removes `OFL-*` rules and sets default outbound to Allow without restoring prior profile state:

```powershell
.\Lock-OutboundFirewall.ps1 -Remove -Force
```

## State and logging

| Path | Purpose |
|------|---------|
| `C:\ProgramData\OutboundFirewallLockdown\` | Root state directory |
| `backup-<timestamp>\` | Profile and rule snapshots from each apply |
| `latest.txt` | Pointer to the most recent backup |
| `apply.log` | Apply operation log |
| `revert.log` | Revert operation log |

All created firewall rules use the `OFL-` prefix and belong to the **OutboundFirewallLockdown** rule group.

## Typical recovery workflow

1. Bring the legacy or recovery server online on an isolated or restricted network segment.
2. Run `Lock-OutboundFirewall.ps1` with the appropriate SQL target before or after starting services.
3. Connect via RDP, validate SQL connectivity, and confirm required services start.
4. Confirm the host cannot reach production domain controllers or other blocked destinations.
5. When recovery work is complete, run `-Remove` or `Unlock-OutboundFirewall.ps1` to restore normal firewall behaviour.

## Important notes

- **High impact**: Default outbound becomes Block. Misconfiguration can cut off management paths or break dependencies. Always confirm you have console or out-of-band access before applying.
- **Not a complete air gap**: Allowing DNS, HTTP, and HTTPS permits name resolution and web traffic to any destination on those ports. Tighten further if your recovery scenario requires stricter isolation.
- **SQL is scoped**: Outbound SQL is allowed only to the host specified by `-SqlServer`. Adjust if your recovery database lives elsewhere.
- **Confirmation prompts**: Apply and revert operations prompt for confirmation unless `-Force` is used.
- **WhatIf support**: Both scripts support `-WhatIf` for dry-run inspection.

## Files

| File | Description |
|------|-------------|
| `Lock-OutboundFirewall.ps1` | Apply or revert outbound lockdown |
| `Unlock-OutboundFirewall.ps1` | Thin wrapper that invokes revert on the lock script |

## Authorship

Written and maintained by **Shawn Ferrier**.

## Copyright

Copyright © 2026 Madriam Services. All rights reserved.

## Licence

This project is released under the MIT Licence. The full licence text is reproduced below and is also available in [LICENSE](LICENSE).

```
MIT License

Copyright (c) 2026 Madriam Services

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
