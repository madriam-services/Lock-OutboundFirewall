#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High", DefaultParameterSetName = "Apply")]
param(
    [Parameter(Mandatory, ParameterSetName = "Apply")]
    [string]$SqlServer,

    [Parameter(ParameterSetName = "Apply")]
    [ValidateRange(1, 65535)]
    [int]$SqlPort = 1433,

    [Parameter(ParameterSetName = "Remove")]
    [Alias("Revert")]
    [switch]$Remove,

    [Parameter(ParameterSetName = "Remove")]
    [string]$BackupPath,

    [Parameter(ParameterSetName = "Remove")]
    [switch]$Force
)

<#
.SYNOPSIS
Applies or reverts outbound firewall lockdown on a Windows Server host.

.DESCRIPTION
Sets the default outbound firewall policy to Block and creates narrowly scoped
allow rules for loopback, inbound/outbound RDP, outbound SQL,
and always-on outbound DNS (port 53) and web (ports 80/443).

The script also supports rollback from backups created during apply operations:
-Remove (or -Revert alias) deletes OFL-* rules and restores profile defaults.

.PARAMETER Remove
Revert an earlier apply action using the latest backup or -BackupPath.
Alias: -Revert. Use -Force when no backup exists (last-resort revert).

.PARAMETER SqlServer
Remote SQL hostname or IP used by the outbound SQL allow rule (apply mode).

.PARAMETER SqlPort
Remote SQL TCP port. Default is 1433.

Inbound RDP (TCP/UDP port 3389) and outbound RDP session traffic (TCP/UDP from port 3389)
are always permitted. Outbound DNS (UDP/TCP 53) and HTTP/HTTPS (80/443) are always permitted.

.PARAMETER BackupPath
Specific backup folder to use for revert. If omitted, latest.txt pointer is used.

.PARAMETER Force
Skip confirmation prompts, or perform last-resort revert when no backup is available.

.EXAMPLE
.\Lock-OutboundFirewall.ps1 -SqlServer 10.20.30.40

.EXAMPLE
.\Lock-OutboundFirewall.ps1 -Remove

.NOTES
Tier 1 revert: .\Lock-OutboundFirewall.ps1 -Remove
Tier 2 revert: .\Unlock-OutboundFirewall.ps1
Tier 3 manual: use wf.msc or netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:ScriptVersion = "1.2.0"
$script:RulePrefix = "OFL-"
$script:RdpLocalPort = 3389
$script:TargetProfiles = @("Domain", "Private", "Public")
$script:StateRoot = "C:\ProgramData\OutboundFirewallLockdown"
$script:ApplyLogPath = Join-Path -Path $script:StateRoot -ChildPath "apply.log"
$script:RevertLogPath = Join-Path -Path $script:StateRoot -ChildPath "revert.log"
$script:LatestPointerPath = Join-Path -Path $script:StateRoot -ChildPath "latest.txt"

function Initialize-StateRoot {
    if (-not (Test-Path -LiteralPath $script:StateRoot)) {
        New-Item -Path $script:StateRoot -ItemType Directory -Force | Out-Null
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter(Mandatory)]
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Path
    )

    Initialize-StateRoot
    $timestamp = (Get-Date).ToString("s")
    Add-Content -LiteralPath $Path -Value "[$timestamp][$Level] $Message"
}

function Assert-NetSecurityModule {
    if (-not (Get-Module -ListAvailable -Name NetSecurity)) {
        throw "NetSecurity module is not available on this host."
    }
    Import-Module NetSecurity -ErrorAction Stop
}

function Resolve-SqlAddress {
    param(
        [Parameter(Mandatory)]
        [string]$TargetName
    )

    if ($TargetName -match '^[0-9a-fA-F\:\.\/]+$') {
        return $TargetName
    }

    try {
        $resolved = Resolve-DnsName -Name $TargetName -Type A -ErrorAction Stop |
            Select-Object -First 1 -ExpandProperty IPAddress
        if ([string]::IsNullOrWhiteSpace($resolved)) {
            throw "No A record found."
        }
        return $resolved
    } catch {
        throw "Failed to resolve SQL host '$TargetName'. Pass an IP, or ensure DNS is reachable (outbound DNS is always allowed on port 53)."
    }
}

function Remove-LegacyRdpClientRules {
    foreach ($name in @(
        "$($script:RulePrefix)Allow-RdpClients",
        "$($script:RulePrefix)Allow-RdpClients-Tcp",
        "$($script:RulePrefix)Allow-RdpClients-Udp"
    )) {
        Remove-RuleByName -DisplayName $name
    }
}

function Remove-RuleByName {
    param([Parameter(Mandatory)][string]$DisplayName)

    $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        $existing | Remove-NetFirewallRule
    }
}

function Backup-FirewallState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SqlTarget,
        [Parameter(Mandatory)]
        [int]$SqlTargetPort,
        [Parameter(Mandatory)]
        [string[]]$ProfileNames
    )

    Initialize-StateRoot
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupDir = Join-Path -Path $script:StateRoot -ChildPath ("backup-" + $stamp)
    New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

    $profilesPath = Join-Path -Path $backupDir -ChildPath "profiles.xml"
    $oflBeforePath = Join-Path -Path $backupDir -ChildPath "ofl-rules-before.json"
    $manifestPath = Join-Path -Path $backupDir -ChildPath "manifest.json"

    Get-NetFirewallProfile | Export-Clixml -LiteralPath $profilesPath
    (Get-NetFirewallRule -DisplayName "$($script:RulePrefix)*" -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty DisplayName) |
        ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath $oflBeforePath -Encoding UTF8

    $manifest = [ordered]@{
        scriptVersion = $script:ScriptVersion
        createdAt = (Get-Date).ToString("o")
        profiles = $ProfileNames
        sqlServer = $SqlTarget
        sqlPort = $SqlTargetPort
        standardOutboundAllows = @(
            "rdp-inbound-tcp-udp-3389",
            "rdp-outbound-tcp-udp-3389",
            "dns-udp-53",
            "dns-tcp-53",
            "http-80",
            "https-443"
        )
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Set-Content -LiteralPath $script:LatestPointerPath -Value $backupDir -Encoding ASCII

    return $backupDir
}

function Confirm-HighImpact {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message)

    if ($Force) {
        return
    }

    $caption = "Outbound Firewall Lockdown"
    if (-not $PSCmdlet.ShouldContinue($Message, $caption)) {
        throw "Operation cancelled by user."
    }
}

function Set-AllowRule {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Direction,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Protocol,
        [Parameter()][string[]]$RemoteAddress,
        [Parameter()][string]$RemotePort,
        [Parameter()][string]$LocalPort
    )

    Remove-RuleByName -DisplayName $DisplayName

    $ruleParams = @{
        DisplayName = $DisplayName
        Group = "OutboundFirewallLockdown"
        Direction = $Direction
        Action = $Action
        Enabled = "True"
        Profile = $script:TargetProfiles
        Protocol = $Protocol
    }

    if ($RemoteAddress -and $RemoteAddress.Count -gt 0) {
        $ruleParams.RemoteAddress = ($RemoteAddress -join ",")
    }
    if (-not [string]::IsNullOrWhiteSpace($RemotePort)) {
        $ruleParams.RemotePort = $RemotePort
    }
    if (-not [string]::IsNullOrWhiteSpace($LocalPort)) {
        $ruleParams.LocalPort = $LocalPort
    }

    New-NetFirewallRule @ruleParams -ErrorAction Stop | Out-Null
}

function Set-AllowInboundRdp {
    param([Parameter(Mandatory)][int]$LocalPort)

    Set-AllowRule -DisplayName "$($script:RulePrefix)Allow-RdpInbound-Tcp" -Direction Inbound -Action Allow -Protocol TCP -LocalPort "$LocalPort"
    Set-AllowRule -DisplayName "$($script:RulePrefix)Allow-RdpInbound-Udp" -Direction Inbound -Action Allow -Protocol UDP -LocalPort "$LocalPort"
}

function Set-AllowRdpOutbound {
    param([Parameter(Mandatory)][int]$LocalPort)

    Set-AllowRule -DisplayName "$($script:RulePrefix)Allow-RdpOutbound-Tcp" -Direction Outbound -Action Allow -Protocol TCP -LocalPort "$LocalPort"
    Set-AllowRule -DisplayName "$($script:RulePrefix)Allow-RdpOutbound-Udp" -Direction Outbound -Action Allow -Protocol UDP -LocalPort "$LocalPort"
    Remove-LegacyRdpClientRules
}

function Set-StandardOutboundAllows {
    Set-AllowRule -DisplayName "$($script:RulePrefix)Allow-DnsUdp" -Direction Outbound -Action Allow -Protocol UDP -RemotePort "53"
    Set-AllowRule -DisplayName "$($script:RulePrefix)Allow-DnsTcp" -Direction Outbound -Action Allow -Protocol TCP -RemotePort "53"
    Set-AllowRule -DisplayName "$($script:RulePrefix)Allow-Http" -Direction Outbound -Action Allow -Protocol TCP -RemotePort "80"
    Set-AllowRule -DisplayName "$($script:RulePrefix)Allow-Https" -Direction Outbound -Action Allow -Protocol TCP -RemotePort "443"
}

function Invoke-Apply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $resolvedSql = Resolve-SqlAddress -TargetName $SqlServer
    Confirm-HighImpact -Message "This will set default outbound action to Block (RDP inbound/outbound stays allowed) for all firewall profiles. Continue?"

    $targetDescription = "Firewall profiles [$($script:TargetProfiles -join ', ')]"
    if ($PSCmdlet.ShouldProcess($targetDescription, "Apply outbound lockdown")) {
        $backup = Backup-FirewallState -SqlTarget $resolvedSql -SqlTargetPort $SqlPort -ProfileNames $script:TargetProfiles
        Write-Log -Path $script:ApplyLogPath -Level "INFO" -Message "Backup created at $backup"

        Set-NetFirewallProfile -Profile $script:TargetProfiles -DefaultInboundAction Allow -DefaultOutboundAction Block -Enabled True
        Write-Log -Path $script:ApplyLogPath -Level "INFO" -Message "Profiles updated: inbound Allow, outbound Block."

        Set-AllowInboundRdp -LocalPort $script:RdpLocalPort
        Set-AllowRdpOutbound -LocalPort $script:RdpLocalPort
        Write-Log -Path $script:ApplyLogPath -Level "INFO" -Message "RDP allow rules applied on port $($script:RdpLocalPort) (inbound and outbound TCP/UDP)."

        Set-AllowRule -DisplayName "$($script:RulePrefix)Allow-Loopback" -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress @("127.0.0.1")
        Set-StandardOutboundAllows
        Write-Log -Path $script:ApplyLogPath -Level "INFO" -Message "Standard outbound allows applied: DNS 53, HTTP 80, HTTPS 443."

        Set-AllowRule -DisplayName "$($script:RulePrefix)Allow-SqlOutbound" -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress @($resolvedSql) -RemotePort "$SqlPort"

        Write-Log -Path $script:ApplyLogPath -Level "INFO" -Message "Apply completed. SQL target: ${resolvedSql}:$SqlPort"
        Write-Output "Apply complete. Backup stored at: $backup"
    }
}

function Resolve-BackupPath {
    if (-not [string]::IsNullOrWhiteSpace($BackupPath)) {
        if (-not (Test-Path -LiteralPath $BackupPath)) {
            throw "BackupPath does not exist: $BackupPath"
        }
        return $BackupPath
    }

    if (-not (Test-Path -LiteralPath $script:LatestPointerPath)) {
        return $null
    }

    $pointer = (Get-Content -LiteralPath $script:LatestPointerPath -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    if ([string]::IsNullOrWhiteSpace($pointer)) {
        return $null
    }
    if (-not (Test-Path -LiteralPath $pointer)) {
        return $null
    }
    return $pointer
}

function Invoke-ForceDefaultRevert {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ($PSCmdlet.ShouldProcess("Firewall profiles", "Set all profiles default outbound to Allow")) {
        Remove-NetFirewallRule -DisplayName "$($script:RulePrefix)*" -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile $script:TargetProfiles -DefaultOutboundAction Allow
        Write-Log -Path $script:RevertLogPath -Level "WARN" -Message "Last-resort revert used; backup restore unavailable."
        Write-Warning "Manual fallback guidance: use wf.msc or run 'netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound'."
        Write-Output "Force revert completed."
    }
}

function Invoke-Remove {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Confirm-HighImpact -Message "This will remove OFL-* rules and restore firewall profiles from backup. Continue?"
    $resolvedBackup = Resolve-BackupPath
    if ($null -eq $resolvedBackup) {
        if (-not $Force) {
            throw "No valid backup found. Use -Remove -Force for last-resort revert, or restore a backup folder."
        }
        Invoke-ForceDefaultRevert
        return
    }

    $profilesPath = Join-Path -Path $resolvedBackup -ChildPath "profiles.xml"
    if (-not (Test-Path -LiteralPath $profilesPath)) {
        throw "Backup is missing profiles.xml: $profilesPath"
    }

    if ($PSCmdlet.ShouldProcess($resolvedBackup, "Revert outbound lockdown")) {
        Remove-NetFirewallRule -DisplayName "$($script:RulePrefix)*" -ErrorAction SilentlyContinue

        $profiles = Import-Clixml -LiteralPath $profilesPath
        foreach ($savedProfile in $profiles) {
            Set-NetFirewallProfile -Profile $savedProfile.Name `
                -Enabled $savedProfile.Enabled `
                -DefaultInboundAction $savedProfile.DefaultInboundAction `
                -DefaultOutboundAction $savedProfile.DefaultOutboundAction
        }

        $restored = Get-NetFirewallProfile -Profile Domain, Private, Public | Select-Object Name, DefaultOutboundAction
        Write-Log -Path $script:RevertLogPath -Level "INFO" -Message "Revert completed from backup $resolvedBackup. Outbound states: $($restored | ConvertTo-Json -Compress)"
        Write-Output "Revert complete from backup: $resolvedBackup"
    }
}

switch ($PSCmdlet.ParameterSetName) {
    "Apply" { Invoke-Apply }
    "Remove" { Invoke-Remove }
    default { throw "Specify -SqlServer for apply or -Remove for revert." }
}
