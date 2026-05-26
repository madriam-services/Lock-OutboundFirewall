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

# SIG # Begin signature block
# MIIgMgYJKoZIhvcNAQcCoIIgIzCCIB8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCxZgiatl4Gs3GA
# ay1i1sUjeamyvBedn6MeA7z+/BR6LqCCGrowggOCMIIDCaADAgECAhBu3U8l5zF9
# OYFXMTTPwdygMAoGCCqGSM49BAMDMH8xCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVU
# ZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9u
# MTQwMgYDVQQDDCtTU0wuY29tIEVWIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
# dHkgRUNDMB4XDTE5MDMwNzE5Mzc0NVoXDTM0MDMwMzE5Mzc0NVowezELMAkGA1UE
# BhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQK
# DAhTU0wgQ29ycDE3MDUGA1UEAwwuU1NMLmNvbSBFViBDb2RlIFNpZ25pbmcgSW50
# ZXJtZWRpYXRlIENBIEVDQyBSMjB2MBAGByqGSM49AgEGBSuBBAAiA2IABDrQ4dqT
# 4rxW0Uk0uIEsNETSGyWTorL/T7TkHzPBJvtMekCG2uzlVG/okXNTkCmKbgXR7rcO
# uDsgCehjjKBRoBT7FuMyK45CpEFAe1DqopbneXiDXLAZzL8OI6Cz5RSpsaOCAUww
# ggFIMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUW8pe5d7SgarNqC1k
# UbbZcpuX5k8wewYIKwYBBQUHAQEEbzBtMEkGCCsGAQUFBzAChj1odHRwOi8vd3d3
# LnNzbC5jb20vcmVwb3NpdG9yeS9TU0xjb20tUm9vdENBLUVWLUVDQy0zODQtUjEu
# Y3J0MCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcHMuc3NsLmNvbTARBgNVHSAECjAI
# MAYGBFUdIAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwPQYDVR0fBDYwNDAyoDCgLoYs
# aHR0cDovL2NybHMuc3NsLmNvbS9zc2wuY29tLUVWZWNjLVJvb3RDQS5jcmwwHQYD
# VR0OBBYEFAGJlLn+tDNd8PH6hfkkRoSjV2leMA4GA1UdDwEB/wQEAwIBhjAKBggq
# hkjOPQQDAwNnADBkAjBKW+qAn7o2ks+MMe3spZnuMie8wxfrh49XUDAFv3WV9zz5
# PxlSgzQg4RFW7jk+t+4CMAK1uNn4eBJHwcBF/xX2oGa7Q+JPQw5Yd5ekolU0JIRa
# VhnPplUgG9kQmlMA+4lecDCCA/YwggN8oAMCAQICEFNH/mVzWPA4gsMaHHg2s6cw
# CgYIKoZIzj0EAwMwezELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYD
# VQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDE3MDUGA1UEAwwuU1NMLmNv
# bSBFViBDb2RlIFNpZ25pbmcgSW50ZXJtZWRpYXRlIENBIEVDQyBSMjAeFw0yMzA5
# MTkxNzI1MDFaFw0yNjA5MTgxNzI1MDFaMIG4MQswCQYDVQQGEwJDQTEQMA4GA1UE
# CAwHT250YXJpbzEPMA0GA1UEBwwGT3R0YXdhMR4wHAYDVQQKDBVNYWRyaWFtIFNl
# cnZpY2VzIEluYy4xEjAQBgNVBAUTCTExMjYxMzYtMzEeMBwGA1UEAwwVTWFkcmlh
# bSBTZXJ2aWNlcyBJbmMuMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjET
# MBEGCysGAQQBgjc8AgEDEwJDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABJKGZhyL
# Uf+qUvYOJp5klIo5Dv2D517rhg2oadMcWY7YQvObKJ+M69XUWuZISbvxlZLtzcs9
# lw2oXpEnFrJZDRpRextHq+DVvhdiiJOZOfhPjaL/2w3dqdUe1qLe0vQwmqOCAYUw
# ggGBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUAYmUuf60M13w8fqF+SRGhKNX
# aV4wWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vY2VydC5zc2wu
# Y29tL1NTTGNvbS1TdWJDQS1FVi1jb2RlU2lnbmluZy1FQ0MtMzg0LVIyLmNlcjBf
# BgNVHSAEWDBWMAcGBWeBDAEDMA0GCyqEaAGG9ncCBQEHMDwGDCsGAQQBgqkwAQMD
# AjAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5zc2wuY29tL3JlcG9zaXRvcnkw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwTwYDVR0fBEgwRjBEoEKgQIY+aHR0cDovL2Ny
# bHMuc3NsLmNvbS9TU0xjb20tU3ViQ0EtRVYtY29kZVNpZ25pbmctRUNDLTM4NC1S
# Mi5jcmwwHQYDVR0OBBYEFHiwVSjHMXieTj9vmEoTPpFIvJ4IMA4GA1UdDwEB/wQE
# AwIHgDAKBggqhkjOPQQDAwNoADBlAjEAmNwghnB6MJvDuhZn/dihQfY4xDkl+2x+
# YvWt3Kv9mavaJw+lJ6D0t4NAuHluEq+TAjAtzldhyNj3KiBCvLNZzRPfPsC3BEI0
# kwY439LzmEJjp0ZCUcYfFa/pNyxUeaF2DJ0wggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMr
# V7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8
# dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7M
# rxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZ
# ZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFO
# nHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+n
# igNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeIt
# K/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1
# zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk
# 8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsW
# eupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAk
# prxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWL
# pQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgj
# g8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3Q
# YIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5
# bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUG
# tMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNE
# suEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6U
# Arb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG
# 0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWV
# FjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5
# t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjs
# arfNZzGCBM4wggTKAgEBMIGPMHsxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhh
# czEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxNzA1BgNVBAMM
# LlNTTC5jb20gRVYgQ29kZSBTaWduaW5nIEludGVybWVkaWF0ZSBDQSBFQ0MgUjIC
# EFNH/mVzWPA4gsMaHHg2s6cwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIB
# DDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgWFXmJ/rndncE
# FUa8DByclrNZK7CZrlryXguyAFa/RQIwCwYHKoZIzj0CAQUABGYwZAIwJ5EQQM98
# PpCH8oWjBKkoJG1geRWEYA9jwV5XY51hpiXY8axRplcPhNcwPgFTa7H0AjAeq0be
# K+TJTAik79h8A8diREadC63LF7toHZlnt0MRKqGyoQ9OXuqv0BHW49UJCCyhggMm
# MIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUG
# A1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQg
# RzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAKgO8YS43x
# BYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwNTI2MTgwNDIyWjAvBgkqhkiG9w0BCQQx
# IgQgcrBIXoNHROtcZchhwQM2QDTtz68vgpfw6LJnDLDpw4QwDQYJKoZIhvcNAQEB
# BQAEggIAp9PpFji7tjMMR3jFudCHsos3BMTzBGr2FRXGBi6OGU7z2fv4ith3takA
# rs6EDfAQymtuGRHFwtAoqHcsdWiv0Nf+0w/1PUqDRh2XPhNIeVN5sFaOCXGO0YaC
# b2YO17eNcaXOpIcs83ShSW01IxEEkI+GkTUz8rES7w2y0B+CJy3UEB+1rdvsKZPj
# 5sZxDFqKe/21kwjC1fenkTLvBnHn5Q0c6XN5zm57zo/d3soHmHcSfrudFcHPB3Cz
# unMYHyGFWWWEGCglGD17GK0yQY9x4yPIN9YMdG0CesHoIrd7aVEJDcpmjMVm1fPG
# yqMTH0yfRzxQB0qOHK2YvGmmC61FR6s7hkHb2o7Ao+4P5BUJWuoNHzEymZtOOvnC
# +iWP7As/rxXdroBLGQ+qRPdo8Vn7quCl/uDW0lwXrdzHJjGDPu0SZbR2QU2OptyJ
# OW8Iqe3bUnHul8qta7XeBNl4hY55t0R1epPkIZWdKBfrRUCU9khOsQUe5sLoJHK4
# wk1vfMQZ9C7WTjkhauLtRXUZ5uo2pgk/LXS12l5chTAsyvQsAgETz4sYEYFOs3QA
# LRLTd7ysfzDcn5TjlZ/1rEgoBtNPzy4hJc/Vd9vOUxdgiGtgQ/+PocPTXbrufHu6
# mhTJW7xXIcF2h2yA5kfFvaCcn/iK6RUe7WnCQ9whiTEaRHIEFww=
# SIG # End signature block
