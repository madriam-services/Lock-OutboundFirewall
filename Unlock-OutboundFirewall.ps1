#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$BackupPath,

    [Parameter()]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$lockScript = Join-Path -Path $PSScriptRoot -ChildPath "Lock-OutboundFirewall.ps1"
if (-not (Test-Path -LiteralPath $lockScript)) {
    throw "Lock script not found: $lockScript"
}

$invokeParams = @{
    Remove = $true
}
if (-not [string]::IsNullOrWhiteSpace($BackupPath)) {
    $invokeParams.BackupPath = $BackupPath
}
if ($Force) {
    $invokeParams.Force = $true
}
if ($WhatIfPreference) {
    $invokeParams.WhatIf = $true
}

& $lockScript @invokeParams
