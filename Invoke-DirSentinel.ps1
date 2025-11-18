<#
.SYNOPSIS
    DirSentinel – basic AD hardening helper.

.NOTES
    Run in PowerShell with appropriate privileges (often Domain Admin / local admin).
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = ".\config\dirsentinel.config.json",

    [ValidateSet("Audit","Apply")]
    [string]$Mode = "Audit",

    [string]$ReportPath
)

$ErrorActionPreference = "Stop"

# region: Resolve paths and import modules
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $ReportPath) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $ReportPath = Join-Path $ScriptRoot ("Reports\dirsentinel-report-{0}.json" -f $timestamp)
}

$modulesPath = Join-Path $ScriptRoot "modules"
Import-Module (Join-Path $modulesPath "DirSentinel.Core.psm1") -Force
Import-Module (Join-Path $modulesPath "DirSentinel.AD.psm1") -Force
Import-Module (Join-Path $modulesPath "DirSentinel.Security.psm1") -Force
# endregion

# region: Initialize folders and logging
$logsFolder    = Join-Path $ScriptRoot "logs"
$backupsFolder = Join-Path $ScriptRoot "backups"
$reportsFolder = Join-Path $ScriptRoot "reports"

Ensure-DSDirectory -Path $logsFolder
Ensure-DSDirectory -Path $backupsFolder
Ensure-DSDirectory -Path $reportsFolder

$logFile = Initialize-DSLogging -LogFolder $logsFolder
Write-DSLog "DirSentinel starting in mode: $Mode" "INFO"
Write-DSLog "Using config file: $ConfigPath" "INFO"
# endregion

# region: Load configuration
try {
    $config = Get-DSConfig -Path $ConfigPath
}
catch {
    Write-DSLog "Failed to load configuration: $($_.Exception.Message)" "ERROR"
    throw
}
# endregion

$results = @()

# region: Privileged group membership
if ($config.Checks.PrivilegedGroups.Enabled -eq $true) {
    Write-DSLog "Running privileged group membership check..." "INFO"
    try {
        $results += Invoke-DSPrivilegedGroups `
            -Config $config.Checks.PrivilegedGroups `
            -Mode $Mode
    }
    catch {
        Write-DSLog "Error in privileged group check: $($_.Exception.Message)" "ERROR"
        $results += New-DSResult -Category "PrivilegedGroups" -Name "PrivilegedGroups" `
            -Status "Failed" -CurrentValue "" -DesiredValue "" `
            -Details $_.Exception.Message
    }
}
# endregion

# region: Kerberos registry settings
if ($config.Checks.Kerberos.Enabled -eq $true) {
    Write-DSLog "Running Kerberos settings check..." "INFO"
    try {
        $results += Invoke-DSKerberosSettings `
            -Config $config.Checks.Kerberos `
            -Mode $Mode `
            -BackupFolder $backupsFolder
    }
    catch {
        Write-DSLog "Error in Kerberos check: $($_.Exception.Message)" "ERROR"
        $results += New-DSResult -Category "Kerberos" -Name "Kerberos" `
            -Status "Failed" -CurrentValue "" -DesiredValue "" `
            -Details $_.Exception.Message
    }
}
# endregion

# region: NTLM registry settings
if ($config.Checks.NTLM.Enabled -eq $true) {
    Write-DSLog "Running NTLM settings check..." "INFO"
    try {
        $results += Invoke-DSNtlmSettings `
            -Config $config.Checks.NTLM `
            -Mode $Mode `
            -BackupFolder $backupsFolder
    }
    catch {
        Write-DSLog "Error in NTLM check: $($_.Exception.Message)" "ERROR"
        $results += New-DSResult -Category "NTLM" -Name "NTLM" `
            -Status "Failed" -CurrentValue "" -DesiredValue "" `
            -Details $_.Exception.Message
    }
}
# endregion

# region: Basic audit policy / logging
if ($config.Checks.Logging.Enabled -eq $true) {
    Write-DSLog "Running logging/audit policy check..." "INFO"
    try {
        $results += Invoke-DSEventAuditConfig `
            -Config $config.Checks.Logging `
            -Mode $Mode
    }
    catch {
        Write-DSLog "Error in logging check: $($_.Exception.Message)" "ERROR"
        $results += New-DSResult -Category "Logging" -Name "Logging" `
            -Status "Failed" -CurrentValue "" -DesiredValue "" `
            -Details $_.Exception.Message
    }
}
# endregion

# region: LLMNR / insecure protocol settings
if ($config.Checks.InsecureProtocols.Enabled -eq $true) {
    Write-DSLog "Running insecure protocols check..." "INFO"
    try {
        $results += Invoke-DSInsecureProtocols `
            -Config $config.Checks.InsecureProtocols `
            -Mode $Mode `
            -BackupFolder $backupsFolder
    }
    catch {
        Write-DSLog "Error in insecure protocols check: $($_.Exception.Message)" "ERROR"
        $results += New-DSResult -Category "InsecureProtocols" -Name "InsecureProtocols" `
            -Status "Failed" -CurrentValue "" -DesiredValue "" `
            -Details $_.Exception.Message
    }
}
# endregion

# region: Save report
try {
    $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-DSLog "Report written to $ReportPath" "INFO"
}
catch {
    Write-DSLog "Failed to write report: $($_.Exception.Message)" "ERROR"
}
# endregion

Write-Host ""
Write-Host "DirSentinel completed. Mode: $Mode"
Write-Host "Log file   : $logFile"
Write-Host "Report file: $ReportPath"
