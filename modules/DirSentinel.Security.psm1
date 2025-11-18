# DirSentinel.Security.psm1
# Registry-based settings (Kerberos, NTLM, LLMNR) and basic audit policy.

function Test-DSRegistrySetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$ExpectedValue
    )

    try {
        $current = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
        return [PSCustomObject]@{
            Exists       = $true
            CurrentValue = $current
            Compliant    = ($current -eq $ExpectedValue)
        }
    }
    catch {
        return [PSCustomObject]@{
            Exists       = $false
            CurrentValue = $null
            Compliant    = $false
        }
    }
}

function Set-DSRegistrySetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Value,
        [ValidateSet("String","DWord")]
        [string]$Type = "DWord",
        [Parameter(Mandatory)][string]$BackupFolder
    )

    # Backup before change
    Backup-DSRegistryValue -Path $Path -Name $Name -BackupFolder $BackupFolder

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }

    if ($Type -eq "DWord") {
        New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
    }
    else {
        New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
    }

    Write-DSLog "Registry setting updated: $Path\$Name = $Value ($Type)" "INFO"
}

function Invoke-DSKerberosSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config,

        [Parameter(Mandatory)]
        [ValidateSet("Audit","Apply")]
        [string]$Mode,

        [Parameter(Mandatory)]
        [string]$BackupFolder
    )

    $results = @()

    foreach ($setting in $Config.Settings) {
        $name     = $setting.Name
        $path     = $setting.RegistryPath
        $valueName= $setting.ValueName
        $expected = [int]$setting.ExpectedDword

        $test = Test-DSRegistrySetting -Path $path -Name $valueName -ExpectedValue $expected

        if ($test.Compliant) {
            $results += New-DSResult -Category "Kerberos" -Name $name `
                -Status "OK" `
                -CurrentValue $test.CurrentValue `
                -DesiredValue $expected `
                -Details "Already compliant."
        }
        else {
            if ($Mode -eq "Apply") {
                try {
                    Set-DSRegistrySetting -Path $path -Name $valueName -Value $expected `
                        -Type "DWord" -BackupFolder $BackupFolder

                    $results += New-DSResult -Category "Kerberos" -Name $name `
                        -Status "Changed" `
                        -CurrentValue $test.CurrentValue `
                        -DesiredValue $expected `
                        -Details "Updated registry value."
                }
                catch {
                    $results += New-DSResult -Category "Kerberos" -Name $name `
                        -Status "Failed" `
                        -CurrentValue $test.CurrentValue `
                        -DesiredValue $expected `
                        -Details $_.Exception.Message

                    Write-DSLog "Failed to set Kerberos setting '$name': $($_.Exception.Message)" "ERROR"
                }
            }
            else {
                $results += New-DSResult -Category "Kerberos" -Name $name `
                    -Status "NotCompliant" `
                    -CurrentValue $test.CurrentValue `
                    -DesiredValue $expected `
                    -Details "Would set to $expected in Apply mode."
            }
        }
    }

    return $results
}

function Invoke-DSNtlmSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config,

        [Parameter(Mandatory)]
        [ValidateSet("Audit","Apply")]
        [string]$Mode,

        [Parameter(Mandatory)]
        [string]$BackupFolder
    )

    $results = @()

    foreach ($setting in $Config.Settings) {
        $name      = $setting.Name
        $path      = $setting.RegistryPath
        $valueName = $setting.ValueName
        $expected  = [int]$setting.ExpectedDword

        $test = Test-DSRegistrySetting -Path $path -Name $valueName -ExpectedValue $expected

        if ($test.Compliant) {
            $results += New-DSResult -Category "NTLM" -Name $name `
                -Status "OK" `
                -CurrentValue $test.CurrentValue `
                -DesiredValue $expected `
                -Details "Already compliant."
        }
        else {
            if ($Mode -eq "Apply") {
                try {
                    Set-DSRegistrySetting -Path $path -Name $valueName -Value $expected `
                        -Type "DWord" -BackupFolder $BackupFolder

                    $results += New-DSResult -Category "NTLM" -Name $name `
                        -Status "Changed" `
                        -CurrentValue $test.CurrentValue `
                        -DesiredValue $expected `
                        -Details "Updated registry value."
                }
                catch {
                    $results += New-DSResult -Category "NTLM" -Name $name `
                        -Status "Failed" `
                        -CurrentValue $test.CurrentValue `
                        -DesiredValue $expected `
                        -Details $_.Exception.Message

                    Write-DSLog "Failed to set NTLM setting '$name': $($_.Exception.Message)" "ERROR"
                }
            }
            else {
                $results += New-DSResult -Category "NTLM" -Name $name `
                    -Status "NotCompliant" `
                    -CurrentValue $test.CurrentValue `
                    -DesiredValue $expected `
                    -Details "Would set to $expected in Apply mode."
            }
        }
    }

    return $results
}

function Invoke-DSEventAuditConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config,

        [Parameter(Mandatory)]
        [ValidateSet("Audit","Apply")]
        [string]$Mode
    )

    $results = @()

    foreach ($audit in $Config.AuditSubcategories) {
        $name = $audit.Name
        $wantSuccess = [bool]$audit.IncludeSuccess
        $wantFailure = [bool]$audit.IncludeFailure

        try {
            $raw = & auditpol.exe /get /subcategory:"$name" 2>$null
            $rawText = $raw -join "`n"

            $hasSuccess = $rawText -match "Success"
            $hasFailure = $rawText -match "Failure"

            $currentState = if ($hasSuccess -and $hasFailure) {
                "Success and Failure"
            } elseif ($hasSuccess) {
                "Success only"
            } elseif ($hasFailure) {
                "Failure only"
            } else {
                "No auditing"
            }

            $desiredState = switch ("x") {
                { $wantSuccess -and $wantFailure } { "Success and Failure"; break }
                { $wantSuccess -and -not $wantFailure } { "Success only"; break }
                { -not $wantSuccess -and $wantFailure } { "Failure only"; break }
                default { "No auditing" }
            }

            $compliant = ($currentState -eq $desiredState)

            if ($compliant) {
                $results += New-DSResult -Category "Logging" -Name $name `
                    -Status "OK" `
                    -CurrentValue $currentState `
                    -DesiredValue $desiredState `
                    -Details "Already compliant."
            }
            else {
                if ($Mode -eq "Apply") {
                    $successOpt = if ($wantSuccess) { "enable" } else { "disable" }
                    $failureOpt = if ($wantFailure) { "enable" } else { "disable" }

                    & auditpol.exe /set /subcategory:"$name" /success:$successOpt /failure:$failureOpt | Out-Null

                    $results += New-DSResult -Category "Logging" -Name $name `
                        -Status "Changed" `
                        -CurrentValue $currentState `
                        -DesiredValue $desiredState `
                        -Details "Updated audit policy."
                }
                else {
                    $results += New-DSResult -Category "Logging" -Name $name `
                        -Status "NotCompliant" `
                        -CurrentValue $currentState `
                        -DesiredValue $desiredState `
                        -Details "Would set to '$desiredState' in Apply mode."
                }
            }
        }
        catch {
            $results += New-DSResult -Category "Logging" -Name $name `
                -Status "Failed" `
                -CurrentValue "" `
                -DesiredValue "" `
                -Details $_.Exception.Message

            Write-DSLog "Failed to evaluate audit policy for '$name': $($_.Exception.Message)" "ERROR"
        }
    }

    return $results
}

function Invoke-DSInsecureProtocols {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config,

        [Parameter(Mandatory)]
        [ValidateSet("Audit","Apply")]
        [string]$Mode,

        [Parameter(Mandatory)]
        [string]$BackupFolder
    )

    $results = @()

    # Example: LLMNR disable via policy registry key
    if ($Config.Llmnr.Disable -eq $true) {
        $name      = "Disable LLMNR"
        $path      = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
        $valueName = "EnableMulticast"
        $expected  = 0

        $test = Test-DSRegistrySetting -Path $path -Name $valueName -ExpectedValue $expected

        if ($test.Compliant) {
            $results += New-DSResult -Category "InsecureProtocols" -Name $name `
                -Status "OK" `
                -CurrentValue $test.CurrentValue `
                -DesiredValue $expected `
                -Details "LLMNR already disabled by policy."
        }
        else {
            if ($Mode -eq "Apply") {
                try {
                    Set-DSRegistrySetting -Path $path -Name $valueName -Value $expected `
                        -Type "DWord" -BackupFolder $BackupFolder

                    $results += New-DSResult -Category "InsecureProtocols" -Name $name `
                        -Status "Changed" `
                        -CurrentValue $test.CurrentValue `
                        -DesiredValue $expected `
                        -Details "Set EnableMulticast=0 to disable LLMNR."
                }
                catch {
                    $results += New-DSResult -Category "InsecureProtocols" -Name $name `
                        -Status "Failed" `
                        -CurrentValue $test.CurrentValue `
                        -DesiredValue $expected `
                        -Details $_.Exception.Message

                    Write-DSLog "Failed to disable LLMNR: $($_.Exception.Message)" "ERROR"
                }
            }
            else {
                $results += New-DSResult -Category "InsecureProtocols" -Name $name `
                    -Status "NotCompliant" `
                    -CurrentValue $test.CurrentValue `
                    -DesiredValue $expected `
                    -Details "Would set EnableMulticast=0 in Apply mode."
            }
        }
    }

    return $results
}

Export-ModuleMember -Function `
    Invoke-DSKerberosSettings, `
    Invoke-DSNtlmSettings, `
    Invoke-DSEventAuditConfig, `
    Invoke-DSInsecureProtocols
