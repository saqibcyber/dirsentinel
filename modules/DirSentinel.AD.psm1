# DirSentinel.AD.psm1
# AD-related checks (privileged groups).
# Requires RSAT ActiveDirectory module on the machine.

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "[WARN] ActiveDirectory module not loaded. AD checks may fail."
}

function Invoke-DSPrivilegedGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config,

        [Parameter(Mandatory)]
        [ValidateSet("Audit","Apply")]
        [string]$Mode
    )

    <#
        NOTE:
        This check is read-only in both Audit and Apply modes.
        It reports unexpected privileged group members but does not modify membership.
        Automatic cleanup of privileged groups is deliberately left to human review.
    #>

    $results = @()

    foreach ($groupCfg in $Config.Groups) {
        $groupName      = $groupCfg.Name
        $approved       = @($groupCfg.ApprovedMembers)
        $displayName    = if ($groupCfg.DisplayName) { $groupCfg.DisplayName } else { $groupName }

        try {
            $members = Get-ADGroupMember -Identity $groupName -Recursive |
                       Select-Object -ExpandProperty SamAccountName

            $unexpected = $members | Where-Object { $_ -notin $approved }

            if ($unexpected.Count -eq 0) {
                $results += New-DSResult -Category "PrivilegedGroups" -Name $displayName `
                    -Status "OK" `
                    -CurrentValue ($members -join ", ") `
                    -DesiredValue ("Approved: " + ($approved -join ", ")) `
                    -Details "All members are approved."
            }
            else {
                $details = "Unexpected members: " + ($unexpected -join ", ")
                $results += New-DSResult -Category "PrivilegedGroups" -Name $displayName `
                    -Status "Warning" `
                    -CurrentValue ($members -join ", ") `
                    -DesiredValue ("Approved: " + ($approved -join ", ")) `
                    -Details $details

                Write-DSLog "Privileged group '$groupName' has unexpected members: $($unexpected -join ', ')" "WARN"
            }
        }
        catch {
            $results += New-DSResult -Category "PrivilegedGroups" -Name $displayName `
                -Status "Failed" `
                -CurrentValue "" `
                -DesiredValue ("Approved: " + ($approved -join ", ")) `
                -Details $_.Exception.Message

            Write-DSLog "Error checking group '$groupName': $($_.Exception.Message)" "ERROR"
        }
    }

    return $results
}

Export-ModuleMember -Function Invoke-DSPrivilegedGroups
