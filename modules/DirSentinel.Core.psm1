# DirSentinel.Core.psm1
# Core helpers: logging, config, backups, result objects.

$script:LogFile = $null

function Ensure-DSDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Initialize-DSLogging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogFolder
    )

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $script:LogFile = Join-Path $LogFolder ("dirsentinel-{0}.log" -f $timestamp)

    "[$(Get-Date -Format o)] [INFO] DirSentinel log started." |
        Out-File -FilePath $script:LogFile -Encoding UTF8

    return $script:LogFile
}

function Write-DSLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO","WARN","ERROR")]
        [string]$Level = "INFO"
    )

    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format o), $Level, $Message
    Write-Host $line

    if ($script:LogFile) {
        try {
            Add-Content -Path $script:LogFile -Value $line
        }
        catch {
            Write-Host "[WARN] Failed to write to log file: $($_.Exception.Message)"
        }
    }
}

function Get-DSConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "Config file not found: $Path"
    }

    $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
    $config = $raw | ConvertFrom-Json -ErrorAction Stop
    return $config
}

function New-DSResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Status,
        [string]$CurrentValue,
        [string]$DesiredValue,
        [string]$Details
    )

    [PSCustomObject]@{
        Category     = $Category
        Name         = $Name
        Status       = $Status
        CurrentValue = $CurrentValue
        DesiredValue = $DesiredValue
        Details      = $Details
        Timestamp    = (Get-Date)
    }
}

function Backup-DSRegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$BackupFolder
    )

    Ensure-DSDirectory -Path $BackupFolder

    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
    }
    catch {
        Write-DSLog "Backup skipped; registry value not found: $Path\$Name" "WARN"
        return
    }

    $backup = [PSCustomObject]@{
        Path      = $Path
        Name      = $Name
        Value     = $item.$Name
        ValueKind = (Get-ItemPropertyValue -Path $Path -Name $Name).GetType().Name
        Timestamp = Get-Date
    }

    $safePath = $Path -replace '[:\\\/ ]','_'
    $safeName = $Name -replace '[:\\\/ ]','_'
    $fileName = "regbackup_{0}_{1}_{2}.json" -f $safePath, $safeName, (Get-Date -Format "yyyyMMdd-HHmmss")
    $fullPath = Join-Path $BackupFolder $fileName

    $backup | ConvertTo-Json -Depth 5 | Out-File -FilePath $fullPath -Encoding UTF8
    Write-DSLog "Registry backup created: $fullPath" "INFO"
}

Export-ModuleMember -Function `
    Ensure-DSDirectory, `
    Initialize-DSLogging, `
    Write-DSLog, `
    Get-DSConfig, `
    New-DSResult, `
    Backup-DSRegistryValue
