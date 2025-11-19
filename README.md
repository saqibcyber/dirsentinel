# dirsentinel

![banner](./banner.png)

**DirSentinel** is a purpose-built PowerShell toolkit that streamlines the hardening of domain-joined systems in Active Directory environments. It automatically evaluates machines against **MSFT and CIS baselines**, detects common vulnerabilties, and produces structured JSON reports with clear, actionable remediation guidance.

## Features
- Automated discovery of AD and Windows security misconfigurations  
- Recommendations mapped to CIS Baselines and Microsoft hardening guidance  
- Enforcement mode with safe rollbacks and configuration backups  
- JSON reporting and log output for audit trails and trend tracking  
- Idempotent execution—no unnecessary re-applies on compliant settings  

---

## Requirements

- Windows Server or Windows client with administrative privileges  
- PowerShell 5.1 or PowerShell 7+  
- RSAT **ActiveDirectory** module for group membership checks  
- Ability to modify local registry and local audit policy (for Apply mode)

---

## Usage

### Audit Mode (default)

```powershell
.\Invoke-DirSentinel.ps1
````

or explicitly:

```powershell
.\Invoke-DirSentinel.ps1 -Mode Audit
```

### Apply Mode (perform changes)

```powershell
.\Invoke-DirSentinel.ps1 -Mode Apply
```

### Using a custom config file

```powershell
.\Invoke-DirSentinel.ps1 -ConfigPath .\Config\mycustom.json
```

### Custom report output path

```powershell
.\Invoke-DirSentinel.ps1 -ReportPath .\Reports\custom-report.json
```

---

## Configuration

DirSentinel uses a single JSON file to define all checks and their parameters.

Example path:

```
Config\dirsentinel.config.json
```

Configuration sections include:

* `PrivilegedGroups`
* `Kerberos`
* `NTLM`
* `Logging`
* `InsecureProtocols`

Each section can be enabled or disabled individually.

---

## Outputs

### Logs

Plain-text log files are written to:

```
Logs\dirsentinel-<timestamp>.log
```

Logs include timestamps, statuses, and any errors encountered.

### Backups

Registry values and settings are backed up before modification:

```
Backups\regbackup_<setting>_<timestamp>.json
```

### Reports

A structured JSON report is generated after every run:

```
Reports\dirsentinel-report-<timestamp>.json
```

The report includes:

* Category (Kerberos, NTLM, etc.)
* Current value
* Desired value
* Status (`OK`, `Changed`, `NotCompliant`, `Warning`, `Failed`)
* Details and timestamps

