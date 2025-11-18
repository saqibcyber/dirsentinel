# DirSentinel

![banner](./dirsentinel-banner.png)

**DirSentinel** is a PowerShell-based automation tool that applies a set of core Active Directory and Windows security hardening actions. It supports **audit mode** (check only) and **apply mode** (configurable changes with backups), uses a single JSON configuration file, and generates both logs and structured reports.

---

## Features

- Clean module-based structure (`Core`, `AD`, `Security`)
- Single JSON configuration file defining all checks and desired states
- Audit mode for validation without modification
- Apply mode for enforcing configuration
- Automatic creation of logs, reports, and registry/setting backups
- Avoids reapplying settings that are already compliant
- Covers several foundational AD security tasks:
  - Privileged group membership checks
  - Kerberos and NTLM registry policy verification
  - Basic Windows audit policy configuration
  - LLMNR and other insecure protocol settings

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

