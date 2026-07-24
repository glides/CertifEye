# AD CS junior-admin runbook

This runbook is for a domain administrator or PKI operator who is running the
collector for the first time. The collector is read-only, but it produces raw
local files before scrubbing.

## Before starting

- Use a domain-joined Windows PowerShell 5.1+ or PowerShell 7 host.
- Confirm CA database/config read access and AD/LDAP read access.
- Use a dedicated local work folder with restricted permissions.
- Prepare a strong local salt and never paste it into chat or upload it.

## Collect

```powershell
.\Invoke-ADCSAuditPipeline.ps1 -WorkDir C:\Temp\ADCS-Audit
```

Choose the required stages or `All`. Review the prompts for CA access, alternate
DC-read credentials, web enrollment probing, and the year window. Do not use a
privileged credential for an optional behavioral test unless your change-control
process permits it; a host-admin/IIS read is preferred.

## Analyze scrubbed data

```powershell
.\Invoke-ADCSAuditPipeline.ps1 `
  -Stage Analyze -NonInteractive `
  -InputDir C:\Temp\ADCS-Audit\Scrubbed `
  -OutputDir C:\Temp\ADCS-Audit\Output `
  -WorkingDir C:\Temp\ADCS-Audit\Working
```

Review the PDF, HTML, findings CSV, graph, coverage matrix, and upload manifest.

## Upload gate

Upload only reviewed scrubbed CSVs and the safe manifest. Never upload raw CSVs,
the token map, salt, private manifest, local working results, detailed leak
reports, or files marked `DO_NOT_UPLOAD`.
