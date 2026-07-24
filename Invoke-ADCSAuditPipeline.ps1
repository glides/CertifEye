<#
.SYNOPSIS
  Canonical AD CS ESC-audit collector, scrubber, and analysis entry point.

.NOTES
  v2 (collector accuracy update) - ESC5 PKI-object ACL export now records the ACE's
  control-access-right GUID and resolves it, so an ExtendedRight is named precisely
  (Enroll / AutoEnroll / All-ExtendedRights / a specific GUID) instead of the generic
  "ExtendedRight" token. New columns on adcs_pki_object_acls: ObjectTypeGuid,
  ResolvedRight, RightCategory, IsEnrollRight. ESC5Candidate is now scoped to dangerous
  CONTROL rights by a non-default principal (Enroll/AutoEnroll extended rights are
  recorded as enrolment-scope amplifiers via IsEnrollRight, not mis-flagged as ESC5).
  Existing columns are unchanged, so older analysis keeps working.

  v2 also hardens two low-confidence stages:
   * DC strong-mapping (KB5014754): the read order is RemoteRegistry -> WinRM ->
     WMI/StdRegProv -> SYSVOL/GPP. Per-method failures are no longer swallowed --
     each is surfaced (console + new ReadDetail column) and a per-stage summary reports
     how many DCs were read live vs fell back to the GPO-intended SYSVOL/GPP value vs
     were unreadable, so a silent all-fallback run is now obvious.
   * ESC8 EPA: previously EPA was only read when the HTTPS header probe had already
     flagged NTLM -- so a missed NTLM offer left EpaTokenChecking=Unknown. Now EPA is
     read for EVERY reachable HTTPS endpoint (the IIS config read is authoritative when
     the operator has local admin on the web host, e.g. the issuing-CA admin on its own
     certsrv), WWW-Authenticate is also parsed on non-401 responses, failures are
     surfaced with reasons, and a new EpaDetail column records what was read. The opt-in
     behavioural SSPI probe remains an experimental cross-check; the deterministic IIS
     read is preferred when host admin is available.
   * False-positive control (ESC4/ESC5/ESC7): the "default/expected privileged
     principal" tests are now SID-based (well-known SIDs + domain-relative RIDs for
     Domain/Enterprise/Schema Admins, Administrators, Cert Publishers, Domain
     Controllers, Key Admins, SYSTEM, Enterprise DCs) with the old English-name list
     kept only as a fallback -- so renamed or non-English privileged groups are still
     recognised and not mis-flagged as ESC4/ESC5/ESC7 candidates.
   * CA-own-host recognition (ESC5): each EnrollmentServiceCA object is mapped to its
     host's computer-account SID, and that account holding control over its OWN CA
     object is recognised (new IsCAHostAccount column) and excluded from ESC5Candidate
     -- matched by SID and scoped to that object, so the same machine account on NTAuth
     / the templates container / other PKI objects is still flagged.
   * Alternate DC-read credential: the DC strong-mapping stage now prompts for an
     optional credential (e.g. a Domain Admin different from the CA logon). When given,
     the credential-aware transports are tried FIRST, so a non-DA CA logon can still
     obtain confirmed LIVE reads instead of falling back to the SYSVOL/GPP intended value.
     IMPORTANT: the WMI/CIM read is now forced onto the DCOM (RPC) protocol via
     New-CimSessionOption -Protocol Dcom -- New-CimSession/Invoke-CimMethod default to
     WSMan/WinRM, so previously the "WMI" method rode the same WinRM channel and failed
     identically when WinRM was blocked. DCOM (TCP 135 + dynamic, or via 445) is an
     independent transport, so with a DA credential it succeeds even on DCs where WinRM
     is firewalled. Order with a credential: WMI/DCOM(cred) -> WinRM(cred) -> RemoteRegistry
     (current context; OpenRemoteBaseKey cannot take a credential).

.DESCRIPTION
  Consolidates six separate scripts into a single, prompt-driven tool:

    1. Export issued certificates (with SAN/EKU) from a CA database  (needs CA access)
    2. Trim the issued-cert export to the last N years
    3. Export certificate template inventory + ESC flags            (needs AD/LDAP)
    3b. Export CA/PKI/DC/web security posture                       (needs CA + AD/LDAP)
        -- ESC7 (Manage CA/Certificates), ESC5 (PKI object control),
           ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2), ESC11 (InterfaceFlags),
           ESC8 (web-enrollment metadata + optional active NTLM/HTTP probe),
           and per-DC KB5014754 StrongCertificateBindingEnforcement.
    4. Build the identity token map + high-value target file         (needs AD/LDAP)
    5. Scrub a CSV with the token map (with integrated leak hardening)
    6. Leak-harden an already-scrubbed CSV
    7. Run the whole pipeline end to end

  Nothing is hard-coded. Every path, the salt, the year window, the CA
  config string, etc. are prompted for (with sensible defaults), or can be
  supplied up front via parameters.

  KEY CONSISTENCY GUARANTEE
  -------------------------
  The token map build, the scrubber, and the leak-hardening pass all share
  ONE copy of every cryptographic / normalization helper and ONE salt and
  ONE HMAC length for the whole session. That is what makes a given real
  value always collapse to the same token, no matter which stage or which
  file first encounters it. (In the original separate scripts the salt was
  retyped per script and the hardening pass used a different HMAC length and
  a weaker normalizer, so the same value could be tokenized two different
  ways -- the source of the residual leaks.)

  SECURITY
  --------
    * The token map (adcs_token_map_DO_NOT_UPLOAD.csv) is secret. Never upload it.
    * Upload only the *_scrubbed.csv files and high_value_targets_scrubbed.csv.
    * Keep the salt secret and reuse the SAME salt for every run that must
      correlate (otherwise tokens will not line up across files/runs).

.PARAMETER WorkDir
  Base folder for inputs/outputs. Prompted if omitted. Default: current folder.

.PARAMETER Salt
  HMAC salt. If omitted you are prompted securely when a stage needs it.

.PARAMETER HmacLength
  Number of hex characters in generated tokens. Must be the same value used
  when the token map was built. Default 16.

.PARAMETER Stage
  Run a legacy stage with its original prompts: Export, Trim, Templates,
  CASecurity, TokenMap, Scrub, Harden, or All. Use Analyze for the explicit-path
  scrubbed-data report pipeline. Omit for the interactive menu.

.PARAMETER InputDir
  Explicit scrubbed input folder used by Stage Analyze.

.PARAMETER OutputDir
  Explicit report/output folder used by Stage Analyze.

.PARAMETER WorkingDir
  Explicit analyzer working folder used by Stage Analyze.

.PARAMETER YearsBack
  Default historical issuance window passed to the legacy trim stage.

.PARAMETER NonInteractive
  Permitted for Stage Analyze. Legacy collection stages fail closed rather than
  guessing CA, AD, or credential-sensitive collection choices.

.EXAMPLE
  .\Invoke-ADCSAuditPipeline.ps1
  # Fully interactive menu.

.EXAMPLE
  .\Invoke-ADCSAuditPipeline.ps1 -WorkDir C:\Temp\ADCS-Audit -Stage All
  # Runs every stage, prompting only for the bits it still needs.

.NOTES
  Run stages 1, 3, 3b and 4 from a domain-joined machine with the right rights
  (stage 3b also needs certutil access to the CA for ESC7 / the ESC6 flag).
  Stages 2, 5 and 6 only need the CSVs, the token map and the salt.
#>

[CmdletBinding()]
param(
    [string]$WorkDir,
    [string]$InputDir,
    [string]$OutputDir,
    [string]$WorkingDir,
    [string]$Salt,
    [string]$SaltFile,
    [string]$SaltFromEnv,
    [ValidateRange(16,64)][int]$HmacLength = 24,
    [int]$YearsBack = 3,

    [ValidateSet('Interactive','Plan','Collect','Analyze','Validate','Doctor')]
    [string]$Action,

    [ValidateSet('Export', 'Trim', 'Templates', 'CASecurity', 'TokenMap', 'Scrub', 'Harden', 'Analyze', 'All')]
    [string]$Stage,
    [switch]$NonInteractive,
    [switch]$SkipQa,
    [switch]$PlanOnly,
    [switch]$Version,
    [switch]$PassThru,
    [string]$SafeBundlePath,
    # Explicit command-line opt-in for an entirely local static-analysis run.
    # This is deliberately not exposed through the interactive `set` command.
    [switch]$NoTokenization,
    [switch]$Force
)

# We intentionally do NOT enable Set-StrictMode globally: stage 1 talks to the
# CA via COM and stages 3/4 via ADSI, and that code was written without strict
# mode. Forcing strict mode over all of it could surface spurious failures in
# the COM/LDAP paths. The merged helpers below are written to be strict-safe
# regardless.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\AssessmentInteractive.ps1')
$env:ADCS_AUDIT_YEARS_BACK = $YearsBack.ToString()

# Session-wide values shared by every stage. Set by the driver / ensured lazily.
$script:Salt             = $Salt
$script:HmacLength       = $HmacLength
$script:NoTokenization   = [bool]$NoTokenization
$script:TokenByNorm      = @{}    # normalized-value -> token, populated when a token map is loaded
$script:ValueByToken     = @{}
$script:TokenMapCacheKey = $null  # "<fullpath>|<lastwrite>" of the map currently in TokenByNorm

# Explicit-path analysis helpers. These live in this file so the collector and
# analyzer share one public entry point; no second source file or self-loading
# script block is required.
function Resolve-PipelinePath {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    return [System.IO.Path]::GetFullPath($Value)
}

function Find-PythonRuntime {
    foreach ($candidate in @('python', 'py')) {
        try {
            & $candidate --version *> $null
            if ($LASTEXITCODE -eq 0) { return $candidate }
        }
        catch { }
    }
    throw 'Python was not found. Install Python 3.9+ or add it to PATH before running AD CS analysis.'
}

function Write-SafeUploadManifest {
    param([Parameter(Mandatory)][string]$Root)
    $scrubbed = Join-Path $Root 'Scrubbed'
    New-Item -ItemType Directory -Path $scrubbed -Force | Out-Null
    $files = @(
        Get-ChildItem -LiteralPath $scrubbed -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '(?i)_scrubbed\.(csv|json)$|upload_manifest\.json$' } |
            Sort-Object Name |
            ForEach-Object {
                $rows = -1
                if ($_.Extension -ieq '.csv') {
                    try { $rows = @(Import-Csv -LiteralPath $_.FullName).Count } catch { $rows = -1 }
                }
                [ordered]@{ File = $_.Name; Rows = $rows; Bytes = $_.Length; Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
            }
    )
    $manifest = [ordered]@{
        ManifestVersion = $script:AssessmentUploadManifestVersion
        Tool = 'CertifEye'
        CollectorVersion = '2.1.0-rc1'
        SchemaVersion = 'certifeye-exports/v1'
        TokenContractVersion = $script:AssessmentTokenContractVersion
        HmacLength = $script:HmacLength
        Mode = if($Stage){$Stage}else{'Interactive'}
        Files = $files
        ReviewRequired = $true
        Warnings = @('Manifest contains coverage metadata only; it does not prove that missing evidence is clean.')
        UploadGuidance = 'Upload only reviewed manifest-listed files. Never upload raw data, salts, maps, or private manifests.'
    }
    $path = Join-Path $scrubbed 'adcs_upload_manifest.json'
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}

function Write-LocalOnlyManifest {
    param(
        [Parameter(Mandatory)][string]$Root,
        [string]$InputPath,
        [string]$OutputPath
    )
    $private = Join-Path $Root 'Private_DO_NOT_UPLOAD'
    New-Item -ItemType Directory -Path $private -Force | Out-Null
    $relativeArtifacts = @()
    if ($OutputPath -and (Test-Path -LiteralPath $OutputPath)) {
        $relativeArtifacts = @(
            Get-ChildItem -LiteralPath $OutputPath -File -ErrorAction SilentlyContinue |
                Sort-Object Name |
                ForEach-Object { [ordered]@{ File = $_.Name; Bytes = $_.Length } }
        )
    }
    $manifest = [ordered]@{
        ManifestVersion = 'certifeye-local-only/v1'
        Tool = 'CertifEye'
        CollectorVersion = '2.1.0-rc1'
        PackageMode = 'LocalOnlyNoTokenization'
        Tokenization = 'Disabled'
        SafeUploadEligible = $false
        InputLocation = 'Raw_DO_NOT_UPLOAD (or explicitly supplied local input)'
        OutputLocation = 'Private_DO_NOT_UPLOAD (or explicitly supplied local output)'
        Artifacts = $relativeArtifacts
        Warnings = @(
            'LOCAL_ONLY_NO_TOKENIZATION',
            'Raw values may be present in this run. Do not upload, email, or place these artifacts in an AI workflow.',
            'No token map and no safe upload manifest were generated.'
        )
    }
    $path = Join-Path $private 'certifeye_local_only_manifest_DO_NOT_UPLOAD.json'
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}

function Initialize-AssessmentPackage {
    param([Parameter(Mandatory)][string]$Root)
    foreach ($name in @('Raw_DO_NOT_UPLOAD', 'Scrubbed', 'Private_DO_NOT_UPLOAD', 'Output', 'Working')) {
        New-Item -ItemType Directory -Path (Join-Path $Root $name) -Force | Out-Null
    }
}

function Invoke-ExplicitAnalysis {
    param(
        [Parameter(Mandatory)][string]$Root,
        [switch]$LocalOnly
    )
    Initialize-AssessmentPackage -Root $Root
    $defaultInput = if ($LocalOnly) { Join-Path $Root 'Raw_DO_NOT_UPLOAD' } else { Join-Path $Root 'Scrubbed' }
    $defaultOutput = if ($LocalOnly) { Join-Path $Root 'Private_DO_NOT_UPLOAD\Output' } else { Join-Path $Root 'Output' }
    $defaultWorking = if ($LocalOnly) { Join-Path $Root 'Private_DO_NOT_UPLOAD\Working' } else { Join-Path $Root 'Working' }
    $inputPath = Resolve-PipelinePath $(if ($InputDir) { $InputDir } else { $defaultInput })
    $outputPath = Resolve-PipelinePath $(if ($OutputDir) { $OutputDir } else { $defaultOutput })
    $workingPath = Resolve-PipelinePath $(if ($WorkingDir) { $WorkingDir } else { $defaultWorking })
    New-Item -ItemType Directory -Path $inputPath, $outputPath, $workingPath -Force | Out-Null

    $python = Find-PythonRuntime
    $runner = Join-Path $PSScriptRoot 'skills\adcs-esc-audit\scripts\00_run_all.py'
    $arguments = @($runner, '--input-dir', $inputPath, '--output-dir', $outputPath, '--working-dir', $workingPath)
    if ($SkipQa) { $arguments += '--skip-qa' }
    if ($LocalOnly) { $env:ADCS_AUDIT_LOCAL_ONLY = '1' }
    try { & $python @arguments }
    finally { Remove-Item Env:ADCS_AUDIT_LOCAL_ONLY -ErrorAction SilentlyContinue }
    if ($LASTEXITCODE -ne 0) { throw "AD CS analysis pipeline failed with exit code $LASTEXITCODE." }

    if ($LocalOnly) {
        Write-LocalOnlyManifest -Root $Root -InputPath $inputPath -OutputPath $outputPath | Write-Host
        Write-Host 'Local-only analysis complete. Reports are private and are NOT safe to upload or share with AI.' -ForegroundColor Yellow
        return [pscustomobject]@{ PackageMode='LocalOnlyNoTokenization'; SafeUploadEligible=$false; InputDir=$inputPath; OutputDir=$outputPath; WorkingDir=$workingPath }
    }
    Get-ChildItem -LiteralPath $outputPath -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)_scrubbed\.csv$' } |
        Copy-Item -Destination (Join-Path $Root 'Scrubbed') -Force
    Write-SafeUploadManifest -Root $Root | Write-Host
    Write-Host 'AD CS analysis complete. Review Scrubbed and adcs_upload_manifest.json before sharing.' -ForegroundColor Green
}

function Move-LocalOnlyRawExports {
    param([Parameter(Mandatory)][string]$Root)
    Initialize-AssessmentPackage -Root $Root
    $raw = Join-Path $Root 'Raw_DO_NOT_UPLOAD'
    $files = @(Get-ChildItem -LiteralPath $Root -File -Filter '*_UNSCRUBBED.csv' -ErrorAction SilentlyContinue | Sort-Object Name)
    foreach ($file in $files) {
        Move-Item -LiteralPath $file.FullName -Destination (Join-Path $raw $file.Name) -Force
    }
    Write-LocalOnlyManifest -Root $Root -InputPath $raw | Out-Null
    return $files.Count
}

function Publish-LegacyPackage {
    param([Parameter(Mandatory)][string]$Root)
    Initialize-AssessmentPackage -Root $Root
    Get-ChildItem -LiteralPath $Root -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)_scrubbed\.csv$' } |
        Copy-Item -Destination (Join-Path $Root 'Scrubbed') -Force
    Get-ChildItem -LiteralPath $Root -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)_UNSCRUBBED\.csv$' } |
        Copy-Item -Destination (Join-Path $Root 'Raw_DO_NOT_UPLOAD') -Force
    Write-SafeUploadManifest -Root $Root | Write-Host
}

# =====================================================================
# REGION: Console helpers
# =====================================================================

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Read-DefaultString {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$Default
    )
    # If a Default was supplied at all (even an empty string), the field is
    # optional: empty input returns the default. If no Default was supplied,
    # the field is required and we keep asking.
    if ($PSBoundParameters.ContainsKey('Default')) {
        $promptText = if ([string]::IsNullOrEmpty($Default)) { $Prompt } else { "$Prompt [$Default]" }
        $answer = Read-Host $promptText
        if ([string]::IsNullOrWhiteSpace($answer)) {
            return $Default
        }
        return $answer.Trim()
    }

    while ($true) {
        $answer = Read-Host $Prompt
        if (-not [string]::IsNullOrWhiteSpace($answer)) {
            return $answer.Trim()
        }
        Write-Host "  A value is required." -ForegroundColor Yellow
    }
}

function Read-DefaultInt {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][int]$Default
    )
    $answer = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $Default
    }
    $parsed = 0
    if ([int]::TryParse($answer.Trim(), [ref]$parsed)) {
        return $parsed
    }
    Write-Host "  Not a whole number; using $Default." -ForegroundColor Yellow
    return $Default
}

function Read-YesNo {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [bool]$Default = $true
    )
    $suffix = if ($Default) { "[Y/n]" } else { "[y/N]" }
    $answer = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $Default
    }
    return ($answer.Trim() -match '^(y|yes)$')
}

# Prompt once for the salt and cache it for the whole session. Entry is masked.
function Get-SessionSalt {
    if (-not [string]::IsNullOrWhiteSpace($script:Salt)) {
        return $script:Salt
    }

    $script:Salt = Resolve-AssessmentSaltInput -Salt $Salt -SaltFile $SaltFile -SaltFromEnv $SaltFromEnv -PromptWhenMissing:(-not $NonInteractive)
    return $script:Salt
}

function Resolve-OutPath {
    # Turn a possibly-relative path into a full path and ensure its folder exists.
    param([Parameter(Mandatory)][string]$Path)
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $dir = Split-Path -Parent $full
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    return $full
}

# Normalize a date value (DateTime or locale-formatted string) to ISO 8601 so the
# exported CSVs sort and parse unambiguously downstream (avoids M/D/YYYY string
# sorting). Non-date / unparseable values are returned unchanged.
function ConvertTo-Iso8601 {
    param($Value)
    if ($null -eq $Value) { return $Value }
    if ($Value -is [datetime]) { return $Value.ToString("yyyy-MM-ddTHH:mm:ssK") }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $s }
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse($s, [ref]$dt)) { return $dt.ToString("yyyy-MM-ddTHH:mm:ssK") }
    return $s
}

# Non-reversible fingerprint of the session salt, so independent runs can be
# correlated (same salt -> same fingerprint) WITHOUT exposing the salt itself.
function Get-SaltFingerprint {
    $salt = Get-SessionSalt
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($salt)) }
    finally { $sha.Dispose() }
    return (ConvertTo-HexString -Bytes $bytes).Substring(0, 12).ToUpperInvariant()
}

# Emit a self-describing manifest of the scrubbed files a run produced: filename,
# row count, size, plus the salt fingerprint + HMAC length so a consumer (Cowork)
# can confirm a consistent token space across files. Never writes the salt itself.
function Write-RunManifest {
    param([Parameter(Mandatory)][string]$WorkDir)
    $files = @(Get-ChildItem -Path $WorkDir -Filter "*_scrubbed.csv" -File -ErrorAction SilentlyContinue)
    $entries = @()
    foreach ($f in ($files | Sort-Object Name)) {
        $rows = -1
        try { $rows = @(Import-Csv $f.FullName).Count } catch { $rows = -1 }
        $entries += [pscustomobject]@{ file = $f.Name; rows = $rows; bytes = $f.Length }
    }
    $manifest = [pscustomobject]@{
        tool            = "Invoke-ADCSAuditPipeline.ps1"
        schemaVersion   = "1.0"
        generatedUtc    = ((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))
        saltFingerprint = (Get-SaltFingerprint)
        hmacLength      = $script:HmacLength
        scrubbedFiles   = $entries
    }
    $outPath = Resolve-OutPath -Path (Join-Path $WorkDir "adcs_audit_manifest.json")
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $outPath -Encoding UTF8
    Write-Host "[+] Run manifest written to $outPath" -ForegroundColor Green
    return $outPath
}

# Prompt for the sensitive terms the scrubbed output must not contain. Defaults
# are seeded from the environment (AD DNS domain + NetBIOS name), the org label
# (second-level domain), and any CA common names discoverable in the forest.
function Get-SensitiveTerms {
    $defaults = @()
    if ($env:USERDNSDOMAIN) {
        $defaults += $env:USERDNSDOMAIN
        # Second-level label, e.g. corp.contoso.com -> contoso (the org name).
        $parts = @($env:USERDNSDOMAIN.Split('.') | Where-Object { $_ })
        if ($parts.Count -ge 2) { $defaults += $parts[$parts.Count - 2] }
    }
    if ($env:USERDOMAIN) { $defaults += $env:USERDOMAIN }

    # CA common names (best effort; empty off-domain or without rights).
    foreach ($ca in @(Get-CAConfigList)) {
        if (-not [string]::IsNullOrWhiteSpace($ca.CommonName)) { $defaults += $ca.CommonName }
    }

    $defaultStr = (($defaults | Where-Object { $_ } | Select-Object -Unique) -join ', ')

    $raw = Read-DefaultString -Prompt "Sensitive terms the scrubbed file must NOT contain (comma-separated: AD FQDN, NetBIOS, org/CA name, etc.)" -Default $defaultStr
    $terms = @()
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        $terms = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    return $terms
}

# =====================================================================
# REGION: Shared crypto / normalization / token helpers
#         (used by TokenMap build, Scrub, and Harden -- one definition each)
# =====================================================================

function Normalize-SANValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $v = $Value.Trim()
    if     ($v -match '(?i)principal name\s*=\s*(.+)$') { $v = $matches[1] }
    elseif ($v -match '(?i)rfc822 name\s*=\s*(.+)$')    { $v = $matches[1] }
    elseif ($v -match '(?i)upn\s*=\s*(.+)$')            { $v = $matches[1] }
    elseif ($v -match '(?i)email\s*=\s*(.+)$')          { $v = $matches[1] }

    $v = $v -replace '(?i)^smtp:', ''
    $v = $v -replace '(?i)^mailto:', ''
    return $v.Trim()
}

function Normalize-TokenKey {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = Normalize-SANValue -Value $Value
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    return ($v.Trim() -replace "`r|`n", " ").ToLowerInvariant()
}

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString("x2") }) -join "")
}

# Returns "PREFIX_<hex>" or $null when the value cannot be normalized.
# Uses the session salt + session HMAC length so every stage agrees.
function Invoke-HmacToken {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Prefix
    )

    $normalized = Normalize-TokenKey -Value $Value
    if (-not $normalized) { return $null }

    return New-AssessmentHmacToken -Value $Value -Prefix $Prefix -Salt (Get-SessionSalt) -HmacLength $script:HmacLength -ValueByToken $script:ValueByToken
}

function Is-AlreadyToken {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return (
        $Value -match '^(HV_)?(PRINCIPAL|COMPUTER|GROUP|OBJECT|SID|DNS|UPN|EMAIL|CERT|TEMPLATE|CA|X500|GUID|IP)_[A-F0-9]{4,}$' -or
        $Value -match '^UNMAPPED_(UPN|PRINCIPAL|DNS|OBJECT|IP)_[A-F0-9]{4,}$' -or
        $Value -match '^(BROAD|ADCS|HV_GROUP)_[A-Z0-9_]+$'
    )
}

# Value-only canonical label resolver (used by Scrub + Harden).
function Get-CanonicalKnownLabelByValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $trimmed = $Value.Trim()
    $simple = $trimmed
    if     ($trimmed -match '^CN=([^,]+),') { $simple = $matches[1] }
    elseif ($trimmed -match '\\')           { $simple = ($trimmed -split '\\')[-1] }
    $simple = $simple.Trim()
    $simpleLower = $simple.ToLowerInvariant()

    switch -Regex ($trimmed) {
        '^S-1-1-0$'      { return "BROAD_EVERYONE" }
        '^S-1-5-11$'     { return "BROAD_AUTHENTICATED_USERS" }
        '^S-1-5-32-545$' { return "BROAD_BUILTIN_USERS" }
        '^S-1-5-32-544$' { return "HV_GROUP_BUILTIN_ADMINISTRATORS" }
        '^S-1-5-32-548$' { return "HV_GROUP_ACCOUNT_OPERATORS" }
        '^S-1-5-32-549$' { return "HV_GROUP_SERVER_OPERATORS" }
        '^S-1-5-32-550$' { return "HV_GROUP_PRINT_OPERATORS" }
        '^S-1-5-32-551$' { return "HV_GROUP_BACKUP_OPERATORS" }
        '-512$'          { return "HV_GROUP_DOMAIN_ADMINS" }
        '-513$'          { return "BROAD_DOMAIN_USERS" }
        '-515$'          { return "BROAD_DOMAIN_COMPUTERS" }
        '-516$'          { return "HV_GROUP_DOMAIN_CONTROLLERS" }
        '-517$'          { return "ADCS_GROUP_CERT_PUBLISHERS" }
        '-518$'          { return "HV_GROUP_SCHEMA_ADMINS" }
        '-519$'          { return "HV_GROUP_ENTERPRISE_ADMINS" }
        '-520$'          { return "HV_GROUP_GROUP_POLICY_CREATOR_OWNERS" }
        '-526$'          { return "HV_GROUP_KEY_ADMINS" }
        '-527$'          { return "HV_GROUP_ENTERPRISE_KEY_ADMINS" }
    }

    switch ($simpleLower) {
        "everyone"                      { return "BROAD_EVERYONE" }
        "authenticated users"           { return "BROAD_AUTHENTICATED_USERS" }
        "domain users"                  { return "BROAD_DOMAIN_USERS" }
        "domain computers"              { return "BROAD_DOMAIN_COMPUTERS" }
        "users"                         { return "BROAD_BUILTIN_USERS" }
        "builtin\users"                 { return "BROAD_BUILTIN_USERS" }
        "administrators"                { return "HV_GROUP_BUILTIN_ADMINISTRATORS" }
        "builtin\administrators"        { return "HV_GROUP_BUILTIN_ADMINISTRATORS" }
        "domain admins"                 { return "HV_GROUP_DOMAIN_ADMINS" }
        "enterprise admins"             { return "HV_GROUP_ENTERPRISE_ADMINS" }
        "schema admins"                 { return "HV_GROUP_SCHEMA_ADMINS" }
        "account operators"             { return "HV_GROUP_ACCOUNT_OPERATORS" }
        "server operators"              { return "HV_GROUP_SERVER_OPERATORS" }
        "print operators"               { return "HV_GROUP_PRINT_OPERATORS" }
        "backup operators"              { return "HV_GROUP_BACKUP_OPERATORS" }
        "domain controllers"            { return "HV_GROUP_DOMAIN_CONTROLLERS" }
        "enterprise domain controllers" { return "HV_GROUP_ENTERPRISE_DOMAIN_CONTROLLERS" }
        "group policy creator owners"   { return "HV_GROUP_GROUP_POLICY_CREATOR_OWNERS" }
        "key admins"                    { return "HV_GROUP_KEY_ADMINS" }
        "enterprise key admins"         { return "HV_GROUP_ENTERPRISE_KEY_ADMINS" }
        "dnsadmins"                     { return "HV_GROUP_DNSADMINS" }
        "cert publishers"               { return "ADCS_GROUP_CERT_PUBLISHERS" }
    }

    foreach ($label in $script:AdditionalBroadLabels) {
        if (-not [string]::IsNullOrWhiteSpace($label) -and $trimmed -eq $label) {
            return "BROAD_DOMAIN_USERS"
        }
    }

    return $null
}

# Single token resolver shared by Scrub free-text AND Harden. Order:
#   already-a-token -> token map -> canonical safe label -> keep OID -> fresh HMAC.
function Get-Token {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Prefix
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $clean = $Value.Trim()

    if (Is-AlreadyToken -Value $clean) { return $clean }

    $norm = Normalize-TokenKey -Value $clean
    if ($norm -and $script:TokenByNorm.ContainsKey($norm)) {
        return $script:TokenByNorm[$norm]
    }

    $known = Get-CanonicalKnownLabelByValue -Value $clean
    if ($known) { return $known }

    if ($clean -match '^([0-9]+\.)+[0-9]+$') { return $clean }   # leave OIDs intact

    $token = Invoke-HmacToken -Value $clean -Prefix $Prefix
    if ($token) { return $token }
    return $clean
}

# =====================================================================
# REGION: Token-map loading (shared by Scrub + Harden)
# =====================================================================

function Get-MapColumnName {
    param(
        [Parameter(Mandatory)]$Row,
        [Parameter(Mandatory)][string[]]$Candidates
    )
    $props = @($Row.PSObject.Properties.Name)
    foreach ($candidate in $Candidates) {
        if ($props -contains $candidate) { return $candidate }
    }
    return $null
}

function Import-TokenMap {
    param([Parameter(Mandatory)][string]$TokenMapCsv)

    if (-not (Test-Path $TokenMapCsv)) {
        throw "Token map not found: $TokenMapCsv"
    }

    # Keep the parsed map in memory for the whole session so a batch scrub of many
    # files (or scrub+harden) doesn't re-read 100k+ rows each time. The cache key is
    # the resolved path + last-write time, so a rebuilt/edited token map is detected
    # and reloaded automatically.
    $resolved = (Resolve-Path -Path $TokenMapCsv).Path
    $cacheKey = "$resolved|$((Get-Item -Path $resolved).LastWriteTimeUtc.Ticks)"
    if ($script:TokenMapCacheKey -eq $cacheKey -and $script:TokenByNorm -and $script:TokenByNorm.Count -gt 0) {
        Write-Host "Reusing token map already in memory ($($script:TokenByNorm.Count) entries): $TokenMapCsv"
        return $script:TokenByNorm
    }

    Write-Host "Loading token map: $TokenMapCsv"
    $tokenRows = Import-Csv $TokenMapCsv
    $map = @{}

    foreach ($row in $tokenRows) {
        $inputCol = Get-MapColumnName -Row $row -Candidates @("InputValue", "OriginalValue", "Value", "SourceValue")
        $normCol  = Get-MapColumnName -Row $row -Candidates @("NormalizedValue", "Normalized", "NormalizedKey")
        $tokenCol = Get-MapColumnName -Row $row -Candidates @("Token", "ScrubbedValue", "Replacement")

        if (-not $tokenCol) { continue }
        $token = [string]$row.$tokenCol
        if ([string]::IsNullOrWhiteSpace($token)) { continue }

        # Always (re)normalize with the shared normalizer so lookups behave
        # identically in every stage -- the original scripts diverged here.
        $norm = $null
        if ($normCol -and $row.$normCol) {
            $norm = Normalize-TokenKey -Value ([string]$row.$normCol)
        }
        elseif ($inputCol -and $row.$inputCol) {
            $norm = Normalize-TokenKey -Value ([string]$row.$inputCol)
        }

        if ($norm -and -not $map.ContainsKey($norm)) {
            $map[$norm] = $token
        }
    }

    $script:TokenByNorm = $map
    $script:TokenMapCacheKey = $cacheKey
    Write-Host "Loaded token map entries: $($script:TokenByNorm.Count)"
    return $map
}

# =====================================================================
# REGION: CA discovery (auto-detect config strings)
# =====================================================================

function Get-CAConfigList {
    # Enumerate CA config strings ("Server\CAName") registered in the forest via
    # the CertConfig COM object. Returns an array of objects; empty if none/not a
    # CA host / no access.
    $list = @()
    try {
        $cc = New-Object -ComObject CertificateAuthority.Config
    }
    catch {
        return $list
    }
    try {
        $count = [int]$cc.Reset(0)
        if ($count -gt 0) {
            do {
                $cfg = $null; $common = $null; $server = $null
                try { $cfg    = [string]$cc.GetField("Config") }     catch { }
                try { $common = [string]$cc.GetField("CommonName") } catch { }
                try { $server = [string]$cc.GetField("Server") }     catch { }
                if (-not [string]::IsNullOrWhiteSpace($cfg)) {
                    $list += [pscustomobject]@{ Config = $cfg; CommonName = $common; Server = $server }
                }
            } while ($cc.Next() -ge 0)
        }
    }
    catch {
        # Return whatever we managed to collect.
    }
    return $list
}

function Select-CAConfig {
    # Interactive CA picker: auto-detect, offer a numbered list if several,
    # otherwise fall back to a manual prompt. Always returns a cleaned string.
    $cas = @(Get-CAConfigList)

    if ($cas.Count -eq 0) {
        Write-Host "No CAs auto-detected (run on the CA, or check rights)." -ForegroundColor Yellow
        return Read-DefaultString -Prompt "CA config string (e.g. PKI-CA01\Contoso-Issuing-CA)"
    }

    if ($cas.Count -eq 1) {
        Write-Host "Detected CA: $($cas[0].Config)"
        return Read-DefaultString -Prompt "CA config string" -Default $cas[0].Config
    }

    Write-Host "Detected CAs:"
    for ($i = 0; $i -lt $cas.Count; $i++) {
        Write-Host ("  {0}) {1}" -f ($i + 1), $cas[$i].Config)
    }
    $sel = Read-DefaultString -Prompt "Select a CA by number (or type a config string)" -Default "1"

    $idx = 0
    if ([int]::TryParse($sel, [ref]$idx) -and $idx -ge 1 -and $idx -le $cas.Count) {
        return $cas[$idx - 1].Config
    }
    return ($sel -replace '^[\s"'']+', '' -replace '[\s"'']+$', '')
}

# =====================================================================
# REGION: Stage 1 -- Export certificates from a CA database (issued + revoked)
# =====================================================================

function Invoke-ExportIssuedCerts {
    param(
        [Parameter(Mandatory)][string]$CAConfig,
        [Parameter(Mandatory)][string]$OutCsv,
        [int]$MaxRows = 0,
        [switch]$IncludeRevoked
    )

    Write-Section "Stage 1: Export certificates (issued$(if ($IncludeRevoked) { ' + revoked' }))"

    # Defensive: strip any stray surrounding quotes/whitespace from the config.
    $CAConfig = ($CAConfig -replace '^[\s"'']+', '' -replace '[\s"'']+$', '')

    # ICertView constants
    $CV_OUT_BASE64HEADER = 0
    $CVR_SEEK_EQ         = 1
    $CVR_SORT_NONE       = 0

    $AuthCapableOids = @(
        "1.3.6.1.5.5.7.3.2",        # Client Authentication
        "1.3.6.1.4.1.311.20.2.2",   # Smart Card Logon
        "1.3.6.1.5.2.3.4",          # PKINIT Client Authentication
        "2.5.29.37.0"               # Any Purpose
    )

    function Convert-PemToCert {
        param([Parameter(Mandatory)][string]$Pem)
        $b64 = $Pem -replace '-----BEGIN CERTIFICATE-----', ''
        $b64 = $b64 -replace '-----END CERTIFICATE-----', ''
        $b64 = $b64 -replace '\s+', ''
        $bytes = [Convert]::FromBase64String($b64)
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(, $bytes)
    }

    function Get-EkuOids {
        param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
        $ekuOids = @()
        foreach ($ext in $Cert.Extensions) {
            if ($ext.Oid.Value -eq "2.5.29.37") {
                try {
                    $eku = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension -ArgumentList @($ext, $false)
                    foreach ($oid in $eku.EnhancedKeyUsages) { $ekuOids += $oid.Value }
                }
                catch { }
            }
        }
        return (($ekuOids | Sort-Object -Unique) -join "; ")
    }

    function Test-AuthCapable {
        param([AllowNull()][string]$EkuOidString)
        if ([string]::IsNullOrWhiteSpace($EkuOidString)) {
            # No EKU == not restricted by EKU, so review as auth-capable/risky.
            return $true
        }
        $oids = @($EkuOidString -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        foreach ($oid in $oids) {
            if ($AuthCapableOids -contains $oid) { return $true }
        }
        return $false
    }

    function Get-SanData {
        param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

        $sanText = $null
        $sanUpn = @(); $sanDns = @(); $sanEmail = @(); $sanUri = @()

        $sanExt = $Cert.Extensions |
            Where-Object { $_.Oid.Value -eq "2.5.29.17" } |
            Select-Object -First 1

        if ($sanExt) {
            $asn = New-Object System.Security.Cryptography.AsnEncodedData($sanExt.Oid, $sanExt.RawData)
            $sanText = $asn.Format($true)

            foreach ($line in ($sanText -split "(`r`n|`n|`r)")) {
                $trim = $line.Trim()
                if ($trim -match '(?i)Principal Name|UPN') {
                    $value = ($trim -replace '.*?=\s*', '' -replace '.*?:\s*', '').Trim()
                    if ($value) { $sanUpn += $value }
                }
                elseif ($trim -match '(?i)DNS Name=|DNS:') {
                    $value = ($trim -replace '(?i).*?DNS Name=\s*', '' -replace '(?i).*?DNS:\s*', '').Trim()
                    if ($value) { $sanDns += $value }
                }
                elseif ($trim -match '(?i)RFC822 Name=|E-mail|Email') {
                    $value = ($trim -replace '.*?=\s*', '' -replace '.*?:\s*', '').Trim()
                    if ($value) { $sanEmail += $value }
                }
                elseif ($trim -match '(?i)URL=|URI=|URI:') {
                    $value = ($trim -replace '.*?=\s*', '' -replace '.*?:\s*', '').Trim()
                    if ($value) { $sanUri += $value }
                }
            }
        }

        return [pscustomobject]@{
            SAN_Text  = $sanText
            SAN_UPN   = (($sanUpn   | Sort-Object -Unique) -join "; ")
            SAN_DNS   = (($sanDns   | Sort-Object -Unique) -join "; ")
            SAN_Email = (($sanEmail | Sort-Object -Unique) -join "; ")
            SAN_URI   = (($sanUri   | Sort-Object -Unique) -join "; ")
        }
    }

    function Get-SidSecurityExtension {
        # ESC9/ESC10 support: read the AD CS SID security extension
        # (szOID_NTDS_CA_SECURITY_EXT, 1.3.6.1.4.1.311.25.2) that binds the
        # requester's objectSid into the certificate. Its ABSENCE on an
        # auth-capable cert whose template sets NoSecurityExtension is the ESC9
        # signal; an embedded SID that does NOT match the requester is a
        # strong-mapping forgery signal. The objectSid is carried (inside an
        # OtherName, 1.3.6.1.4.1.311.25.2.1) as an "S-1-5-..." string, so a
        # pragmatic ASCII scan recovers it without a full ASN.1 parse.
        param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
        $oid = "1.3.6.1.4.1.311.25.2"
        $ext = $Cert.Extensions | Where-Object { $_.Oid.Value -eq $oid } | Select-Object -First 1
        if (-not $ext) {
            return [pscustomobject]@{ Present = $false; Sid = $null }
        }
        $sid = $null
        try {
            $ascii = [System.Text.Encoding]::ASCII.GetString($ext.RawData)
            $match = [regex]::Match($ascii, 'S-1-\d+(?:-\d+)+')
            if ($match.Success) { $sid = $match.Value }
        }
        catch { }
        return [pscustomobject]@{ Present = $true; Sid = $sid }
    }

    function Resolve-Column {
        param(
            [Parameter(Mandatory)][System.Collections.IDictionary]$AvailableColumns,
            [Parameter(Mandatory)][string[]]$Candidates
        )
        foreach ($candidate in $Candidates) {
            if ($AvailableColumns.Contains($candidate)) { return $candidate }
        }
        return $null
    }

    function Get-RowValue {
        param(
            [Parameter(Mandatory)][System.Collections.IDictionary]$Row,
            [Parameter(Mandatory)][System.Collections.IDictionary]$ColumnMap,
            [Parameter(Mandatory)][string]$LogicalName
        )
        if (-not $ColumnMap.Contains($LogicalName)) { return $null }
        $actualColumn = $ColumnMap[$LogicalName]
        if ([string]::IsNullOrWhiteSpace($actualColumn)) { return $null }
        if ($Row.Contains($actualColumn)) { return $Row[$actualColumn] }
        return $null
    }

    # Pull all rows for ONE disposition value into a records list. ICertView
    # restrictions are AND-only (you cannot OR two dispositions in one view), so
    # each disposition is queried on its own fresh connection and the results are
    # concatenated. 20 = issued, 21 = revoked.
    function Get-RecordsForDisposition {
        param(
            [Parameter(Mandatory)][int]$Disposition,
            [Parameter(Mandatory)][string]$DispositionLabel
        )

        Write-Host "[*] Connecting to CA: $CAConfig  ($DispositionLabel, disposition=$Disposition)"
        $view = New-Object -ComObject CertificateAuthority.View
        $view.OpenConnection($CAConfig)

        $schemaEnum = $view.EnumCertViewColumn(0)
        $availableCols = @{}
        while ($true) {
            $nextSchemaCol = $schemaEnum.Next()
            if ($nextSchemaCol -eq -1) { break }
            $availableCols[$schemaEnum.GetName()] = $schemaEnum.GetDisplayName()
        }

        $columnAliases = [ordered]@{
            RequestID           = @("RequestID", "Request.RequestID")
            RequesterName       = @("RequesterName", "Request.RequesterName")
            CallerName          = @("CallerName", "Request.CallerName")
            SubmittedWhen       = @("SubmittedWhen", "Request.SubmittedWhen")
            ResolvedWhen        = @("ResolvedWhen", "Request.ResolvedWhen")
            CertificateTemplate = @("CertificateTemplate", "Request.CertificateTemplate")
            SerialNumber        = @("SerialNumber", "Request.SerialNumber")
            CertificateHash     = @("CertificateHash", "Request.CertificateHash")
            NotBefore           = @("NotBefore", "Request.NotBefore")
            NotAfter            = @("NotAfter", "Request.NotAfter")
            CommonName          = @("CommonName", "Request.CommonName")
            DistinguishedName   = @("DistinguishedName", "Request.DistinguishedName")
            RequestAttributes   = @("RequestAttributes", "Request.RequestAttributes")
            Disposition         = @("Disposition", "Request.Disposition")
            RevokedWhen         = @("RevokedWhen", "Request.RevokedWhen")
            RevokedReason       = @("RevokedReason", "Request.RevokedReason")
            RawCertificate      = @("RawCertificate", "BinaryRawCertificate", "Request.RawCertificate", "Request.BinaryRawCertificate")
        }

        $columnMap = [ordered]@{}
        foreach ($logicalName in $columnAliases.Keys) {
            $columnMap[$logicalName] = Resolve-Column -AvailableColumns $availableCols -Candidates $columnAliases[$logicalName]
        }

        if (-not $columnMap["Disposition"]) {
            throw "Could not find the Disposition column. Cannot restrict by disposition."
        }
        if (-not $columnMap["RawCertificate"]) {
            Write-Warning "Could not find RawCertificate/BinaryRawCertificate. Cert parsing will be skipped."
        }

        $actualColumns = @(
            $columnMap.Values |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Sort-Object -Unique
        )
        $view.SetResultColumnCount($actualColumns.Count)
        foreach ($col in $actualColumns) {
            $view.SetResultColumn($view.GetColumnIndex($false, $col))
        }

        $dispIdx = $view.GetColumnIndex($false, $columnMap["Disposition"])
        $view.SetRestriction($dispIdx, $CVR_SEEK_EQ, $CVR_SORT_NONE, $Disposition)

        $rowEnum = $view.OpenView()
        $records = New-Object System.Collections.Generic.List[object]
        $rowCount = 0

        while ($true) {
            $nextRow = $rowEnum.Next()
            if ($nextRow -eq -1) { break }
            $rowCount++
            if ($rowCount % 200 -eq 0) { Write-Progress -Activity "Stage 1: exporting $DispositionLabel certificates" -Status "$rowCount rows parsed..." }
            if ($MaxRows -gt 0 -and $rowCount -gt $MaxRows) { break }

            $row = @{}
            $colEnum = $rowEnum.EnumCertViewColumn()
            while ($true) {
                $nextCol = $colEnum.Next()
                if ($nextCol -eq -1) { break }
                $row[$colEnum.GetName()] = $colEnum.GetValue($CV_OUT_BASE64HEADER)
            }

            $parseStatus = "OK"
            $subject = $null; $issuer = $null; $thumbprint = $null
            $ekuOids = $null; $authCapable = $null
            $san = [pscustomobject]@{ SAN_Text = $null; SAN_UPN = $null; SAN_DNS = $null; SAN_Email = $null; SAN_URI = $null }
            # ESC9/10: $null (not $false) until a cert is parsed, so "no extension"
            # is never confused with "could not parse".
            $hasSidExt = $null; $sidExtSid = $null

            try {
                $rawCertValue = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "RawCertificate"
                if (-not [string]::IsNullOrWhiteSpace($rawCertValue)) {
                    $cert = Convert-PemToCert -Pem $rawCertValue
                    $subject = $cert.Subject
                    $issuer = $cert.Issuer
                    $thumbprint = $cert.Thumbprint
                    $ekuOids = Get-EkuOids -Cert $cert
                    $authCapable = Test-AuthCapable -EkuOidString $ekuOids
                    $san = Get-SanData -Cert $cert
                    $sidExtInfo = Get-SidSecurityExtension -Cert $cert
                    $hasSidExt  = $sidExtInfo.Present
                    $sidExtSid  = $sidExtInfo.Sid
                }
                else {
                    $parseStatus = "No RawCertificate returned"
                }
            }
            catch {
                $parseStatus = "Parse failed: $($_.Exception.Message)"
            }

            # Issuance-log ESC signal flags (computed from already-collected fields).
            #   ESC6: a SAN delivered via the request attributes (san:...)
            #   ESC3: Certificate Request Agent EKU, and on-behalf-of enrollment
            #   ESC2: Any Purpose EKU or no EKU at all
            $raForFlags = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "RequestAttributes"
            $rnForFlags = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "RequesterName"
            $cnForFlags = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "CallerName"
            $requestAttributesHasSan  = [bool]("$raForFlags" -match '(?i)\bsan:')
            $isEnrollmentAgentCert    = [bool]("$ekuOids"    -match '1\.3\.6\.1\.4\.1\.311\.20\.2\.1')
            $hasAnyPurposeOrNoEku     = [bool]([string]::IsNullOrWhiteSpace($ekuOids) -or ("$ekuOids" -match '2\.5\.29\.37\.0'))
            $onBehalfOfCallerMismatch = [bool](
                -not [string]::IsNullOrWhiteSpace($cnForFlags) -and
                -not [string]::IsNullOrWhiteSpace($rnForFlags) -and
                ($cnForFlags.Trim().ToLowerInvariant() -ne $rnForFlags.Trim().ToLowerInvariant())
            )

            [void]$records.Add([pscustomobject]@{
                RequestID               = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "RequestID"
                RequesterName           = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "RequesterName"
                CallerName              = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "CallerName"
                SubmittedWhen           = ConvertTo-Iso8601 (Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "SubmittedWhen")
                ResolvedWhen            = ConvertTo-Iso8601 (Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "ResolvedWhen")
                CertificateTemplate     = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "CertificateTemplate"
                SerialNumber            = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "SerialNumber"
                CertificateHash         = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "CertificateHash"
                NotBefore               = ConvertTo-Iso8601 (Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "NotBefore")
                NotAfter                = ConvertTo-Iso8601 (Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "NotAfter")
                CA_CommonName           = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "CommonName"
                CA_DistinguishedName    = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "DistinguishedName"
                RequestAttributes       = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "RequestAttributes"
                CertSubject             = $subject
                CertIssuer              = $issuer
                CertThumbprintParsed    = $thumbprint
                EKU_OIDs                = $ekuOids
                AuthCapableOrAnyPurpose = $authCapable
                SAN_UPN                 = $san.SAN_UPN
                SAN_DNS                 = $san.SAN_DNS
                SAN_Email               = $san.SAN_Email
                SAN_URI                 = $san.SAN_URI
                SAN_Text                = $san.SAN_Text
                HasSidSecurityExtension  = $hasSidExt
                SidSecurityExtensionSid  = $sidExtSid
                RequestAttributesHasSAN  = $requestAttributesHasSan
                IsEnrollmentAgentCert    = $isEnrollmentAgentCert
                HasAnyPurposeOrNoEKU     = $hasAnyPurposeOrNoEku
                OnBehalfOfCallerMismatch = $onBehalfOfCallerMismatch
                CertDisposition         = $DispositionLabel
                RevokedWhen             = ConvertTo-Iso8601 (Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "RevokedWhen")
                RevokedReason           = Get-RowValue -Row $row -ColumnMap $columnMap -LogicalName "RevokedReason"
                ParseStatus             = $parseStatus
            })
        }

        Write-Progress -Activity "Stage 1: exporting $DispositionLabel certificates" -Completed
        Write-Host "[+] $DispositionLabel rows collected: $($records.Count)"
        return $records
    }

    $all = @()
    $all += Get-RecordsForDisposition -Disposition 20 -DispositionLabel "Issued"
    if ($IncludeRevoked) {
        $all += Get-RecordsForDisposition -Disposition 21 -DispositionLabel "Revoked"
    }
    $all = @($all)

    Write-Host "[+] Enumeration complete. Total rows: $($all.Count)"
    if ($MaxRows -gt 0) {
        Write-Host "    (note: -MaxRows $MaxRows is applied per disposition query)"
    }

    $outFull = Resolve-OutPath -Path $OutCsv
    if ($all.Count -gt 0) {
        $all | Export-Csv -Path $outFull -NoTypeInformation -Encoding UTF8
        Write-Host "[+] Exported to $outFull"
    }
    else {
        [pscustomobject]@{ Note = "Zero rows matched. Check disposition values and CA connection." } |
            Export-Csv -Path $outFull -NoTypeInformation -Encoding UTF8
        Write-Warning "Zero rows returned."
    }

    Write-Host "Rows exported: $($all.Count)"
    Write-Host "This file is UNSCRUBBED. Run the scrubber before uploading anywhere." -ForegroundColor Yellow
    return $outFull
}

# =====================================================================
# REGION: Stage 2 -- Trim issued certs to the last N years
# =====================================================================

function Invoke-TrimIssuedCerts {
    param(
        [Parameter(Mandatory)][string]$InputCsv,
        [Parameter(Mandatory)][string]$OutCsv,
        [Parameter(Mandatory)][int]$YearsBack
    )

    Write-Section "Stage 2: Trim issued certs to last $YearsBack year(s)"

    if (-not (Test-Path $InputCsv)) {
        throw "Input not found: $InputCsv"
    }

    $cutoff = (Get-Date).AddYears(-[Math]::Abs($YearsBack))

    function Get-IssuedDate {
        param($Row)
        foreach ($field in @("ResolvedWhen", "SubmittedWhen")) {
            if ($Row.PSObject.Properties.Name -contains $field) {
                $value = $Row.$field
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    $parsed = [datetime]::MinValue
                    if ([datetime]::TryParse([string]$value, [ref]$parsed)) {
                        return $parsed
                    }
                }
            }
        }
        return $null
    }

    $allRows = @(Import-Csv $InputCsv)
    $keptRows = foreach ($row in $allRows) {
        $issuedDate = Get-IssuedDate -Row $row
        if ($issuedDate -and $issuedDate -ge $cutoff) { $row }
    }
    $keptRows = @($keptRows)

    $outFull = Resolve-OutPath -Path $OutCsv
    if ($keptRows.Count -gt 0) {
        $keptRows | Export-Csv -Path $outFull -NoTypeInformation -Encoding UTF8
    }
    else {
        # Still write an (empty) file with headers so downstream stages do not choke.
        $allRows | Select-Object -First 0 | Export-Csv -Path $outFull -NoTypeInformation -Encoding UTF8
        Write-Warning "No rows fell within the last $YearsBack year(s)."
    }

    Write-Host "Input file:  $InputCsv"
    Write-Host "Output file: $outFull"
    Write-Host "Cutoff:      $cutoff"
    Write-Host "Rows input:  $($allRows.Count)"
    Write-Host "Rows kept:   $($keptRows.Count)"
    return $outFull
}

# =====================================================================
# REGION: Stage 3 -- Export certificate template inventory (AD/LDAP)
# =====================================================================

function Invoke-ExportTemplateInventory {
    param([Parameter(Mandatory)][string]$OutCsv)

    Write-Section "Stage 3: Export certificate template inventory"

    $EnrollGuid     = [Guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
    $AutoEnrollGuid = [Guid]"a05b8cc2-17bc-4802-a710-e7c15ab866a2"
    $AllGuid        = [Guid]"00000000-0000-0000-0000-000000000000"

    $CT_ENROLLEE_SUPPLIES_SUBJECT     = 0x00000001
    $CT_ENROLLEE_SUPPLIES_SUBJECT_ALT = 0x00010000
    $CT_PEND_ALL_REQUESTS     = 0x00000002
    $CT_AUTO_ENROLLMENT       = 0x00000020
    $CT_NO_SECURITY_EXTENSION = 0x00080000

    $AuthOids = @{
        "1.3.6.1.5.5.7.3.2"      = "Client Authentication"
        "1.3.6.1.4.1.311.20.2.2" = "Smart Card Logon"
        "1.3.6.1.5.2.3.4"        = "PKINIT Client Authentication"
        "2.5.29.37.0"            = "Any Purpose"
    }

    # Template-export LDAP helpers (named distinctly to avoid clashing with the
    # token-map LDAP helpers below, which have different signatures).
    function Get-TplLdapValues {
        param([Parameter(Mandatory)]$SearchResult, [Parameter(Mandatory)][string]$Name)
        $key = $SearchResult.Properties.PropertyNames | Where-Object { $_ -ieq $Name } | Select-Object -First 1
        if ($key) { return @($SearchResult.Properties[$key]) }
        return @()
    }
    function Get-TplLdapSingle {
        param([Parameter(Mandatory)]$SearchResult, [Parameter(Mandatory)][string]$Name, $Default = $null)
        $vals = @(Get-TplLdapValues -SearchResult $SearchResult -Name $Name)
        if ($vals.Count -gt 0) { return $vals[0] }
        return $Default
    }
    function Test-Bit {
        param([int64]$Value, [int64]$Mask)
        return (($Value -band $Mask) -ne 0)
    }
    function Join-List {
        param($Items)
        $arr = @($Items | Where-Object { $_ -ne $null -and "$_".Trim() -ne "" } | Sort-Object -Unique)
        return ($arr -join "; ")
    }
    function Test-BroadPrincipal {
        param([string]$Principal)
        if ([string]::IsNullOrWhiteSpace($Principal)) { return $false }
        return (
            $Principal -match '(?i)\\Domain Users$' -or
            $Principal -match '(?i)\\Authenticated Users$' -or
            $Principal -match '(?i)^NT AUTHORITY\\Authenticated Users$' -or
            $Principal -match '(?i)^Everyone$' -or
            $Principal -match '(?i)^BUILTIN\\Users$' -or
            $Principal -match '(?i)\\Domain Computers$' -or
            $Principal -match '(?i)\\Users$'
        )
    }
    # ESC4 support: recognize the principals that are EXPECTED to hold dangerous
    # control over PKI objects (tier-0 / PKI admins). Anything else holding
    # WriteDacl/WriteOwner/GenericAll/WriteProperty on a template is an ESC4
    # candidate -- a non-admin that can rewrite the template into an ESC1 shape.
    # Compares on the leaf account name so DOMAIN\Domain Admins, BUILTIN\
    # Administrators and NT AUTHORITY\SYSTEM are all treated as default.
    function Test-DefaultControlPrincipal {
        param([string]$Principal)
        if ([string]::IsNullOrWhiteSpace($Principal)) { return $false }
        # SID-based check first: locale-proof and rename-proof (works even when the
        # privileged groups are not English-named). Falls back to leaf-name match if
        # the principal can't be translated to a SID.
        try {
            $sid = ([System.Security.Principal.NTAccount]$Principal).Translate([System.Security.Principal.SecurityIdentifier]).Value
            # SYSTEM, Enterprise DCs, Creator Owner, BUILTIN\Administrators.
            if (@('S-1-5-18','S-1-5-9','S-1-3-0','S-1-5-32-544') -contains $sid) { return $true }
            # Domain-relative privileged RIDs: Domain Admins 512, Enterprise Admins 519,
            # Schema Admins 518, Cert Publishers 517, Domain Controllers 516, RODCs 521,
            # Key Admins 526, Enterprise Key Admins 527.
            if ($sid -match '-(512|519|518|517|516|521|526|527)$') { return $true }
        } catch { }
        $leaf = $Principal.Trim()
        if ($leaf -match '\\') { $leaf = ($leaf -split '\\')[-1] }
        $leaf = $leaf.Trim().ToLowerInvariant()
        $defaults = @(
            'domain admins', 'enterprise admins', 'schema admins',
            'administrators', 'system', 'local system', 'creator owner',
            'enterprise domain controllers', 'cert publishers'
        )
        return ($defaults -contains $leaf)
    }

    $rootDse = [ADSI]"LDAP://RootDSE"
    $configNC = [string]$rootDse.configurationNamingContext

    # template CN -> publishing CA names
    $publishingMap = @{}
    $enrollmentServices = [ADSI]("LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC")
    $caSearcher = New-Object System.DirectoryServices.DirectorySearcher($enrollmentServices)
    $caSearcher.Filter = "(objectClass=pKIEnrollmentService)"
    $caSearcher.PageSize = 1000
    [void]$caSearcher.PropertiesToLoad.Add("cn")
    [void]$caSearcher.PropertiesToLoad.Add("certificateTemplates")

    foreach ($ca in $caSearcher.FindAll()) {
        $caName = [string](Get-TplLdapSingle -SearchResult $ca -Name "cn")
        $templates = @(Get-TplLdapValues -SearchResult $ca -Name "certificateTemplates")
        foreach ($t in $templates) {
            if (-not $publishingMap.ContainsKey($t)) {
                $publishingMap[$t] = New-Object System.Collections.Generic.List[string]
            }
            $publishingMap[$t].Add($caName)
        }
    }

    $templateBase = [ADSI]("LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($templateBase)
    $searcher.Filter = "(objectClass=pKICertificateTemplate)"
    $searcher.PageSize = 1000
    $props = @(
        "cn", "displayName", "name", "msPKI-Cert-Template-OID",
        "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
        "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
        "msPKI-Template-Schema-Version", "msPKI-Template-Minor-Revision"
    )
    foreach ($p in $props) { [void]$searcher.PropertiesToLoad.Add($p) }

    $results = foreach ($res in $searcher.FindAll()) {
        $de = New-Object System.DirectoryServices.DirectoryEntry($res.Path)
        $cn = [string](Get-TplLdapSingle -SearchResult $res -Name "cn")
        $displayName = [string](Get-TplLdapSingle -SearchResult $res -Name "displayName" -Default $cn)
        $templateOid = [string](Get-TplLdapSingle -SearchResult $res -Name "msPKI-Cert-Template-OID" -Default "")
        $schemaVersion = Get-TplLdapSingle -SearchResult $res -Name "msPKI-Template-Schema-Version" -Default ""
        $minorRevision = Get-TplLdapSingle -SearchResult $res -Name "msPKI-Template-Minor-Revision" -Default ""

        $nameFlag = [int64](Get-TplLdapSingle -SearchResult $res -Name "msPKI-Certificate-Name-Flag" -Default 0)
        $enrollFlag = [int64](Get-TplLdapSingle -SearchResult $res -Name "msPKI-Enrollment-Flag" -Default 0)
        $raSig = [int64](Get-TplLdapSingle -SearchResult $res -Name "msPKI-RA-Signature" -Default 0)

        $suppliesSubject = Test-Bit $nameFlag $CT_ENROLLEE_SUPPLIES_SUBJECT
        $suppliesSAN = Test-Bit $nameFlag $CT_ENROLLEE_SUPPLIES_SUBJECT_ALT
        $suppliesEither = ($suppliesSubject -or $suppliesSAN)
        $managerApprovalRequired = Test-Bit $enrollFlag $CT_PEND_ALL_REQUESTS
        $autoEnrollmentFlag = Test-Bit $enrollFlag $CT_AUTO_ENROLLMENT
        $noSecurityExtension = Test-Bit $enrollFlag $CT_NO_SECURITY_EXTENSION
        $authorizedSignaturesRequired = ($raSig -gt 0)

        $ekus = @()
        $ekus += @(Get-TplLdapValues -SearchResult $res -Name "pKIExtendedKeyUsage")
        $ekus += @(Get-TplLdapValues -SearchResult $res -Name "msPKI-Certificate-Application-Policy")
        $ekus = @($ekus | Where-Object { $_ } | Sort-Object -Unique)
        $hasNoEku = ($ekus.Count -eq 0)

        $authEkuNames = foreach ($oid in $ekus) {
            if ($AuthOids.ContainsKey([string]$oid)) { $AuthOids[[string]$oid] }
        }
        $authCapableOrAnyPurpose = ($hasNoEku -or @($authEkuNames).Count -gt 0)

        $enrollAllow = New-Object System.Collections.Generic.List[string]
        $autoEnrollAllow = New-Object System.Collections.Generic.List[string]
        $enrollDeny = New-Object System.Collections.Generic.List[string]
        $controlAllow = New-Object System.Collections.Generic.List[string]
        $controlAllowNonDefault = New-Object System.Collections.Generic.List[string]

        $acl = $de.ObjectSecurity
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
        foreach ($ace in $rules) {
            $principal = [string]$ace.IdentityReference.Value
            $rights = $ace.ActiveDirectoryRights
            $objType = $ace.ObjectType
            $isAllow = ($ace.AccessControlType -eq "Allow")
            $isDeny = ($ace.AccessControlType -eq "Deny")
            $hasExtendedRight = (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0)

            if ($hasExtendedRight) {
                if ($objType -eq $EnrollGuid -or $objType -eq $AllGuid) {
                    if ($isAllow) { $enrollAllow.Add($principal) }
                    if ($isDeny)  { $enrollDeny.Add($principal) }
                }
                if ($objType -eq $AutoEnrollGuid -or $objType -eq $AllGuid) {
                    if ($isAllow) { $autoEnrollAllow.Add($principal) }
                }
            }

            $dangerous =
                (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -ne 0) -or
                (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -ne 0) -or
                (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -ne 0) -or
                (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne 0)

            if ($isAllow -and $dangerous) {
                $controlAllow.Add("$principal [$rights]")
                if (-not (Test-DefaultControlPrincipal -Principal $principal)) {
                    $controlAllowNonDefault.Add("$principal [$rights]")
                }
            }
        }

        # ESC4: a non-default principal holds dangerous control over this template
        # and could rewrite it (e.g. add enrollee-supplies-subject + auth EKU) into
        # an ESC1-capable shape.
        $esc4Candidate = ($controlAllowNonDefault.Count -gt 0)

        $enrollAllowUnique = @($enrollAllow | Sort-Object -Unique)
        $broadEnroll = @($enrollAllowUnique | Where-Object { Test-BroadPrincipal $_ })

        $publishedCAs = @()
        if ($publishingMap.ContainsKey($cn)) {
            $publishedCAs = @($publishingMap[$cn] | Sort-Object -Unique)
        }
        $published = ($publishedCAs.Count -gt 0)

        $esc1AnyEnroll =
            $published -and $suppliesEither -and $authCapableOrAnyPurpose -and
            (-not $managerApprovalRequired) -and (-not $authorizedSignaturesRequired) -and
            ($enrollAllowUnique.Count -gt 0)

        $esc1BroadEnroll = $esc1AnyEnroll -and ($broadEnroll.Count -gt 0)

        [pscustomobject]@{
            TemplateName                    = $cn
            DisplayName                     = $displayName
            TemplateOID                     = $templateOid
            TemplateSchemaVersion           = $schemaVersion
            TemplateMinorRevision           = $minorRevision
            Published                       = $published
            PublishingCAs                   = Join-List $publishedCAs
            SubjectSuppliedByRequester      = $suppliesSubject
            SANSuppliedByRequester          = $suppliesSAN
            SubjectOrSANSuppliedByRequester = $suppliesEither
            NameFlagDecimal                 = $nameFlag
            NameFlagHex                     = ("0x{0:X8}" -f $nameFlag)
            EnrollmentFlagDecimal           = $enrollFlag
            EnrollmentFlagHex               = ("0x{0:X8}" -f $enrollFlag)
            ManagerApprovalRequired         = $managerApprovalRequired
            AuthorizedSignaturesRequired    = $authorizedSignaturesRequired
            RequiredSignatureCount          = $raSig
            AutoEnrollmentFlagSet           = $autoEnrollmentFlag
            NoSecurityExtension             = $noSecurityExtension
            EKU_OIDs                        = Join-List $ekus
            AuthEKUsMatched                 = Join-List $authEkuNames
            NoEKU                           = $hasNoEku
            AuthCapableOrAnyPurpose         = $authCapableOrAnyPurpose
            EnrollAllowPrincipals           = Join-List $enrollAllowUnique
            EnrollDenyPrincipals            = Join-List $enrollDeny
            AutoEnrollAllowPrincipals       = Join-List $autoEnrollAllow
            BroadEnrollPrincipals           = Join-List $broadEnroll
            DangerousControlAllowPrincipals = Join-List $controlAllow
            DangerousControlNonDefaultPrincipals = Join-List $controlAllowNonDefault
            ESC4Candidate                   = $esc4Candidate
            ESC1Candidate_AnyEnroll         = $esc1AnyEnroll
            ESC1Candidate_BroadEnroll       = $esc1BroadEnroll
            DistinguishedName               = [string]$de.distinguishedName
        }
    }

    $outFull = Resolve-OutPath -Path $OutCsv
    $results |
        Sort-Object ESC1Candidate_BroadEnroll, ESC1Candidate_AnyEnroll, Published, TemplateName -Descending |
        Export-Csv -Path $outFull -NoTypeInformation -Encoding UTF8

    Write-Host "Exported template inventory to $outFull"
    Write-Host "This file is UNSCRUBBED. Run the scrubber before uploading anywhere." -ForegroundColor Yellow
    return $outFull
}

# =====================================================================
# REGION: Stage 3b -- CA security descriptors + PKI object ACLs
#         Covers the permission-based ESCs that issuance logs cannot show:
#           * ESC7  -- Manage CA / Manage Certificates on the CA itself
#           * ESC5  -- dangerous control over CA / PKI AD objects
#           * ESC6  -- CA-wide EDITF_ATTRIBUTESUBJECTALTNAME2 confirmation
#           * ESC11 -- CA InterfaceFlags missing IF_ENFORCEENCRYPTICERTREQUEST
#                      (unencrypted ICertRequest RPC -> relay surface)
#           * KB5014754 -- per-DC StrongCertificateBindingEnforcement, which turns
#                      ESC9/ESC10 SID-extension findings from "candidate" into a
#                      confirmed (or mitigated) state.
#           * ESC8  -- web-enrollment endpoints (CES/CEP + legacy certsrv). The AD
#                      metadata (endpoint URI, auth type, HTTP vs HTTPS) is always
#                      collected; an OPT-IN active probe (-ProbeWebEnrollment) then
#                      makes a no-credential HTTP request to each endpoint to read
#                      its WWW-Authenticate schemes (NTLM/Negotiate) and confirm
#                      reachability -- the difference between "looks vulnerable" and
#                      "is reachable + offers NTLM". The probe makes outbound
#                      network connections to internal CA hosts, so it is OFF by
#                      default and must be explicitly requested.
# =====================================================================

function Invoke-ExportCaAndPkiSecurity {
    param(
        [Parameter(Mandatory)][string]$OutCaCsv,
        [Parameter(Mandatory)][string]$OutPkiAclCsv,
        [string]$OutDcEnforcementCsv,
        [string]$OutWebEnrollmentCsv,
        [switch]$ProbeWebEnrollment,
        [switch]$TestEpaBehavioral,
        [System.Management.Automation.PSCredential]$WebEnrollmentCredential,
        # Optional alternate credential for the remote DC reads (e.g. a Domain Admin that
        # differs from the account this is running under on the CA). Used by the
        # credential-aware transports (WinRM, WMI); when supplied they are tried first.
        [System.Management.Automation.PSCredential]$DCRemoteCredential,
        [string]$CAConfig
    )

    Write-Section "Stage 3b: CA security + PKI object ACLs (ESC5 / ESC7 / ESC6 / ESC11 / ESC8 / KB5014754)"

    # Leaf-name test for principals EXPECTED to hold powerful rights over CA / PKI
    # objects (tier-0 / PKI admins). Defined locally so this stage runs standalone.
    function Test-DefaultPkiPrincipal {
        param([string]$Principal)
        if ([string]::IsNullOrWhiteSpace($Principal)) { return $false }
        # SID-based check first: locale-proof and rename-proof. Falls back to leaf-name
        # match if the principal can't be translated to a SID.
        try {
            $sid = ([System.Security.Principal.NTAccount]$Principal).Translate([System.Security.Principal.SecurityIdentifier]).Value
            if (@('S-1-5-18','S-1-5-9','S-1-3-0','S-1-5-32-544') -contains $sid) { return $true }
            # Domain Admins 512, Enterprise Admins 519, Schema Admins 518, Cert Publishers
            # 517, Domain Controllers 516, RODCs 521, Key Admins 526, Enterprise Key Admins 527.
            if ($sid -match '-(512|519|518|517|516|521|526|527)$') { return $true }
        } catch { }
        $leaf = $Principal.Trim()
        if ($leaf -match '\\') { $leaf = ($leaf -split '\\')[-1] }
        $leaf = $leaf.Trim().ToLowerInvariant()
        $defaults = @(
            'domain admins', 'enterprise admins', 'schema admins',
            'administrators', 'system', 'local system', 'creator owner',
            'enterprise domain controllers', 'cert publishers'
        )
        return ($defaults -contains $leaf)
    }
    function Join-AclList {
        param($Items)
        $arr = @($Items | Where-Object { $_ -ne $null -and "$_".Trim() -ne "" } | Sort-Object -Unique)
        return ($arr -join "; ")
    }

    # ----------------------------------------------------------------
    # Part 1 -- per-CA security: ESC7 (Manage CA / Manage Certificates)
    #           and the ESC6 CA-config flag (EDITF_ATTRIBUTESUBJECTALTNAME2).
    # ----------------------------------------------------------------
    $caRecords = New-Object System.Collections.Generic.List[object]

    $caConfigs = @()
    if (-not [string]::IsNullOrWhiteSpace($CAConfig)) {
        $caConfigs = @([pscustomobject]@{ Config = ($CAConfig -replace '^[\s"'']+', '' -replace '[\s"'']+$', ''); CommonName = $null })
    }
    else {
        $caConfigs = @(Get-CAConfigList)
    }
    if ($caConfigs.Count -eq 0) {
        Write-Host "No CAs auto-detected." -ForegroundColor Yellow
        $manual = Read-DefaultString -Prompt "CA config string for CA security (blank to skip)" -Default ""
        if (-not [string]::IsNullOrWhiteSpace($manual)) {
            $caConfigs = @([pscustomobject]@{ Config = $manual; CommonName = $null })
        }
    }

    foreach ($ca in $caConfigs) {
        $cfg = [string]$ca.Config
        if ([string]::IsNullOrWhiteSpace($cfg)) { continue }
        $cn = [string]$ca.CommonName
        if ([string]::IsNullOrWhiteSpace($cn)) { $cn = ($cfg -split '\\')[-1] }

        Write-Host "[*] Collecting CA security for: $cfg"

        $manageCa   = New-Object System.Collections.Generic.List[string]
        $manageCert = New-Object System.Collections.Generic.List[string]
        $secSource  = "None"

        # ESC7 primary source: certutil -getreg CA\Security (human-readable ACL).
        $secText = $null
        try { $secText = (& certutil -config $cfg -getreg CA\Security 2>$null | Out-String) } catch { $secText = $null }

        if ($secText) {
            foreach ($line in ($secText -split "(`r`n|`n|`r)")) {
                $l = $line.Trim()
                if ($l -notmatch '(?i)^Allow') { continue }
                $hasManageCa   = ($l -match '(?i)Manage CA|CA Administrator')
                $hasManageCert = ($l -match '(?i)Manage Certificates|Certificate Manager')
                if (-not ($hasManageCa -or $hasManageCert)) { continue }
                # Trailing token after the rights phrase is the principal (DOMAIN\name).
                $principal = ($l -replace '(?i)^Allow\b', '').Trim()
                $principal = ($principal -replace '(?i).*(Manage CA|CA Administrator|Manage Certificates|Certificate Manager)[ ,]*', '').Trim()
                if ($principal) {
                    if ($hasManageCa)   { $manageCa.Add($principal) }
                    if ($hasManageCert) { $manageCert.Add($principal) }
                }
            }
            if (($manageCa.Count + $manageCert.Count) -gt 0) { $secSource = "certutil" }
        }

        # Fallback: ICertAdmin2.GetCASecurity returns the SD as SDDL.
        if (($manageCa.Count + $manageCert.Count) -eq 0) {
            try {
                $admin = New-Object -ComObject CertificateAuthority.Admin
                $sddl = [string]$admin.GetCASecurity($cfg)
                if ($sddl) {
                    $secSource = "COM/SDDL"
                    # CA access mask bits: Manage CA = 0x1, Manage Certificates = 0x2.
                    # SDDL ACE = (AceType;Flags;Rights;ObjGuid;InheritGuid;Sid).
                    foreach ($m in [regex]::Matches($sddl, '\(A;[^;]*;([0-9A-Fa-fx]+);[^;]*;[^;]*;([^)]+)\)')) {
                        $maskRaw = $m.Groups[1].Value
                        $sidStr  = $m.Groups[2].Value
                        $mask = 0
                        try { $mask = if ($maskRaw -match '^0x') { [Convert]::ToInt64($maskRaw, 16) } else { [int64]$maskRaw } } catch { $mask = 0 }
                        $name = $sidStr
                        try {
                            if ($sidStr -match '^S-1-') {
                                $name = (New-Object System.Security.Principal.SecurityIdentifier($sidStr)).Translate([System.Security.Principal.NTAccount]).Value
                            }
                        } catch { $name = $sidStr }
                        if (($mask -band 0x1) -ne 0) { $manageCa.Add($name) }
                        if (($mask -band 0x2) -ne 0) { $manageCert.Add($name) }
                    }
                }
            }
            catch {
                Write-Warning "Could not read CA security for $cfg (certutil and COM both failed): $($_.Exception.Message)"
            }
        }

        # ESC6 confirmation: policy\EditFlags -> EDITF_ATTRIBUTESUBJECTALTNAME2 (0x00040000).
        $editFlagsHex = $null
        $editfSan2 = $false
        try {
            $efText = (& certutil -config $cfg -getreg policy\EditFlags 2>$null | Out-String)
            if ($efText) {
                $editfSan2 = [bool]($efText -match '(?i)EDITF_ATTRIBUTESUBJECTALTNAME2')
                $mEf = [regex]::Match($efText, '(0x[0-9a-fA-F]{6,})')
                if ($mEf.Success) {
                    $editFlagsHex = $mEf.Groups[1].Value
                    if (-not $editfSan2) {
                        try { $editfSan2 = ((([Convert]::ToInt64($editFlagsHex, 16)) -band 0x00040000) -ne 0) } catch { }
                    }
                }
            }
        }
        catch { }

        # ESC11: CA\InterfaceFlags -> IF_ENFORCEENCRYPTICERTREQUEST (0x00000200).
        # When the flag is NOT set, the CA accepts unencrypted ICertRequest RPC,
        # which is relayable. ESC11Candidate = enforcement is OFF.
        $ifFlagsHex = $null
        $ifEnforceEncrypt = $false
        try {
            $ifText = (& certutil -config $cfg -getreg CA\InterfaceFlags 2>$null | Out-String)
            if ($ifText) {
                $ifEnforceEncrypt = [bool]($ifText -match '(?i)IF_ENFORCEENCRYPTICERTREQUEST')
                $mIf = [regex]::Match($ifText, '(0x[0-9a-fA-F]{6,})')
                if ($mIf.Success) {
                    $ifFlagsHex = $mIf.Groups[1].Value
                    if (-not $ifEnforceEncrypt) {
                        try { $ifEnforceEncrypt = ((([Convert]::ToInt64($ifFlagsHex, 16)) -band 0x00000200) -ne 0) } catch { }
                    }
                }
            }
        }
        catch { }
        # Only assert ESC11 when we actually read the flags; unknown -> not flagged.
        $esc11Candidate = ($null -ne $ifFlagsHex -and -not $ifEnforceEncrypt)

        $manageCaUnique   = @($manageCa   | Sort-Object -Unique)
        $manageCertUnique = @($manageCert | Sort-Object -Unique)
        $esc7Candidate = (
            @($manageCaUnique   | Where-Object { -not (Test-DefaultPkiPrincipal $_) }).Count -gt 0 -or
            @($manageCertUnique | Where-Object { -not (Test-DefaultPkiPrincipal $_) }).Count -gt 0
        )

        $caRecords.Add([pscustomobject]@{
            CA_Config                      = $cfg
            CA_CommonName                  = $cn
            ManageCAPrincipals             = Join-AclList $manageCaUnique
            ManageCertificatesPrincipals   = Join-AclList $manageCertUnique
            SecuritySource                 = $secSource
            EditFlagsHex                   = $editFlagsHex
            EditF_AttributeSubjectAltName2 = $editfSan2
            ESC6_CAConfigFlag              = $editfSan2
            InterfaceFlagsHex              = $ifFlagsHex
            IF_EnforceEncryptICertRequest  = $ifEnforceEncrypt
            ESC11Candidate                 = $esc11Candidate
            ESC7Candidate                  = $esc7Candidate
        })
    }

    $caOut = Resolve-OutPath -Path $OutCaCsv
    if ($caRecords.Count -gt 0) {
        $caRecords | Export-Csv -Path $caOut -NoTypeInformation -Encoding UTF8
        Write-Host "[+] CA security exported to $caOut  (rows: $($caRecords.Count))"
    }
    else {
        [pscustomobject]@{ Note = "No CA security collected (no CA config / no access)." } |
            Export-Csv -Path $caOut -NoTypeInformation -Encoding UTF8
        Write-Warning "No CA security rows collected."
    }

    # ----------------------------------------------------------------
    # Part 2 -- ESC5: dangerous control over CA / PKI AD objects.
    # ----------------------------------------------------------------
    $aclRecords = New-Object System.Collections.Generic.List[object]
    try {
        $rootDse = [ADSI]"LDAP://RootDSE"
        $configNC = [string]$rootDse.configurationNamingContext
        $defaultNC = [string]$rootDse.defaultNamingContext
        $pkiBase = "CN=Public Key Services,CN=Services,$configNC"

        # Resolve a CA host's computer-account SID from its DNS name, so the CA's OWN
        # machine account holding control over its OWN CA object can be recognised as
        # expected (not an ESC5 finding) -- precisely, by SID, scoped to that object.
        $caObjHostSid = @{}   # EnrollmentServiceCA object DN -> owning host computer SID
        function Get-ComputerSidByDns {
            param([string]$Dns, [string]$DefNC)
            if ([string]::IsNullOrWhiteSpace($Dns) -or [string]::IsNullOrWhiteSpace($DefNC)) { return $null }
            try {
                $s = New-Object System.DirectoryServices.DirectorySearcher(
                    [ADSI]("LDAP://$DefNC"), "(&(objectCategory=computer)(dNSHostName=$Dns))", @("objectSid"))
                $r = $s.FindOne()
                if ($r -and $r.Properties["objectsid"].Count -gt 0) {
                    return (New-Object System.Security.Principal.SecurityIdentifier($r.Properties["objectsid"][0], 0)).Value
                }
            } catch { }
            return $null
        }

        $targets = @(
            @{ Type = "PublicKeyServicesContainer";       Dn = $pkiBase },
            @{ Type = "EnrollmentServicesContainer";      Dn = "CN=Enrollment Services,$pkiBase" },
            @{ Type = "CertificationAuthoritiesContainer"; Dn = "CN=Certification Authorities,$pkiBase" },
            @{ Type = "NTAuthCertificates";               Dn = "CN=NTAuthCertificates,$pkiBase" },
            @{ Type = "AIAContainer";                     Dn = "CN=AIA,$pkiBase" },
            @{ Type = "KRAContainer";                     Dn = "CN=KRA,$pkiBase" },
            @{ Type = "OIDContainer";                     Dn = "CN=OID,$pkiBase" },
            @{ Type = "CertificateTemplatesContainer";    Dn = "CN=Certificate Templates,$pkiBase" }
        )
        # Each enrollment-service (CA) object individually.
        try {
            $esBase = [ADSI]("LDAP://CN=Enrollment Services,$pkiBase")
            foreach ($child in $esBase.Children) {
                $childDn = [string]$child.distinguishedName
                if ($childDn) {
                    $targets += @{ Type = "EnrollmentServiceCA"; Dn = $childDn }
                    # Map this CA object to its host's computer-account SID (if resolvable).
                    $caHostDns = [string]$child.dNSHostName
                    if ($caHostDns) {
                        $hsid = Get-ComputerSidByDns -Dns $caHostDns -DefNC $defaultNC
                        if ($hsid) { $caObjHostSid[$childDn] = $hsid }
                    }
                }
            }
        }
        catch { }

        $dangerousRights =
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll -bor
            [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor
            [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner -bor
            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty

        # Well-known control-access-right GUIDs so an ExtendedRight ACE can be named
        # precisely (Enroll vs AutoEnroll vs all-extended-rights) instead of being
        # exported as the generic token "ExtendedRight" -- which forces the analyst to
        # guess which right Authenticated Users (etc.) actually hold.
        $EnrollGuid     = [Guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
        $AutoEnrollGuid = [Guid]"a05b8cc2-17bc-4802-a710-e7c15ab866a2"
        $AllGuid        = [Guid]"00000000-0000-0000-0000-000000000000"
        function Resolve-AceRight {
            param($Ace)
            $r       = $Ace.ActiveDirectoryRights
            $objType = $Ace.ObjectType
            $isExt   = (($r -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0)
            if ($isExt) {
                if     ($objType -eq $EnrollGuid)     { return "Enroll" }
                elseif ($objType -eq $AutoEnrollGuid) { return "AutoEnroll" }
                elseif ($objType -eq $AllGuid)        { return "All-ExtendedRights" }
                else                                  { return "ExtendedRight:$objType" }
            }
            if ($objType -and $objType -ne $AllGuid)  { return "Scoped:$objType" }
            return "Generic"
        }

        $tIdx = 0; $tTot = @($targets).Count
        foreach ($t in $targets) {
            $tIdx++
            Write-Progress -Activity "Stage 3b: PKI object ACLs (ESC5)" -Status "$($t.Type) ($tIdx of $tTot)" -PercentComplete ([int](($tIdx / [math]::Max($tTot,1)) * 100))
            $dn = [string]$t.Dn
            if ([string]::IsNullOrWhiteSpace($dn)) { continue }
            $entry = $null
            try { $entry = [ADSI]("LDAP://$dn") } catch { continue }
            if (-not $entry -or -not $entry.distinguishedName) { continue }

            $acl = $null
            try { $acl = $entry.ObjectSecurity } catch { $acl = $null }
            if (-not $acl) { continue }

            $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
            foreach ($ace in $rules) {
                if ($ace.AccessControlType -ne "Allow") { continue }
                $rights     = $ace.ActiveDirectoryRights
                $hasControl = (($rights -band $dangerousRights) -ne 0)
                $hasExt     = (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0)
                # Keep dangerous CONTROL rights (the ESC5 signal) AND ExtendedRight ACEs
                # (so Enroll / AutoEnroll on CA objects are recorded with their resolved
                # name instead of being dropped or guessed at). Pure read ACEs are skipped.
                if (-not ($hasControl -or $hasExt)) { continue }
                $principal     = [string]$ace.IdentityReference.Value
                $isDefault     = Test-DefaultPkiPrincipal -Principal $principal
                # Is this the CA's OWN host computer account holding rights on its OWN CA
                # object? A CA managing its own enrollment-service object is expected, so it
                # is recognised (by SID, scoped to that object) and excluded from ESC5 --
                # but the same account on NTAuth / templates container etc. is NOT suppressed.
                $isCaHost      = $false
                $ownerHostSid  = $caObjHostSid[[string]$entry.distinguishedName]
                if ($ownerHostSid) {
                    try {
                        $pSid = ([System.Security.Principal.NTAccount]$principal).Translate([System.Security.Principal.SecurityIdentifier]).Value
                        $isCaHost = ($pSid -eq $ownerHostSid)
                    } catch { }
                }
                $resolved      = Resolve-AceRight -Ace $ace
                $objTypeGuid   = if ($ace.ObjectType -and $ace.ObjectType -ne $AllGuid) { [string]$ace.ObjectType } else { "" }
                $rightCategory = if ($hasControl) { "Control" } elseif ($hasExt) { "ExtendedRight" } else { "Other" }
                $isEnrollRight = ($resolved -eq "Enroll" -or $resolved -eq "AutoEnroll" -or $resolved -eq "All-ExtendedRights")
                $aclRecords.Add([pscustomobject]@{
                    PkiObjectType           = [string]$t.Type
                    ObjectDistinguishedName = [string]$entry.distinguishedName
                    Principal               = $principal
                    Rights                  = [string]$rights
                    ObjectTypeGuid          = $objTypeGuid
                    ResolvedRight           = $resolved
                    RightCategory           = $rightCategory
                    IsEnrollRight           = $isEnrollRight
                    AccessType              = "Allow"
                    IsDangerous             = $hasControl
                    IsDefaultPrincipal      = $isDefault
                    IsCAHostAccount         = $isCaHost
                    # ESC5 is dangerous CONTROL by a non-default principal -- an Enroll/
                    # AutoEnroll extended right is an enrolment-scope amplifier, not control,
                    # and the CA's own host account on its own CA object is expected; both are
                    # recorded but no longer mis-flagged as ESC5.
                    ESC5Candidate           = ($hasControl -and -not $isDefault -and -not $isCaHost)
                })
            }
        }
    }
    catch {
        Write-Warning "PKI object ACL enumeration failed: $($_.Exception.Message)"
    }
    Write-Progress -Activity "Stage 3b: PKI object ACLs (ESC5)" -Completed

    $aclOut = Resolve-OutPath -Path $OutPkiAclCsv
    if ($aclRecords.Count -gt 0) {
        $aclRecords |
            Sort-Object ESC5Candidate, PkiObjectType -Descending |
            Export-Csv -Path $aclOut -NoTypeInformation -Encoding UTF8
        Write-Host "[+] PKI object ACLs exported to $aclOut  (rows: $($aclRecords.Count))"
    }
    else {
        [pscustomobject]@{ Note = "No dangerous PKI object ACEs found (or no access)." } |
            Export-Csv -Path $aclOut -NoTypeInformation -Encoding UTF8
        Write-Warning "No PKI object ACL rows collected."
    }

    # ----------------------------------------------------------------
    # Part 3 -- KB5014754: per-DC StrongCertificateBindingEnforcement.
    #           This is what decides whether a missing / mismatched SID security
    #           extension (ESC9/ESC10) is actually exploitable: with Full
    #           enforcement (2) the DC rejects weak mappings; Compatibility (1) and
    #           Disabled (0) leave them abusable. Read read-only over remote registry.
    # ----------------------------------------------------------------
    $dcOut = $null
    if (-not [string]::IsNullOrWhiteSpace($OutDcEnforcementCsv)) {
        $dcRecords = New-Object System.Collections.Generic.List[object]
        try {
            $rootDse2 = [ADSI]"LDAP://RootDSE"
            $defaultNC = [string]$rootDse2.defaultNamingContext
            $dcSearcher = New-Object System.DirectoryServices.DirectorySearcher(
                [ADSI]("LDAP://$defaultNC"),
                "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                @("dNSHostName", "cn")
            )
            $dcSearcher.PageSize = 1000
            $dcHosts = @()
            foreach ($res in $dcSearcher.FindAll()) {
                $h = $null
                if ($res.Properties.Contains("dnshostname") -and $res.Properties["dnshostname"].Count -gt 0) { $h = [string]$res.Properties["dnshostname"][0] }
                elseif ($res.Properties.Contains("cn") -and $res.Properties["cn"].Count -gt 0) { $h = [string]$res.Properties["cn"][0] }
                if ($h -and ($dcHosts -notcontains $h)) { $dcHosts += $h }
            }

            function Get-EnforcementLabel {
                param($Value)
                switch ([string]$Value) {
                    '0'     { return "Disabled (0) -- weak mappings accepted" }
                    '1'     { return "Compatibility (1) -- weak mappings logged but allowed" }
                    '2'     { return "Full enforcement (2) -- weak mappings rejected" }
                    default { return "Unknown / not set (defaults to Compatibility on patched DCs)" }
                }
            }

            $kdcRegPath = 'SYSTEM\CurrentControlSet\Services\Kdc'
            $sbeName    = 'StrongCertificateBindingEnforcement'

            # --- Read methods, each independent of the others' transport. ---
            # 1) Remote registry (RemoteRegistry service).
            function Read-SbeRemoteReg {
                param([string]$Dc)
                $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Dc)
                try { $k=$base.OpenSubKey($kdcRegPath); if ($k){ $v=$k.GetValue($sbeName); $k.Close(); return $v } return $null }
                finally { $base.Close() }
            }
            # 2) WinRM (PowerShell Remoting) -- reads the local registry ON the DC.
            function Read-SbeWinRM {
                param([string]$Dc, [System.Management.Automation.PSCredential]$Cred)
                $p = @{ ComputerName = $Dc; ErrorAction = 'Stop' }
                if ($Cred) { $p['Credential'] = $Cred }   # WinRM honors alternate creds natively
                return Invoke-Command @p -ScriptBlock {
                    (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'StrongCertificateBindingEnforcement' -ErrorAction SilentlyContinue).StrongCertificateBindingEnforcement
                }
            }
            # 3) WMI StdRegProv (WMI/DCOM) -- different transport again.
            function Read-SbeWmi {
                param([string]$Dc, [System.Management.Automation.PSCredential]$Cred)
                $HKLM=[uint32]2147483650
                $argz = @{ hDefKey=$HKLM; sSubKeyName=$kdcRegPath; sValueName=$sbeName }
                # Force the DCOM (RPC) transport -- NOT WSMan/WinRM. New-CimSession and
                # Invoke-CimMethod default to WinRM, so without this the "WMI" method rides the
                # same WinRM channel and fails identically when WinRM is blocked (which is the
                # common case on hardened DCs). DCOM uses RPC (TCP 135 + dynamic) and is a
                # genuinely independent transport; it also accepts an alternate -Credential.
                $opt = New-CimSessionOption -Protocol Dcom
                $csParams = @{ ComputerName = $Dc; SessionOption = $opt; ErrorAction = 'Stop' }
                if ($Cred) { $csParams['Credential'] = $Cred }
                $cs = New-CimSession @csParams
                try {
                    $r = Invoke-CimMethod -CimSession $cs -Namespace 'root\default' -ClassName 'StdRegProv' `
                            -MethodName 'GetDWORDValue' -Arguments $argz -ErrorAction Stop
                } finally { Remove-CimSession $cs -ErrorAction SilentlyContinue }
                if ($r.ReturnValue -eq 0) { return $r.uValue }
                return $null
            }

            # Domain-wide SYSVOL fallback: the value as DEPLOYED by Group Policy
            # Preferences (intended config, readable by any authenticated user even
            # when live remote reads are blocked). Computed once and reused.
            $sysvolSbe = $null
            try {
                $dnsDomain = (($defaultNC -split ',' | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_.Substring(3) }) -join '.')
                if ($dnsDomain) {
                    $polRoot = "\\$dnsDomain\SYSVOL\$dnsDomain\Policies"
                    if (Test-Path $polRoot) {
                        Write-Progress -Activity "Stage 3b: DC strong-mapping enforcement (KB5014754)" -Status "Scanning Group Policy (SYSVOL) for the intended value..."
                        foreach ($rx in (Get-ChildItem -Path $polRoot -Recurse -Filter 'Registry.xml' -ErrorAction SilentlyContinue)) {
                            try {
                                [xml]$xml = Get-Content -Path $rx.FullName -ErrorAction SilentlyContinue
                                $node = $xml.SelectNodes("//Registry[Properties[@name='$sbeName']]") | Select-Object -First 1
                                if ($node) { $sysvolSbe = [string]$node.Properties.value; break }
                            } catch { }
                        }
                    }
                }
            } catch { }

            $dcIdx = 0; $dcTot = @($dcHosts).Count
            foreach ($dc in $dcHosts) {
                $dcIdx++
                $sbe = $null; $status = "Unreadable"; $source = "None"
                $methodNotes = New-Object System.Collections.Generic.List[string]
                # With an alternate credential, try the credential-aware transports (WinRM,
                # WMI) FIRST -- RemoteRegistry's OpenRemoteBaseKey can't take a credential, so
                # it runs under the current (CA-logon) context and is kept only as a fallback.
                $dcMethods = if ($DCRemoteCredential) {
                    # Credentialed RPC/DCOM first (works even when WinRM is blocked and the
                    # current logon is denied), then credentialed WinRM, then RemoteRegistry
                    # (current context -- can't take a credential).
                    @(
                        @{ n="WMI/DCOM(cred)";   f={ Read-SbeWmi       -Dc $dc -Cred $DCRemoteCredential } },
                        @{ n="WinRM(cred)";      f={ Read-SbeWinRM     -Dc $dc -Cred $DCRemoteCredential } },
                        @{ n="RemoteRegistry";   f={ Read-SbeRemoteReg -Dc $dc } }
                    )
                } else {
                    @(
                        @{ n="RemoteRegistry"; f={ Read-SbeRemoteReg -Dc $dc } },
                        @{ n="WMI/DCOM";       f={ Read-SbeWmi       -Dc $dc } },
                        @{ n="WinRM";          f={ Read-SbeWinRM     -Dc $dc } }
                    )
                }
                foreach ($m in $dcMethods) {
                    Write-Progress -Activity "Stage 3b: DC strong-mapping enforcement (KB5014754)" `
                        -Status "DC $dcIdx of $dcTot ($dc) -- trying $($m.n) (each method can wait on a timeout)..." `
                        -PercentComplete ([int](($dcIdx / [math]::Max($dcTot,1)) * 100))
                    try {
                        $val = & $m.f
                        # 0 is a VALID value (Disabled) -- accept any non-null result.
                        if ($null -ne $val) {
                            $sbe=$val; $status="OK"; $source=$m.n
                            $methodNotes.Add("$($m.n)=OK($val)")
                            break
                        }
                        $methodNotes.Add("$($m.n)=no-value")
                    } catch {
                        $em = $_.Exception.Message
                        $short = if ($em.Length -gt 90) { $em.Substring(0,90) + "..." } else { $em }
                        $methodNotes.Add("$($m.n)=ERR:$short")
                        Write-Host "    [-] $dc : $($m.n) failed -- $em" -ForegroundColor DarkYellow
                    }
                }
                if ($null -ne $sbe) {
                    Write-Host "    [+] $dc : live read via $source (StrongCertificateBindingEnforcement=$sbe)." -ForegroundColor DarkGreen
                }
                elseif ($null -ne $sysvolSbe) {
                    $sbe=$sysvolSbe; $status="GPO intended (not live)"; $source="SYSVOL/GPP"
                    Write-Host "    [i] $dc : all live reads failed -- falling back to SYSVOL/GPP intended value ($sbe). This is the value GPO INTENDS to deploy, not a confirmed live read." -ForegroundColor Yellow
                }
                else {
                    $status="All remote methods blocked"
                    Write-Host "    [!] $dc : unreadable -- all live methods failed and no SYSVOL/GPP value found." -ForegroundColor Red
                }

                $dcRecords.Add([pscustomobject]@{
                    DC_DnsHostName                      = $dc
                    StrongCertificateBindingEnforcement = $sbe
                    EnforcementLevel                    = (Get-EnforcementLabel $sbe)
                    FullEnforcement                     = ([string]$sbe -eq '2')
                    ReadStatus                          = $status
                    ReadMethod                          = $source
                    ReadDetail                          = ($methodNotes -join '; ')
                })
            }
            Write-Progress -Activity "Stage 3b: DC strong-mapping enforcement (KB5014754)" -Completed

            # Read-method summary so the analyst can see, at a glance, whether the values
            # are confirmed live reads or only the GPO-intended SYSVOL/GPP fallback.
            # Any successful read method (RemoteRegistry / WinRM / WMI-DCOM, with or without
            # a credential) counts as live; only SYSVOL/GPP and None are non-live.
            $liveCount = @($dcRecords | Where-Object { $_.ReadMethod -ne 'SYSVOL/GPP' -and $_.ReadMethod -ne 'None' }).Count
            $gppCount  = @($dcRecords | Where-Object { $_.ReadMethod -eq 'SYSVOL/GPP' }).Count
            $deadCount = @($dcRecords | Where-Object { $_.ReadMethod -eq 'None' }).Count
            Write-Host ("[i] DC strong-mapping read summary: {0} live, {1} SYSVOL/GPP (intended, not live), {2} unreadable -- of {3} DCs." -f $liveCount, $gppCount, $deadCount, $dcRecords.Count) -ForegroundColor Cyan
            if ($liveCount -eq 0 -and $dcRecords.Count -gt 0) {
                Write-Host "    [!] NO live reads succeeded -- every value is GPO-intended, not confirmed. Typical causes:" -ForegroundColor Yellow
                Write-Host "        - RemoteRegistry service stopped on the DCs (start it, or it is disabled by policy)" -ForegroundColor Yellow
                Write-Host "        - WinRM/PowerShell Remoting not enabled (Enable-PSRemoting on the DCs)" -ForegroundColor Yellow
                Write-Host "        - Host firewall blocking RPC (445/135) or WinRM (5985) from this host" -ForegroundColor Yellow
                Write-Host "        See the ReadDetail column for the exact per-method error on each DC." -ForegroundColor Yellow
            }
            if (@($dcRecords | Where-Object { $_.ReadMethod -eq 'None' }).Count -gt 0) {
                Write-Host "    To read the value locally on a DC, run there:" -ForegroundColor Yellow
                Write-Host "    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' StrongCertificateBindingEnforcement).StrongCertificateBindingEnforcement" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Warning "DC enforcement enumeration failed: $($_.Exception.Message)"
        }

        $dcOut = Resolve-OutPath -Path $OutDcEnforcementCsv
        if ($dcRecords.Count -gt 0) {
            $dcRecords | Export-Csv -Path $dcOut -NoTypeInformation -Encoding UTF8
            Write-Host "[+] DC enforcement exported to $dcOut  (rows: $($dcRecords.Count))"
        }
        else {
            [pscustomobject]@{ Note = "No domain controllers enumerated / no registry access." } |
                Export-Csv -Path $dcOut -NoTypeInformation -Encoding UTF8
            Write-Warning "No DC enforcement rows collected."
        }
    }

    # ----------------------------------------------------------------
    # Part 4 -- ESC8: web-enrollment (CES/CEP + legacy certsrv) surface.
    #           Metadata is always collected; the active probe is opt-in.
    # ----------------------------------------------------------------
    $webOut = $null
    if (-not [string]::IsNullOrWhiteSpace($OutWebEnrollmentCsv)) {

        function Convert-CesAuth {
            param($Code)
            switch ([string]$Code) {
                '1'     { return "Kerberos" }
                '2'     { return "UsernamePassword" }
                '4'     { return "ClientCertificate" }
                '8'     { return "Anonymous" }
                default { return "Unknown($Code)" }
            }
        }

        # No-credential probe: read WWW-Authenticate schemes + reachability without
        # ever sending credentials. TLS validation is bypassed because we only read
        # headers from internal CA hosts whose certs may not chain in this context.
        function Test-WebEnrollmentEndpoint {
            param([Parameter(Mandatory)][string]$Url)
            $out = [pscustomobject]@{ Reachable = $false; HttpStatus = $null; AuthSchemes = @(); Ntlm = $false }
            $origCb = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
            try {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($a, $b, $c, $d) $true }
                $req = [System.Net.HttpWebRequest]::Create($Url)
                $req.Method = "GET"
                $req.Timeout = 7000
                $req.AllowAutoRedirect = $false
                $req.UseDefaultCredentials = $false
                $resp = $null
                try {
                    $resp = $req.GetResponse()
                    $out.Reachable = $true
                    try { $out.HttpStatus = [int]$resp.StatusCode } catch { }
                    # Some endpoints answer 200/redirect to an unauthenticated GET; still read
                    # WWW-Authenticate so a Negotiate/NTLM offer is not missed on the non-401 path.
                    try {
                        $authHeader = [string]$resp.Headers["WWW-Authenticate"]
                        if (-not [string]::IsNullOrWhiteSpace($authHeader)) {
                            $out.AuthSchemes = @($authHeader -split ',' | ForEach-Object { ($_.Trim() -split '\s+')[0] } | Where-Object { $_ } | Sort-Object -Unique)
                            $out.Ntlm = [bool]($authHeader -match '(?i)NTLM|Negotiate')
                        }
                    } catch { }
                }
                catch [System.Net.WebException] {
                    $hr = $_.Exception.Response
                    if ($hr) {
                        $out.Reachable = $true
                        try { $out.HttpStatus = [int]$hr.StatusCode } catch { }
                        $authHeader = $null
                        try { $authHeader = [string]$hr.Headers["WWW-Authenticate"] } catch { }
                        if (-not [string]::IsNullOrWhiteSpace($authHeader)) {
                            $out.AuthSchemes = @($authHeader -split ',' | ForEach-Object { ($_.Trim() -split '\s+')[0] } | Where-Object { $_ } | Sort-Object -Unique)
                            $out.Ntlm = [bool]($authHeader -match '(?i)NTLM|Negotiate')
                        }
                        try { $hr.Close() } catch { }
                    }
                }
                finally {
                    if ($resp) { try { $resp.Close() } catch { } }
                }
            }
            catch { }
            finally {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $origCb
            }
            return $out
        }

        # Extended Protection for Authentication (EPA) is the channel-binding control
        # that defeats NTLM relay to an HTTPS endpoint -- but it CANNOT be seen from an
        # unauthenticated header probe (it is validated during the auth exchange). The
        # deterministic check is the IIS Windows-Auth `extendedProtection tokenChecking`
        # setting. Try WinRM (WebAdministration) first, then read applicationHost.config
        # over the admin share. Returns None/Allow/Require/Unknown + the source.
        # NOTE: both methods require LOCAL ADMIN on the web host (WebAdministration /
        # IIS:\ provider, and the C$ admin share). In a tiered environment where the
        # auditing account only holds CA-service rights, this returns
        # TokenChecking="Unknown" / Source="Unreadable (needs host admin)" -- which keeps
        # the endpoint at ESC8NeedsEpaCheck (never falsely mitigated). EPA confirmation is
        # then a task for whoever administers the web host's OS.
        function Get-WebEnrollmentEpa {
            param([Parameter(Mandatory)][string]$HostName)
            $out = [pscustomobject]@{ TokenChecking = "Unknown"; Source = "Unreadable (needs host admin)"; Detail = "" }
            $rank = @{ 'None' = 0; 'Allow' = 1; 'Require' = 2 }   # report the WEAKEST setting (conservative)
            # 1) WinRM + WebAdministration: read tokenChecking on the CertSrv app (the relay
            #    target) and the site. Requires local admin on the web host -- which the CA-host
            #    admin running this DOES have for the issuing CA's own certsrv.
            try {
                $vals = Invoke-Command -ComputerName $HostName -ErrorAction Stop -ScriptBlock {
                    Import-Module WebAdministration -ErrorAction SilentlyContinue
                    $v = @()
                    foreach ($site in @('IIS:\Sites\Default Web Site\CertSrv','IIS:\Sites\Default Web Site')) {
                        try {
                            $p = Get-WebConfigurationProperty -PSPath $site `
                                 -Filter 'system.webServer/security/authentication/windowsAuthentication/extendedProtection' `
                                 -Name 'tokenChecking' -ErrorAction SilentlyContinue
                            if ($p -and $p.Value) { $v += [string]$p.Value }
                        } catch { }
                    }
                    ,$v
                }
                if ($vals -and @($vals).Count -gt 0) {
                    $weakest = (@($vals) | Sort-Object { $rank[[string]$_] } | Select-Object -First 1)
                    $out.TokenChecking = [string]$weakest
                    $out.Source        = "WinRM/IIS"
                    $out.Detail        = "WinRM/IIS tokenChecking: " + ((@($vals) | Sort-Object -Unique) -join ',')
                    return $out
                }
                # WinRM worked but no explicit extendedProtection -> IIS default is None (EPA off).
                $out.TokenChecking = "None"
                $out.Source        = "WinRM/IIS (default)"
                $out.Detail        = "WinRM connected; CertSrv/site have no explicit extendedProtection -> IIS default None"
                Write-Host "    [i] EPA on $HostName : WinRM OK, CertSrv has no extendedProtection -> default None (no channel binding -- HTTPS+NTLM is relayable)." -ForegroundColor DarkYellow
                return $out
            }
            catch {
                $out.Detail = "WinRM/IIS: $($_.Exception.Message)"
                Write-Host "    [-] EPA via WinRM/IIS on $HostName failed -- $($_.Exception.Message)" -ForegroundColor DarkYellow
            }
            # 2) Fallback: parse applicationHost.config over the C$ admin share (config read, no test).
            try {
                $cfg = "\\$HostName\C`$\Windows\System32\inetsrv\config\applicationHost.config"
                if (Test-Path $cfg) {
                    [xml]$x = Get-Content -Path $cfg -ErrorAction SilentlyContinue
                    $nodes = @($x.SelectNodes("//windowsAuthentication/extendedProtection") | Where-Object { $_.tokenChecking })
                    if ($nodes.Count -gt 0) {
                        $tcs = @($nodes | ForEach-Object { [string]$_.tokenChecking })
                        $weakest = ($tcs | Sort-Object { $rank[$_] } | Select-Object -First 1)
                        $out.TokenChecking = [string]$weakest; $out.Source = "applicationHost.config"
                        $out.Detail = "applicationHost.config tokenChecking: " + (($tcs | Sort-Object -Unique) -join ',')
                    }
                    elseif (@($x.SelectNodes("//windowsAuthentication")).Count -gt 0) {
                        $out.TokenChecking = "None"; $out.Source = "applicationHost.config (default)"
                        $out.Detail = "windowsAuthentication present, no extendedProtection -> default None"
                    }
                    else { $out.Detail += " | applicationHost.config: no windowsAuthentication section found" }
                }
                else {
                    $out.Detail += " | C`$ share: applicationHost.config not reachable"
                    Write-Host "    [-] EPA via C`$ share on $HostName failed -- \\$HostName\C`$ applicationHost.config not reachable." -ForegroundColor DarkYellow
                }
            }
            catch {
                $out.Detail += " | C`$ share: $($_.Exception.Message)"
                Write-Host "    [-] EPA via C`$ share on $HostName failed -- $($_.Exception.Message)" -ForegroundColor DarkYellow
            }
            if ($out.TokenChecking -eq "Unknown") {
                Write-Host "    [!] EPA on $HostName : could not be read by any method (need local admin on the web host). Endpoint stays ESC8NeedsEpaCheck." -ForegroundColor Yellow
            }
            return $out
        }

        # ---- EXPERIMENTAL: behavioral EPA probe (opt-in, -TestEpaBehavioral) ----
        # Authenticates to the HTTPS endpoint as the supplied account TWICE on fresh
        # connections: once WITH the TLS channel-binding token (CBT) and once WITHOUT.
        #   * with-CBT succeeds + without-CBT rejected (401)  => EPA Required (mitigated)
        #   * both succeed                                    => EPA off / Allow (relayable)
        #   * anything else / any error                      => Inconclusive (never "Require")
        # No coercion, no relay -- two ordinary logons to your own endpoint as yourself.
        # This is hand-rolled SSPI over a raw TLS socket and is UNTESTED in this build;
        # validate against a known endpoint before trusting it. The conservative verdict
        # means a bug degrades to ESC8NeedsEpaCheck, never to a false "mitigated".
        $epaProbeCSharp = @'
using System;
using System.IO;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Text;
public static class EpaProbe {
  const int SECBUFFER_TOKEN=2, SECBUFFER_CHANNEL_BINDINGS=14, SECPKG_CRED_OUTBOUND=2;
  const uint ISC_REQ_CONNECTION=0x800, ISC_REQ_ALLOCATE_MEMORY=0x100;
  const int SEC_E_OK=0; const int SEC_I_CONTINUE_NEEDED=unchecked((int)0x00090312);
  [StructLayout(LayoutKind.Sequential)] struct HANDLE { public IntPtr l; public IntPtr u; }
  [StructLayout(LayoutKind.Sequential)] struct TS { public uint lo; public int hi; }
  [StructLayout(LayoutKind.Sequential)] struct SecBuffer { public int cb; public int type; public IntPtr buf; }
  [StructLayout(LayoutKind.Sequential)] struct SecBufferDesc { public int ver; public int c; public IntPtr buffers; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct AuthId {
    public string User; public int UserLen; public string Domain; public int DomLen;
    public string Pass; public int PassLen; public int Flags; }
  [DllImport("secur32.dll", CharSet=CharSet.Unicode)] static extern int AcquireCredentialsHandle(
    string pr, string pkg, int use, IntPtr lg, ref AuthId auth, IntPtr gk, IntPtr ga, ref HANDLE cred, ref TS exp);
  [DllImport("secur32.dll", CharSet=CharSet.Unicode)] static extern int InitializeSecurityContext(
    ref HANDLE cred, IntPtr ctxIn, string tgt, uint f, int r, int drep, IntPtr inDesc, int r2,
    ref HANDLE ctxOut, ref SecBufferDesc outDesc, ref uint attr, ref TS exp);
  [DllImport("secur32.dll", CharSet=CharSet.Unicode)] static extern int InitializeSecurityContext(
    ref HANDLE cred, ref HANDLE ctxIn, string tgt, uint f, int r, int drep, ref SecBufferDesc inDesc, int r2,
    ref HANDLE ctxOut, ref SecBufferDesc outDesc, ref uint attr, ref TS exp);
  [DllImport("secur32.dll")] static extern int FreeContextBuffer(IntPtr p);
  [DllImport("secur32.dll")] static extern int DeleteSecurityContext(ref HANDLE c);
  [DllImport("secur32.dll")] static extern int FreeCredentialsHandle(ref HANDLE c);

  static byte[] CbtAppData(X509Certificate cert) {
    byte[] der = cert.GetRawCertData();
    byte[] hash = SHA256.Create().ComputeHash(der); // tls-server-end-point (SHA-256 default)
    byte[] pre = Encoding.ASCII.GetBytes("tls-server-end-point:");
    byte[] app = new byte[pre.Length + hash.Length];
    Buffer.BlockCopy(pre,0,app,0,pre.Length); Buffer.BlockCopy(hash,0,app,pre.Length,hash.Length);
    // SEC_CHANNEL_BINDINGS: 8 ULONGs (32 bytes) header, appData appended.
    byte[] blob = new byte[32 + app.Length];
    BitConverter.GetBytes((uint)app.Length).CopyTo(blob,24); // cbApplicationDataLength
    BitConverter.GetBytes((uint)32).CopyTo(blob,28);         // dwApplicationDataOffset
    Buffer.BlockCopy(app,0,blob,32,app.Length);
    return blob;
  }
  static string ReadResp(SslStream s, out int code) {
    code=0; var sb=new StringBuilder(); var buf=new byte[1]; int prev=0; string www=null;
    var hdr=new StringBuilder();
    while (true){ int n=s.Read(buf,0,1); if(n<=0) break; hdr.Append((char)buf[0]);
      if(hdr.Length>=4 && hdr[hdr.Length-1]=='\n'&&hdr[hdr.Length-2]=='\r'&&hdr[hdr.Length-3]=='\n'&&hdr[hdr.Length-4]=='\r') break;
      if(hdr.Length>200000) break; }
    string h=hdr.ToString(); string[] lines=h.Split('\n');
    if(lines.Length>0){ var p=lines[0].Split(' '); if(p.Length>1) int.TryParse(p[1].Trim(), out code); }
    int clen=0;
    foreach(var l in lines){ var t=l.Trim();
      if(t.ToLower().StartsWith("www-authenticate:") && t.ToLower().Contains("ntlm")) www=t.Substring(t.ToLower().IndexOf("ntlm")+4).Trim();
      if(t.ToLower().StartsWith("content-length:")) int.TryParse(t.Substring(15).Trim(), out clen); }
    if(clen>0){ var body=new byte[clen]; int got=0; while(got<clen){ int n=s.Read(body,got,clen-got); if(n<=0)break; got+=n; } }
    return www;
  }
  // Returns final HTTP status using NTLM, optionally with CBT. -1 on transport error.
  static int NtlmAuth(string host, int port, string path, string dom, string usr, string pwd, bool withCbt, int timeoutMs) {
    HANDLE cred=new HANDLE(), ctx=new HANDLE(); TS exp=new TS(); uint attr=0; bool haveCred=false, haveCtx=false;
    TcpClient tcp=null; SslStream ssl=null;
    try {
      tcp=new TcpClient(); var ar=tcp.BeginConnect(host,port,null,null); if(!ar.AsyncWaitHandle.WaitOne(timeoutMs)) return -1; tcp.EndConnect(ar);
      ssl=new SslStream(tcp.GetStream(), false, delegate { return true; });
      ssl.AuthenticateAsClient(host); ssl.ReadTimeout=timeoutMs; ssl.WriteTimeout=timeoutMs;
      byte[] cbt = withCbt ? CbtAppData(ssl.RemoteCertificate) : null;
      var id=new AuthId{ User=usr, UserLen=(usr??"").Length, Domain=dom, DomLen=(dom??"").Length, Pass=pwd, PassLen=(pwd??"").Length, Flags=2 };
      if(AcquireCredentialsHandle(null,"NTLM",SECPKG_CRED_OUTBOUND,IntPtr.Zero,ref id,IntPtr.Zero,IntPtr.Zero,ref cred,ref exp)!=SEC_E_OK) return -1;
      haveCred=true;
      uint flags=ISC_REQ_CONNECTION|ISC_REQ_ALLOCATE_MEMORY;
      // Type 1
      var outB=new SecBuffer{cb=0,type=SECBUFFER_TOKEN,buf=IntPtr.Zero};
      IntPtr pOut=Marshal.AllocHGlobal(Marshal.SizeOf(outB)); Marshal.StructureToPtr(outB,pOut,false);
      var outD=new SecBufferDesc{ver=0,c=1,buffers=pOut};
      int rc=InitializeSecurityContext(ref cred,IntPtr.Zero,"HTTP/"+host,flags,0,0,IntPtr.Zero,0,ref ctx,ref outD,ref attr,ref exp);
      haveCtx=true; if(rc!=SEC_I_CONTINUE_NEEDED && rc!=SEC_E_OK) return -1;
      var ob=(SecBuffer)Marshal.PtrToStructure(pOut,typeof(SecBuffer)); byte[] t1=new byte[ob.cb]; if(ob.cb>0) Marshal.Copy(ob.buf,t1,0,ob.cb);
      if(ob.buf!=IntPtr.Zero) FreeContextBuffer(ob.buf); Marshal.FreeHGlobal(pOut);
      // send GET + type1
      SendGet(ssl,host,path,Convert.ToBase64String(t1));
      int code; string chal=ReadResp(ssl,out code);
      if(chal==null) return code; // server didn't challenge NTLM
      byte[] t2=Convert.FromBase64String(chal);
      // Type 3 (with optional CBT)
      IntPtr pT2=Marshal.AllocHGlobal(t2.Length); Marshal.Copy(t2,0,pT2,t2.Length);
      int nbuf = withCbt?2:1;
      IntPtr arr=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecBuffer))*nbuf);
      var sbTok=new SecBuffer{cb=t2.Length,type=SECBUFFER_TOKEN,buf=pT2};
      Marshal.StructureToPtr(sbTok,arr,false);
      IntPtr pCbt=IntPtr.Zero;
      if(withCbt){ pCbt=Marshal.AllocHGlobal(cbt.Length); Marshal.Copy(cbt,0,pCbt,cbt.Length);
        var sbCbt=new SecBuffer{cb=cbt.Length,type=SECBUFFER_CHANNEL_BINDINGS,buf=pCbt};
        Marshal.StructureToPtr(sbCbt,(IntPtr)(arr.ToInt64()+Marshal.SizeOf(typeof(SecBuffer))),false); }
      var inD=new SecBufferDesc{ver=0,c=nbuf,buffers=arr};
      var outB2=new SecBuffer{cb=0,type=SECBUFFER_TOKEN,buf=IntPtr.Zero};
      IntPtr pOut2=Marshal.AllocHGlobal(Marshal.SizeOf(outB2)); Marshal.StructureToPtr(outB2,pOut2,false);
      var outD2=new SecBufferDesc{ver=0,c=1,buffers=pOut2};
      int rc2=InitializeSecurityContext(ref cred,ref ctx,"HTTP/"+host,flags,0,0,ref inD,0,ref ctx,ref outD2,ref attr,ref exp);
      var ob2=(SecBuffer)Marshal.PtrToStructure(pOut2,typeof(SecBuffer)); byte[] t3=new byte[ob2.cb]; if(ob2.cb>0) Marshal.Copy(ob2.buf,t3,0,ob2.cb);
      if(ob2.buf!=IntPtr.Zero) FreeContextBuffer(ob2.buf);
      Marshal.FreeHGlobal(pOut2); Marshal.FreeHGlobal(pT2); Marshal.FreeHGlobal(arr); if(pCbt!=IntPtr.Zero) Marshal.FreeHGlobal(pCbt);
      if(rc2!=SEC_E_OK && rc2!=SEC_I_CONTINUE_NEEDED) return -1;
      SendGet(ssl,host,path,Convert.ToBase64String(t3));
      int code2; ReadResp(ssl,out code2);
      return code2;
    } catch { return -1; }
    finally { if(haveCtx) DeleteSecurityContext(ref ctx); if(haveCred) FreeCredentialsHandle(ref cred);
      if(ssl!=null) ssl.Dispose(); if(tcp!=null) tcp.Close(); }
  }
  static void SendGet(SslStream s, string host, string path, string ntlm){
    string req="GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: keep-alive\r\nAuthorization: NTLM "+ntlm+"\r\n\r\n";
    byte[] b=Encoding.ASCII.GetBytes(req); s.Write(b,0,b.Length); s.Flush();
  }
  public static string Check(string host, int port, string path, string dom, string usr, string pwd, int timeoutMs){
    int withCbt=NtlmAuth(host,port,path,dom,usr,pwd,true,timeoutMs);
    int noCbt =NtlmAuth(host,port,path,dom,usr,pwd,false,timeoutMs);
    // Success = not 401/403 and a real status (2xx/30x). NTLM accept usually 200.
    bool okWith = withCbt>=200 && withCbt<400;
    bool okNo   = noCbt>=200 && noCbt<400;
    if(!okWith) return "INCONCLUSIVE(withCBT="+withCbt+",noCBT="+noCbt+" - check creds/reachability)";
    if(okWith && !okNo && (noCbt==401||noCbt==403)) return "REQUIRE(withCBT="+withCbt+",noCBT="+noCbt+")";
    if(okWith && okNo) return "OFF(withCBT="+withCbt+",noCBT="+noCbt+")";
    return "INCONCLUSIVE(withCBT="+withCbt+",noCBT="+noCbt+")";
  }
}
'@
        function Test-EpaBehavioral {
            param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential)
            $res = [pscustomobject]@{ TokenChecking = "Unknown"; Source = "BehavioralProbe (inconclusive)"; Detail = "" }
            try {
                if (-not ([System.Management.Automation.PSTypeName]'EpaProbe').Type) {
                    Add-Type -TypeDefinition $epaProbeCSharp -ErrorAction Stop
                }
                $u = [uri]$Url
                $port = if ($u.Port -gt 0) { $u.Port } else { 443 }
                $nc = $Credential.GetNetworkCredential()
                $verdict = [EpaProbe]::Check($u.Host, $port, $u.AbsolutePath, $nc.Domain, $nc.UserName, $nc.Password, 8000)
                $res.Detail = [string]$verdict
                if ($verdict -match '^REQUIRE') { $res.TokenChecking = "Require"; $res.Source = "BehavioralProbe" }
                elseif ($verdict -match '^OFF')  { $res.TokenChecking = "None";    $res.Source = "BehavioralProbe" }
            }
            catch { $res.Detail = "probe error: $($_.Exception.Message)" }
            return $res
        }

        $webRecords = New-Object System.Collections.Generic.List[object]
        $epaByHost = @{}   # host -> EPA result, computed at most once per host

        # EPA dispatcher: behavioral probe first (if opted in + credential), else the
        # admin-only IIS config read. Result cached per host.
        function Resolve-Epa {
            param([string]$HostName, [string]$Url)
            if ($epaByHost.ContainsKey($HostName)) { return $epaByHost[$HostName] }
            $r = $null
            if ($TestEpaBehavioral -and $WebEnrollmentCredential -and -not [string]::IsNullOrWhiteSpace($Url)) {
                Write-Progress -Activity "Stage 3b: web-enrollment probe (ESC8)" -Status "Behavioral EPA test on $HostName (two TLS logons; may take a few seconds)..."
                $b = Test-EpaBehavioral -Url $Url -Credential $WebEnrollmentCredential
                if ($b.TokenChecking -ne "Unknown") { $r = $b }
            }
            if (-not $r) {
                Write-Progress -Activity "Stage 3b: web-enrollment probe (ESC8)" -Status "Reading EPA config on $HostName..."
                $r = Get-WebEnrollmentEpa -HostName $HostName
            }
            $epaByHost[$HostName] = $r
            return $r
        }
        $caHosts = New-Object System.Collections.Generic.List[string]
        try {
            $rootDse3 = [ADSI]"LDAP://RootDSE"
            $cfgNc = [string]$rootDse3.configurationNamingContext
            $esContainer = [ADSI]("LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfgNc")
            $esSearcher = New-Object System.DirectoryServices.DirectorySearcher($esContainer)
            $esSearcher.Filter = "(objectClass=pKIEnrollmentService)"
            $esSearcher.PageSize = 1000
            foreach ($p in @("cn", "dNSHostName", "msPKI-Enrollment-Servers")) { [void]$esSearcher.PropertiesToLoad.Add($p) }

            foreach ($es in $esSearcher.FindAll()) {
                $caCn = ""
                if ($es.Properties.Contains("cn") -and $es.Properties["cn"].Count -gt 0) { $caCn = [string]$es.Properties["cn"][0] }
                $caHost = ""
                if ($es.Properties.Contains("dnshostname") -and $es.Properties["dnshostname"].Count -gt 0) { $caHost = [string]$es.Properties["dnshostname"][0] }
                if ($caHost -and -not $caHosts.Contains($caHost)) { $caHosts.Add($caHost) }

                # CES endpoints from msPKI-Enrollment-Servers (authoritative metadata).
                $cesValues = @()
                if ($es.Properties.Contains("mspki-enrollment-servers")) { $cesValues = @($es.Properties["mspki-enrollment-servers"]) }
                foreach ($raw in $cesValues) {
                    $val = [string]$raw
                    $uri = $null
                    $mUri = [regex]::Match($val, '(?i)(https?://\S+)')
                    if ($mUri.Success) { $uri = ($mUri.Groups[1].Value -replace '[\\\s]+$', '') }
                    $authCode = $null
                    $mAuth = [regex]::Match($val, '^\s*\d+\D+(\d+)')
                    if ($mAuth.Success) { $authCode = $mAuth.Groups[1].Value }
                    if (-not $uri) { continue }
                    $isHttp = ($uri -match '(?i)^http://')
                    $epHost = $uri
                    try { $epHost = ([uri]$uri).Host } catch { }

                    $rec = [ordered]@{
                        CA_CommonName        = $caCn
                        EndpointKind         = "CES"
                        EndpointHostName     = $epHost
                        Scheme               = $(if ($isHttp) { "http" } else { "https" })
                        IsHttp               = $isHttp
                        AuthFromMetadata     = (Convert-CesAuth $authCode)
                        Probed               = $false
                        Reachable            = $null
                        HttpStatus           = $null
                        AuthSchemesOffered   = ""
                        NtlmOffered          = $null
                        EpaTokenChecking     = "Unknown"
                        EpaSource            = "None"
                        EpaDetail            = ""
                        Esc8RiskFromMetadata = [bool]$isHttp
                        ESC8Confirmed        = $false
                        ESC8NeedsEpaCheck    = $false
                        ESC8Mitigated        = $false
                    }
                    if ($ProbeWebEnrollment) {
                        Write-Progress -Activity "Stage 3b: web-enrollment probe (ESC8)" -Status "Probing CES endpoint on $epHost..."
                        $pr = Test-WebEnrollmentEndpoint -Url $uri
                        $rec.Probed = $true
                        $rec.Reachable = $pr.Reachable
                        $rec.HttpStatus = $pr.HttpStatus
                        $rec.AuthSchemesOffered = (($pr.AuthSchemes) -join "; ")
                        $rec.NtlmOffered = $pr.Ntlm
                        # HTTP + NTLM is relayable regardless of EPA (no TLS to bind to).
                        $rec.ESC8Confirmed = [bool]($pr.Reachable -and $pr.Ntlm -and $isHttp)
                        # HTTPS: read EPA whenever the endpoint is reachable (authoritative and
                        # cheap when we have host admin) so EpaTokenChecking is populated even if
                        # the header probe did not surface NTLM. Relay risk applies only when
                        # NTLM/Negotiate is actually offered; EPA Required closes it.
                        if (-not $isHttp -and $pr.Reachable) {
                            $epa = Resolve-Epa -HostName $epHost -Url $uri
                            $rec.EpaTokenChecking = $epa.TokenChecking
                            $rec.EpaSource = $epa.Source
                            $rec.EpaDetail = $epa.Detail
                            $mit = ($epa.TokenChecking -match '(?i)Require')
                            $rec.ESC8Mitigated = [bool]($pr.Ntlm -and $mit)
                            $rec.ESC8NeedsEpaCheck = [bool]($pr.Ntlm -and -not $mit)
                        }
                    }
                    $webRecords.Add([pscustomobject]$rec)
                }
            }
        }
        catch {
            Write-Warning "Web-enrollment metadata enumeration failed: $($_.Exception.Message)"
        }

        # Legacy certsrv web enrollment is not published in AD, so it can only be
        # confirmed by probing. Only emit those rows when probing is enabled.
        if ($ProbeWebEnrollment) {
            $hIdx = 0; $hTot = @($caHosts).Count
            foreach ($h in $caHosts) {
                $hIdx++
                foreach ($scheme in @("http", "https")) {
                    $url = "$scheme`://$h/certsrv/"
                    $isHttp = ($scheme -eq "http")
                    Write-Progress -Activity "Stage 3b: web-enrollment probe (ESC8)" -Status "Probing $scheme certsrv on host $hIdx of $hTot..." -PercentComplete ([int](($hIdx / [math]::Max($hTot,1)) * 100))
                    $pr = Test-WebEnrollmentEndpoint -Url $url
                    if (-not $pr.Reachable) { continue }   # don't list dead legacy URLs
                    $epaTc = "Unknown"; $epaSrc = "None"; $epaDetail = ""; $epaMit = $false; $needsEpa = $false
                    if (-not $isHttp -and $pr.Reachable) {
                        $epa = Resolve-Epa -HostName $h -Url $url
                        $epaTc = $epa.TokenChecking; $epaSrc = $epa.Source; $epaDetail = $epa.Detail
                        $epaMit = ($pr.Ntlm -and ($epa.TokenChecking -match '(?i)Require'))
                        $needsEpa = ($pr.Ntlm -and -not ($epa.TokenChecking -match '(?i)Require'))
                    }
                    $webRecords.Add([pscustomobject]@{
                        CA_CommonName        = ""
                        EndpointKind         = "WebEnrollment(certsrv)"
                        EndpointHostName     = $h
                        Scheme               = $scheme
                        IsHttp               = $isHttp
                        AuthFromMetadata     = "Unknown(probe)"
                        Probed               = $true
                        Reachable            = $pr.Reachable
                        HttpStatus           = $pr.HttpStatus
                        AuthSchemesOffered   = (($pr.AuthSchemes) -join "; ")
                        NtlmOffered          = $pr.Ntlm
                        EpaTokenChecking     = $epaTc
                        EpaSource            = $epaSrc
                        EpaDetail            = $epaDetail
                        Esc8RiskFromMetadata = [bool]$isHttp
                        ESC8Confirmed        = [bool]($pr.Reachable -and $pr.Ntlm -and $isHttp)
                        ESC8NeedsEpaCheck    = [bool]$needsEpa
                        ESC8Mitigated        = [bool]$epaMit
                    })
                }
            }
        }
        Write-Progress -Activity "Stage 3b: web-enrollment probe (ESC8)" -Completed

        $webOut = Resolve-OutPath -Path $OutWebEnrollmentCsv
        if ($webRecords.Count -gt 0) {
            $webRecords |
                Sort-Object ESC8Confirmed, Esc8RiskFromMetadata -Descending |
                Export-Csv -Path $webOut -NoTypeInformation -Encoding UTF8
            Write-Host "[+] Web-enrollment surface exported to $webOut  (rows: $($webRecords.Count); probe: $([bool]$ProbeWebEnrollment))"
        }
        else {
            [pscustomobject]@{ Note = "No web-enrollment endpoints found in AD metadata$(if (-not $ProbeWebEnrollment) { ' (probe disabled)' })." } |
                Export-Csv -Path $webOut -NoTypeInformation -Encoding UTF8
            Write-Warning "No web-enrollment endpoints collected."
        }
    }

    Write-Host "These files are UNSCRUBBED. Run the scrubber before uploading anywhere." -ForegroundColor Yellow
    return [pscustomobject]@{ CaCsv = $caOut; PkiAclCsv = $aclOut; DcCsv = $dcOut; WebCsv = $webOut }
}

# =====================================================================
# REGION: Stage 4 -- Build identity token map + high-value target file
# =====================================================================

function Invoke-BuildTokenMap {
    param(
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [string]$HighValueTargetsCsv,
        [switch]$SkipComputers,
        [string[]]$AdditionalBroadPrincipalNames = @()
    )

    Write-Section "Stage 4: Build identity token map + high-value targets"

    # Ensure the salt exists before we start hashing.
    [void](Get-SessionSalt)

    Add-Type -AssemblyName System.DirectoryServices

    function Convert-ObjectSidToString {
        param([Parameter(Mandatory)]$ObjectSid)
        [byte[]]$sidByteArray = @($ObjectSid | ForEach-Object { [byte]$_ })
        $sid = [System.Security.Principal.SecurityIdentifier]::new($sidByteArray, 0)
        return $sid.Value
    }

    function Get-AdLdapSingle {
        param([Parameter(Mandatory)]$SearchResult, [Parameter(Mandatory)][string]$Name)
        if ($SearchResult.Properties.Contains($Name) -and $SearchResult.Properties[$Name].Count -gt 0) {
            return $SearchResult.Properties[$Name][0]
        }
        return $null
    }

    function Get-AdLdapMulti {
        param([Parameter(Mandatory)]$SearchResult, [Parameter(Mandatory)][string]$Name)
        if ($SearchResult.Properties.Contains($Name) -and $SearchResult.Properties[$Name].Count -gt 0) {
            return @($SearchResult.Properties[$Name])
        }
        return @()
    }

    function Get-LdapFilterEscaped {
        param([string]$Value)
        if ($null -eq $Value) { return "" }
        $escaped = $Value
        $escaped = $escaped.Replace('\', '\5c')
        $escaped = $escaped.Replace('*', '\2a')
        $escaped = $escaped.Replace('(', '\28')
        $escaped = $escaped.Replace(')', '\29')
        $escaped = $escaped -replace "`0", "\00"
        return $escaped
    }

    function New-LdapSearcher {
        param(
            [Parameter(Mandatory)][string]$SearchBase,
            [Parameter(Mandatory)][string]$Filter,
            [string[]]$Properties = @()
        )
        $entry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$SearchBase")
        $searcher = [System.DirectoryServices.DirectorySearcher]::new($entry)
        $searcher.Filter = $Filter
        $searcher.PageSize = 1000
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        foreach ($prop in $Properties) { [void]$searcher.PropertiesToLoad.Add($prop) }
        return $searcher
    }

    function Get-DomainInfo {
        $rootDse = [ADSI]"LDAP://RootDSE"
        $defaultNC = [string]$rootDse.defaultNamingContext
        $configNC = [string]$rootDse.configurationNamingContext
        $dnsName = ($defaultNC -split "," | Where-Object { $_ -like "DC=*" } | ForEach-Object { $_.Substring(3) }) -join "."
        $netbios = $null
        try {
            $escapedNC = Get-LdapFilterEscaped -Value $defaultNC
            $searcher = New-LdapSearcher -SearchBase $configNC -Filter "(&(objectClass=crossRef)(nCName=$escapedNC)(nETBIOSName=*))" -Properties @("nETBIOSName")
            $result = $searcher.FindOne()
            if ($result) { $netbios = [string](Get-AdLdapSingle -SearchResult $result -Name "nETBIOSName") }
        }
        catch { $netbios = $null }
        if (-not $netbios) { $netbios = ($dnsName -split "\.")[0].ToUpperInvariant() }
        return [pscustomobject]@{
            DefaultNamingContext       = $defaultNC
            ConfigurationNamingContext = $configNC
            DnsName                    = $dnsName
            NetBIOSName                = $netbios
        }
    }

    function Get-CanonicalKnownLabelByObject {
        param([string]$Value, [string]$Sid, [string]$ObjectType)
        $simple = $null
        if ($Value) {
            $trimmed = $Value.Trim()
            if     ($trimmed -match '^CN=([^,]+),') { $simple = $matches[1] }
            elseif ($trimmed -match '\\')           { $simple = ($trimmed -split '\\')[-1] }
            else                                    { $simple = $trimmed }
            $simple = $simple.Trim()
        }
        $simpleLower = if ($simple) { $simple.ToLowerInvariant() } else { "" }

        switch -Regex ($Sid) {
            '^S-1-1-0$'      { return "BROAD_EVERYONE" }
            '^S-1-5-11$'     { return "BROAD_AUTHENTICATED_USERS" }
            '^S-1-5-32-545$' { return "BROAD_BUILTIN_USERS" }
            '^S-1-5-32-544$' { return "HV_GROUP_BUILTIN_ADMINISTRATORS" }
            '^S-1-5-32-548$' { return "HV_GROUP_ACCOUNT_OPERATORS" }
            '^S-1-5-32-549$' { return "HV_GROUP_SERVER_OPERATORS" }
            '^S-1-5-32-550$' { return "HV_GROUP_PRINT_OPERATORS" }
            '^S-1-5-32-551$' { return "HV_GROUP_BACKUP_OPERATORS" }
            '-512$'          { if ($ObjectType -eq "Group") { return "HV_GROUP_DOMAIN_ADMINS" } }
            '-513$'          { if ($ObjectType -eq "Group") { return "BROAD_DOMAIN_USERS" } }
            '-515$'          { if ($ObjectType -eq "Group") { return "BROAD_DOMAIN_COMPUTERS" } }
            '-516$'          { if ($ObjectType -eq "Group") { return "HV_GROUP_DOMAIN_CONTROLLERS" } }
            '-517$'          { if ($ObjectType -eq "Group") { return "ADCS_GROUP_CERT_PUBLISHERS" } }
            '-518$'          { if ($ObjectType -eq "Group") { return "HV_GROUP_SCHEMA_ADMINS" } }
            '-519$'          { if ($ObjectType -eq "Group") { return "HV_GROUP_ENTERPRISE_ADMINS" } }
            '-520$'          { if ($ObjectType -eq "Group") { return "HV_GROUP_GROUP_POLICY_CREATOR_OWNERS" } }
            '-526$'          { if ($ObjectType -eq "Group") { return "HV_GROUP_KEY_ADMINS" } }
            '-527$'          { if ($ObjectType -eq "Group") { return "HV_GROUP_ENTERPRISE_KEY_ADMINS" } }
        }

        switch ($simpleLower) {
            "everyone"                      { return "BROAD_EVERYONE" }
            "authenticated users"           { return "BROAD_AUTHENTICATED_USERS" }
            "domain users"                  { return "BROAD_DOMAIN_USERS" }
            "domain computers"              { return "BROAD_DOMAIN_COMPUTERS" }
            "users"                         { return "BROAD_BUILTIN_USERS" }
            "builtin\users"                 { return "BROAD_BUILTIN_USERS" }
            "administrators"                { return "HV_GROUP_BUILTIN_ADMINISTRATORS" }
            "builtin\administrators"        { return "HV_GROUP_BUILTIN_ADMINISTRATORS" }
            "domain admins"                 { return "HV_GROUP_DOMAIN_ADMINS" }
            "enterprise admins"             { return "HV_GROUP_ENTERPRISE_ADMINS" }
            "schema admins"                 { return "HV_GROUP_SCHEMA_ADMINS" }
            "account operators"             { return "HV_GROUP_ACCOUNT_OPERATORS" }
            "server operators"              { return "HV_GROUP_SERVER_OPERATORS" }
            "print operators"               { return "HV_GROUP_PRINT_OPERATORS" }
            "backup operators"              { return "HV_GROUP_BACKUP_OPERATORS" }
            "domain controllers"            { return "HV_GROUP_DOMAIN_CONTROLLERS" }
            "enterprise domain controllers" { return "HV_GROUP_ENTERPRISE_DOMAIN_CONTROLLERS" }
            "group policy creator owners"   { return "HV_GROUP_GROUP_POLICY_CREATOR_OWNERS" }
            "key admins"                    { return "HV_GROUP_KEY_ADMINS" }
            "enterprise key admins"         { return "HV_GROUP_ENTERPRISE_KEY_ADMINS" }
            "dnsadmins"                     { return "HV_GROUP_DNSADMINS" }
            "cert publishers"               { return "ADCS_GROUP_CERT_PUBLISHERS" }
        }
        return $null
    }

    function Get-ObjectTypeFromSearchResult {
        param($SearchResult)
        $classes = @(Get-AdLdapMulti -SearchResult $SearchResult -Name "objectClass" | ForEach-Object { "$_".ToLowerInvariant() })
        if ($classes -contains "group")    { return "Group" }
        if ($classes -contains "computer") { return "Computer" }
        if ($classes -contains "user")     { return "User" }
        return "Object"
    }

    $domain = Get-DomainInfo
    Write-Host "Default NC: $($domain.DefaultNamingContext)"
    Write-Host "DNS domain: $($domain.DnsName)"
    Write-Host "NetBIOS:    $($domain.NetBIOSName)"

    $TokenMapRows  = New-Object System.Collections.Generic.List[object]
    $HighValueRows = New-Object System.Collections.Generic.List[object]
    $SeenTokenKeys = @{}
    $HighValueBySid = @{}

    function Add-HighValueReason {
        param([Parameter(Mandatory)][string]$Sid, [Parameter(Mandatory)][string]$Reason)
        $key = $Sid.ToLowerInvariant()
        if (-not $HighValueBySid.ContainsKey($key)) {
            $HighValueBySid[$key] = New-Object System.Collections.Generic.List[string]
        }
        if (-not $HighValueBySid[$key].Contains($Reason)) {
            $HighValueBySid[$key].Add($Reason)
        }
    }

    function Add-TokenMapping {
        param(
            [string]$InputValue, [string]$Token, [string]$TokenType,
            [bool]$IsHighValue, [string]$HighValueReason, [string]$KnownLabel, [string]$Source
        )
        if ([string]::IsNullOrWhiteSpace($InputValue) -or [string]::IsNullOrWhiteSpace($Token)) { return }
        $norm = Normalize-TokenKey -Value $InputValue
        if (-not $norm) { return }
        if ($SeenTokenKeys.ContainsKey($norm)) { return }
        $SeenTokenKeys[$norm] = $true
        $TokenMapRows.Add([pscustomobject]@{
            InputValue      = $InputValue
            NormalizedValue = $norm
            Token           = $Token
            TokenType       = $TokenType
            IsHighValue     = $IsHighValue
            HighValueReason = $HighValueReason
            KnownLabel      = $KnownLabel
            Source          = $Source
        })
    }

    $staticKnown = @(
        @{ Input = "Everyone"; Token = "BROAD_EVERYONE"; Type = "BroadGroup"; HV = $false; Reason = ""; Label = "BROAD_EVERYONE" },
        @{ Input = "NT AUTHORITY\Authenticated Users"; Token = "BROAD_AUTHENTICATED_USERS"; Type = "BroadGroup"; HV = $false; Reason = ""; Label = "BROAD_AUTHENTICATED_USERS" },
        @{ Input = "Authenticated Users"; Token = "BROAD_AUTHENTICATED_USERS"; Type = "BroadGroup"; HV = $false; Reason = ""; Label = "BROAD_AUTHENTICATED_USERS" },
        @{ Input = "$($domain.NetBIOSName)\Domain Users"; Token = "BROAD_DOMAIN_USERS"; Type = "BroadGroup"; HV = $false; Reason = ""; Label = "BROAD_DOMAIN_USERS" },
        @{ Input = "Domain Users"; Token = "BROAD_DOMAIN_USERS"; Type = "BroadGroup"; HV = $false; Reason = ""; Label = "BROAD_DOMAIN_USERS" },
        @{ Input = "$($domain.NetBIOSName)\Domain Computers"; Token = "BROAD_DOMAIN_COMPUTERS"; Type = "BroadGroup"; HV = $false; Reason = ""; Label = "BROAD_DOMAIN_COMPUTERS" },
        @{ Input = "Domain Computers"; Token = "BROAD_DOMAIN_COMPUTERS"; Type = "BroadGroup"; HV = $false; Reason = ""; Label = "BROAD_DOMAIN_COMPUTERS" },
        @{ Input = "BUILTIN\Users"; Token = "BROAD_BUILTIN_USERS"; Type = "BroadGroup"; HV = $false; Reason = ""; Label = "BROAD_BUILTIN_USERS" },
        @{ Input = "Users"; Token = "BROAD_BUILTIN_USERS"; Type = "BroadGroup"; HV = $false; Reason = ""; Label = "BROAD_BUILTIN_USERS" },
        @{ Input = "BUILTIN\Administrators"; Token = "HV_GROUP_BUILTIN_ADMINISTRATORS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_BUILTIN_ADMINISTRATORS" },
        @{ Input = "Administrators"; Token = "HV_GROUP_BUILTIN_ADMINISTRATORS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_BUILTIN_ADMINISTRATORS" },
        @{ Input = "$($domain.NetBIOSName)\Domain Admins"; Token = "HV_GROUP_DOMAIN_ADMINS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_DOMAIN_ADMINS" },
        @{ Input = "Domain Admins"; Token = "HV_GROUP_DOMAIN_ADMINS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_DOMAIN_ADMINS" },
        @{ Input = "Enterprise Admins"; Token = "HV_GROUP_ENTERPRISE_ADMINS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_ENTERPRISE_ADMINS" },
        @{ Input = "Schema Admins"; Token = "HV_GROUP_SCHEMA_ADMINS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_SCHEMA_ADMINS" },
        @{ Input = "Account Operators"; Token = "HV_GROUP_ACCOUNT_OPERATORS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_ACCOUNT_OPERATORS" },
        @{ Input = "Server Operators"; Token = "HV_GROUP_SERVER_OPERATORS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_SERVER_OPERATORS" },
        @{ Input = "Print Operators"; Token = "HV_GROUP_PRINT_OPERATORS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_PRINT_OPERATORS" },
        @{ Input = "Backup Operators"; Token = "HV_GROUP_BACKUP_OPERATORS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_BACKUP_OPERATORS" },
        @{ Input = "Domain Controllers"; Token = "HV_GROUP_DOMAIN_CONTROLLERS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_DOMAIN_CONTROLLERS" },
        @{ Input = "Enterprise Domain Controllers"; Token = "HV_GROUP_ENTERPRISE_DOMAIN_CONTROLLERS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_ENTERPRISE_DOMAIN_CONTROLLERS" },
        @{ Input = "Group Policy Creator Owners"; Token = "HV_GROUP_GROUP_POLICY_CREATOR_OWNERS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_GROUP_POLICY_CREATOR_OWNERS" },
        @{ Input = "Key Admins"; Token = "HV_GROUP_KEY_ADMINS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_KEY_ADMINS" },
        @{ Input = "Enterprise Key Admins"; Token = "HV_GROUP_ENTERPRISE_KEY_ADMINS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_ENTERPRISE_KEY_ADMINS" },
        @{ Input = "DnsAdmins"; Token = "HV_GROUP_DNSADMINS"; Type = "PrivilegedGroup"; HV = $true; Reason = "Default privileged group"; Label = "HV_GROUP_DNSADMINS" },
        @{ Input = "Cert Publishers"; Token = "ADCS_GROUP_CERT_PUBLISHERS"; Type = "ADCSGroup"; HV = $false; Reason = ""; Label = "ADCS_GROUP_CERT_PUBLISHERS" }
    )

    foreach ($broadName in $AdditionalBroadPrincipalNames) {
        if (-not [string]::IsNullOrWhiteSpace($broadName)) {
            $staticKnown += @{ Input = $broadName; Token = "BROAD_DOMAIN_USERS"; Type = "BroadGroup"; HV = $false; Reason = "Configured broad enrollment group"; Label = "BROAD_DOMAIN_USERS" }
        }
    }

    foreach ($item in $staticKnown) {
        Add-TokenMapping -InputValue $item.Input -Token $item.Token -TokenType $item.Type -IsHighValue $item.HV -HighValueReason $item.Reason -KnownLabel $item.Label -Source "StaticKnownPrincipal"
    }

    $highValueGroupNames = @(
        "Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Account Operators", "Server Operators", "Print Operators", "Backup Operators",
        "Domain Controllers", "Enterprise Domain Controllers", "Group Policy Creator Owners",
        "Key Admins", "Enterprise Key Admins", "DnsAdmins"
    )

    $highValueGroupDns = New-Object System.Collections.Generic.List[string]
    Write-Host "Discovering default privileged groups..."
    foreach ($groupName in $highValueGroupNames) {
        $escaped = Get-LdapFilterEscaped -Value $groupName
        $filter = "(&(objectCategory=group)(|(cn=$escaped)(sAMAccountName=$escaped)))"
        $searcher = New-LdapSearcher -SearchBase $domain.DefaultNamingContext -Filter $filter -Properties @("distinguishedName", "objectSid", "cn", "sAMAccountName", "objectClass")
        foreach ($result in $searcher.FindAll()) {
            $dn = [string](Get-AdLdapSingle -SearchResult $result -Name "distinguishedName")
            $sidBytes = Get-AdLdapSingle -SearchResult $result -Name "objectSid"
            if (-not $dn -or -not $sidBytes) { continue }
            $sid = Convert-ObjectSidToString -ObjectSid $sidBytes
            Add-HighValueReason -Sid $sid -Reason "Default privileged group: $groupName"
            if (-not $highValueGroupDns.Contains($dn)) { $highValueGroupDns.Add($dn) }
        }
    }

    Write-Host "Discovering recursive members of privileged groups..."
    foreach ($groupDn in $highValueGroupDns) {
        $escapedGroupDn = Get-LdapFilterEscaped -Value $groupDn
        $filter = "(&(objectClass=*)(memberOf:1.2.840.113556.1.4.1941:=$escapedGroupDn))"
        $props = @("distinguishedName", "objectSid", "objectClass", "sAMAccountName", "cn", "userPrincipalName", "dNSHostName", "mail", "proxyAddresses", "name", "userAccountControl")
        $searcher = New-LdapSearcher -SearchBase $domain.DefaultNamingContext -Filter $filter -Properties $props
        foreach ($result in $searcher.FindAll()) {
            $sidBytes = Get-AdLdapSingle -SearchResult $result -Name "objectSid"
            if (-not $sidBytes) { continue }
            $sid = Convert-ObjectSidToString -ObjectSid $sidBytes
            Add-HighValueReason -Sid $sid -Reason "Recursive member of privileged group"
        }
    }

    Write-Host "Enumerating AD users, groups, and computers..."
    $filterParts = @(
        "(&(objectCategory=person)(objectClass=user))",
        "(objectCategory=group)"
    )
    if (-not $SkipComputers) { $filterParts += "(objectCategory=computer)" }

    $objectFilter = "(|$($filterParts -join ''))"
    $props = @(
        "distinguishedName", "objectSid", "objectClass", "sAMAccountName", "cn", "name",
        "userPrincipalName", "mail", "proxyAddresses", "dNSHostName", "servicePrincipalName", "userAccountControl"
    )
    $identitySearcher = New-LdapSearcher -SearchBase $domain.DefaultNamingContext -Filter $objectFilter -Properties $props

    $count = 0
    foreach ($result in $identitySearcher.FindAll()) {
        $count++
        if ($count % 1000 -eq 0) {
            Write-Progress -Activity "Building AD CS token map" -Status "Processed $count AD objects" -PercentComplete -1
        }

        $sidBytes = Get-AdLdapSingle -SearchResult $result -Name "objectSid"
        if (-not $sidBytes) { continue }
        $sid = Convert-ObjectSidToString -ObjectSid $sidBytes
        $sidKey = $sid.ToLowerInvariant()

        $objectType = Get-ObjectTypeFromSearchResult -SearchResult $result
        $dn   = [string](Get-AdLdapSingle -SearchResult $result -Name "distinguishedName")
        $sam  = [string](Get-AdLdapSingle -SearchResult $result -Name "sAMAccountName")
        $cn   = [string](Get-AdLdapSingle -SearchResult $result -Name "cn")
        $name = [string](Get-AdLdapSingle -SearchResult $result -Name "name")
        $upn  = [string](Get-AdLdapSingle -SearchResult $result -Name "userPrincipalName")
        $mail = [string](Get-AdLdapSingle -SearchResult $result -Name "mail")
        $dns  = [string](Get-AdLdapSingle -SearchResult $result -Name "dNSHostName")
        $uacRaw = Get-AdLdapSingle -SearchResult $result -Name "userAccountControl"

        $isDcComputer = $false
        if ($objectType -eq "Computer" -and $uacRaw) {
            try {
                $uac = [int]$uacRaw
                if (($uac -band 8192) -ne 0) {
                    $isDcComputer = $true
                    Add-HighValueReason -Sid $sid -Reason "Domain controller computer account"
                }
            }
            catch { }
        }

        $isHighValue = $HighValueBySid.ContainsKey($sidKey)
        $reason = if ($isHighValue) { ($HighValueBySid[$sidKey] -join "; ") } else { "" }

        $knownLabel = Get-CanonicalKnownLabelByObject -Value $sam -Sid $sid -ObjectType $objectType
        if (-not $knownLabel) {
            $knownLabel = Get-CanonicalKnownLabelByObject -Value $cn -Sid $sid -ObjectType $objectType
        }
        if (-not $knownLabel -and $objectType -eq "Group" -and $AdditionalBroadPrincipalNames.Count -gt 0) {
            foreach ($broadCandidate in $AdditionalBroadPrincipalNames) {
                if ($sam -eq $broadCandidate -or $cn -eq $broadCandidate -or $name -eq $broadCandidate) {
                    $knownLabel = "BROAD_DOMAIN_USERS"
                    break
                }
            }
        }

        if ($knownLabel) {
            $token = $knownLabel
            if ($knownLabel -like "HV_*") {
                $isHighValue = $true
                if (-not $reason) { $reason = "Default privileged group" }
            }
            $tokenType = if ($knownLabel -like "BROAD_*") { "BroadGroup" } elseif ($knownLabel -like "ADCS_*") { "ADCSGroup" } elseif ($knownLabel -like "HV_GROUP_*") { "PrivilegedGroup" } else { $objectType }
        }
        else {
            switch ($objectType) {
                "Group"    { $prefix = if ($isHighValue) { "HV_GROUP" } else { "GROUP" } }
                "Computer" { $prefix = if ($isHighValue -or $isDcComputer) { "HV_COMPUTER" } else { "COMPUTER" } }
                "User"     { $prefix = if ($isHighValue) { "HV_PRINCIPAL" } else { "PRINCIPAL" } }
                default    { $prefix = if ($isHighValue) { "HV_OBJECT" } else { "OBJECT" } }
            }
            $token = Invoke-HmacToken -Value $sid -Prefix $prefix
            $tokenType = $prefix
        }

        if (-not $token) { continue }

        $aliases = New-Object System.Collections.Generic.List[string]
        foreach ($v in @($sid, $dn, $sam, $cn, $name, $upn, $mail, $dns)) {
            if (-not [string]::IsNullOrWhiteSpace($v) -and -not $aliases.Contains($v)) { $aliases.Add($v) }
        }

        if ($sam) {
            $domainSam = "$($domain.NetBIOSName)\$sam"
            if (-not $aliases.Contains($domainSam)) { $aliases.Add($domainSam) }

            if ($objectType -eq "User" -or $objectType -eq "Computer") {
                $implicitUpn = "$sam@$($domain.DnsName)"
                if (-not $aliases.Contains($implicitUpn)) { $aliases.Add($implicitUpn) }
            }

            if ($sam.EndsWith("$")) {
                $samNoDollar = $sam.TrimEnd("$")
                if (-not $aliases.Contains($samNoDollar)) { $aliases.Add($samNoDollar) }
                $domainSamNoDollar = "$($domain.NetBIOSName)\$samNoDollar"
                if (-not $aliases.Contains($domainSamNoDollar)) { $aliases.Add($domainSamNoDollar) }
                if ($objectType -eq "Computer") {
                    $implicitComputerUpn = "$samNoDollar@$($domain.DnsName)"
                    if (-not $aliases.Contains($implicitComputerUpn)) { $aliases.Add($implicitComputerUpn) }
                }
            }
        }

        foreach ($proxyAddress in (Get-AdLdapMulti -SearchResult $result -Name "proxyAddresses")) {
            if (-not $proxyAddress) { continue }
            $proxyText = [string]$proxyAddress
            if ($proxyText -match '^(?i)smtp:(.+)$') {
                $smtpAddress = $matches[1]
                if ($smtpAddress -and -not $aliases.Contains($smtpAddress)) { $aliases.Add($smtpAddress) }
            }
        }

        foreach ($spn in (Get-AdLdapMulti -SearchResult $result -Name "servicePrincipalName")) {
            if ($spn -and -not $aliases.Contains([string]$spn)) { $aliases.Add([string]$spn) }
        }

        foreach ($candidateAddress in @($upn, $mail)) {
            if (-not [string]::IsNullOrWhiteSpace($candidateAddress)) {
                foreach ($sanVariant in @(
                    $candidateAddress,
                    "Principal Name=$candidateAddress",
                    "RFC822 Name=$candidateAddress",
                    "UPN=$candidateAddress",
                    "Email=$candidateAddress",
                    "smtp:$candidateAddress",
                    "mailto:$candidateAddress"
                )) {
                    if (-not $aliases.Contains($sanVariant)) { $aliases.Add($sanVariant) }
                }
            }
        }

        if ($dns) {
            foreach ($dnsVariant in @($dns, "DNS Name=$dns", "dNSHostName=$dns")) {
                if (-not $aliases.Contains($dnsVariant)) { $aliases.Add($dnsVariant) }
            }
        }

        foreach ($alias in $aliases) {
            Add-TokenMapping -InputValue $alias -Token $token -TokenType $tokenType -IsHighValue $isHighValue -HighValueReason $reason -KnownLabel $knownLabel -Source "ADObject"
        }

        if ($isHighValue -or $knownLabel -like "HV_*") {
            $HighValueRows.Add([pscustomobject]@{
                Token           = $token
                ObjectType      = $objectType
                TokenType       = $tokenType
                HighValueReason = $reason
                KnownLabel      = $knownLabel
            })
        }
    }

    Write-Progress -Activity "Building AD CS token map" -Completed

    $tokenMapFull = Resolve-OutPath -Path $TokenMapCsv
    $TokenMapRows |
        Sort-Object Token, InputValue -Unique |
        Export-Csv -Path $tokenMapFull -NoTypeInformation -Encoding UTF8

    Write-Host "Token map written to: $tokenMapFull"
    Write-Host "Token map rows:       $($TokenMapRows.Count)"
    Write-Host "DO NOT upload this token map." -ForegroundColor Red

    if ($HighValueTargetsCsv) {
        $hvtFull = Resolve-OutPath -Path $HighValueTargetsCsv
        $HighValueRows |
            Sort-Object Token -Unique |
            Export-Csv -Path $hvtFull -NoTypeInformation -Encoding UTF8
        Write-Host "Cowork-safe high-value target file written to: $hvtFull"
    }

    return $tokenMapFull
}

# =====================================================================
# REGION: Stage 5 -- Scrub a CSV with the token map
# =====================================================================

function Get-FallbackPrefix {
    param([string]$ColumnName, [string]$Value)
    $col = if ($ColumnName) { $ColumnName.ToLowerInvariant() } else { "" }

    # Multi-valued cells ("; " or "|" lists, e.g. several enrollment / Manage CA
    # principals in one column) must be split and tokenized PER element by the
    # caller's list branch -- never collapsed into one token. Defer them so the
    # exact-value path falls through to that branch.
    if ($Value -match ';|\|') { return $null }

    if ($col -match 'requestid|notbefore|notafter|submittedwhen|resolvedwhen|disposition|validity|date|time') { return $null }
    if ($col -match 'eku|oid|authcapable|published|approval|required|candidate|enabled|flag|count|number|status') { return $null }
    # CA / issuer identity columns -> CA_ tokens (keeps CA + org names out of the
    # output; the skill expects CA_x tokens). Must precede the template / X500
    # rules below so 'CA_DistinguishedName' does not fall through to X500.
    if ($col -match '^ca_|publishingca|certissuer') { return "CA" }
    if ($col -match 'template' -and $Value -notmatch '^([0-9]+\.)+[0-9]+$') { return "TEMPLATE" }
    if ($col -match 'hash|thumbprint|serial|certificatehash|rawcertificate') { return "CERT" }
    if ($col -match 'dns|hostname|fqdn') { return "DNS" }
    if ($col -match 'san_upn|subjectaltnameupn|upn|email') { return "UNMAPPED_UPN" }
    if ($col -match 'requester|caller') {
        if ($Value -match '\$$') { return "COMPUTER" }
        return "UNMAPPED_PRINCIPAL"
    }
    if ($col -match 'principal|owner|user|account|enroll|permission|acl|allow|dangerouscontrol|group') {
        if ($Value -match '\$$') { return "COMPUTER" }
        return "PRINCIPAL"
    }
    if ($col -match 'issuer|subject|distinguished|x500|dn') { return "X500" }
    if ($Value -match '^S-1-\d+-') { return "SID" }
    if ($Value -match '^[0-9a-fA-F]{32,}$') { return "CERT" }
    if ($Value -match '^[{]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[}]?$') { return "GUID" }
    if ($Value -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return "UNMAPPED_UPN" }
    if ($Value -match '^[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$]+$') { return "PRINCIPAL" }
    if ($Value -match '^(CN|OU|DC|O|L|ST|C)=') { return "X500" }
    if ($Value -match '^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$') { return "DNS" }
    if ($Value -match '^\d{1,3}(\.\d{1,3}){3}$') { return "IP" }
    return $null
}

function Get-TokenForAtomicValue {
    param([string]$ColumnName, [string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }

    $clean = if ($ColumnName -match 'SAN|UPN|Email') { Normalize-SANValue -Value $Value } else { $Value.Trim() }
    if ([string]::IsNullOrWhiteSpace($clean)) { return $Value }

    if (Is-AlreadyToken -Value $clean) { return $clean }

    $norm = Normalize-TokenKey -Value $clean
    if ($norm -and $script:TokenByNorm.ContainsKey($norm)) { return $script:TokenByNorm[$norm] }

    $known = Get-CanonicalKnownLabelByValue -Value $clean
    if ($known) { return $known }

    if ($clean -match '^([0-9]+\.)+[0-9]+$') { return $clean }   # OID
    if ($clean -match '^(true|false)$') { return $clean }        # boolean

    $date = [datetime]::MinValue
    if (($ColumnName -match 'date|time|when|notbefore|notafter') -and [datetime]::TryParse($clean, [ref]$date)) {
        return $clean
    }

    $prefix = Get-FallbackPrefix -ColumnName $ColumnName -Value $clean
    if ($prefix) {
        $token = Invoke-HmacToken -Value $clean -Prefix $prefix
        if ($token) { return $token }
    }
    return $clean
}

function Resolve-IdentityValue {
    param([string]$ColumnName, [string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return [pscustomobject]@{ Token = $null; Mapped = $false; Status = "Blank" }
    }

    $clean = if ($ColumnName -match 'SAN|UPN|Email') { Normalize-SANValue -Value $Value } else { $Value.Trim() }
    $norm = Normalize-TokenKey -Value $clean

    if ($norm -and $script:TokenByNorm.ContainsKey($norm)) {
        return [pscustomobject]@{ Token = $script:TokenByNorm[$norm]; Mapped = $true; Status = "MappedToAD" }
    }

    $known = Get-CanonicalKnownLabelByValue -Value $clean
    if ($known) {
        return [pscustomobject]@{ Token = $known; Mapped = $true; Status = "KnownSafeLabel" }
    }

    $token = Get-TokenForAtomicValue -ColumnName $ColumnName -Value $clean

    $status =
        if     ($token -like "UNMAPPED_UPN_*")       { "UnmappedUPN" }
        elseif ($token -like "UNMAPPED_PRINCIPAL_*") { "UnmappedRequester" }
        elseif ($token -like "PRINCIPAL_*" -or $token -like "COMPUTER_*" -or $token -like "HV_PRINCIPAL_*" -or $token -like "HV_COMPUTER_*") { "FallbackToken" }
        else   { "UnmappedOther" }

    return [pscustomobject]@{ Token = $token; Mapped = $false; Status = $status }
}

function Get-RowValueByNames {
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][string[]]$Names)
    $props = @($Row.PSObject.Properties.Name)
    foreach ($name in $Names) {
        if ($props -contains $name) { return [string]$Row.$name }
    }
    return $null
}

# Ordered free-text hardening passes. Shared by Scrub (per field) and Harden
# (whole file). Every match routes through Get-Token so token-map, canonical
# labels, OID-preservation and HMAC length are all consistent.
function Invoke-FreeTextHardening {
    param([string]$ColumnName, [string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $out = $Value

    # SIDs
    $out = [regex]::Replace($out, 'S-1-\d+(?:-\d+)+', {
        param($m) Get-Token -Value $m.Value -Prefix "SID"
    })

    # CertificateTemplate:name
    $out = [regex]::Replace($out, '(?im)(\bCertificateTemplate\s*:\s*)([A-Za-z0-9_.\-]+)', {
        param($m)
        if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value }
        return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "TEMPLATE")
    })

    # cdc/rmd/ccm markers in request attributes
    $out = [regex]::Replace($out, '(?im)(\b(?:cdc|rmd|ccm)\s*:\s*)([A-Za-z0-9_.\-]+)', {
        param($m)
        if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value }
        return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "DNS")
    })

    # SAN markers. NOTE: the original used a single-quoted [^,;`r`n] class, which
    # literally excluded the letters r and n (backtick-r/backtick-n are not CR/LF
    # inside single quotes). Using \r\n here matches the documented intent.
    $out = [regex]::Replace($out, '(?im)(\b(?:DNS Name|Principal Name|RFC822 Name|URL|URI|IP Address)\s*=\s*)([^,;\r\n]+)', {
        param($m)
        $label = $m.Groups[1].Value
        $rawVal = $m.Groups[2].Value.Trim()
        if (Is-AlreadyToken -Value $rawVal) { return $label + $rawVal }
        if ($label -match '(?i)IP Address') { return $label + (Get-Token -Value $rawVal -Prefix "IP") }
        if ($label -match '(?i)Principal Name|RFC822 Name') { return $label + (Get-Token -Value $rawVal -Prefix "UNMAPPED_UPN") }
        if ($label -match '(?i)URL|URI') { return $label + (Get-Token -Value $rawVal -Prefix "SAN_URI") }
        return $label + (Get-Token -Value $rawVal -Prefix "DNS")
    })

    # DOMAIN\user style principals
    $out = [regex]::Replace($out, '(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$ ]+', {
        param($m) Get-Token -Value $m.Value -Prefix "PRINCIPAL"
    })

    # Emails / UPNs anywhere else
    $out = [regex]::Replace($out, '\b[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', {
        param($m)
        if (Is-AlreadyToken -Value $m.Value) { return $m.Value }
        return Get-Token -Value $m.Value -Prefix "UNMAPPED_UPN"
    })

    # IPv4 addresses
    $out = [regex]::Replace($out, '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b', {
        param($m) Get-Token -Value $m.Value -Prefix "IP"
    })

    # FQDNs (avoid OIDs / decimal version strings)
    $out = [regex]::Replace($out, '\b(?=[A-Za-z0-9.-]*[A-Za-z])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b', {
        param($m)
        $value = $m.Value
        if (Is-AlreadyToken -Value $value) { return $value }
        if ($value -match '^([0-9]+\.)+[0-9]+$') { return $value }
        if ($value -match '^\d+(?:\.\d+)+$')     { return $value }
        return Get-Token -Value $value -Prefix "DNS"
    })

    # DN-like chunks
    $out = [regex]::Replace($out, '(?i)\b(?:CN|OU|DC|O|L|ST|C)=[^;\r\n]+', {
        param($m) Get-Token -Value $m.Value -Prefix "X500"
    })

    # Long raw hex identifiers
    $out = [regex]::Replace($out, '(?<![A-Za-z0-9_])[0-9a-fA-F]{20,}(?![A-Za-z0-9_])', {
        param($m) Get-Token -Value $m.Value -Prefix "CERT"
    })

    return $out
}

function Scrub-Field {
    param([string]$ColumnName, $Value)

    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $text }

    # Preserve low-risk analytical columns intact. Includes the ESC4/5/7 + CA
    # security flags and enum/keyword columns added by the template and CA-security
    # stages (booleans, AD-rights enums, object-type labels, EditFlags hex). These
    # carry no tenant identity and must survive scrubbing for the skill to read.
    if ($ColumnName -match '^(RequestID|SubmittedWhen|ResolvedWhen|NotBefore|NotAfter|Disposition|ParseStatus|Published|SubjectSuppliedByRequester|SANSuppliedByRequester|SubjectOrSANSuppliedByRequester|ManagerApprovalRequired|AuthorizedSignaturesRequired|RequiredSignatureCount|NoSecurityExtension|NoEKU|AuthCapableOrAnyPurpose|ESC1Candidate_AnyEnroll|ESC1Candidate_BroadEnroll|ESC4Candidate|ESC5Candidate|ESC7Candidate|ESC11Candidate|ESC6_CAConfigFlag|EditF_AttributeSubjectAltName2|EditFlagsHex|InterfaceFlagsHex|IF_EnforceEncryptICertRequest|SecuritySource|IsDangerous|IsDefaultPrincipal|AccessType|PkiObjectType|Rights|SidMismatchLikelyBenign|StrongCertificateBindingEnforcement|EnforcementLevel|FullEnforcement|ReadStatus|ReadMethod|EndpointKind|Scheme|IsHttp|AuthFromMetadata|Probed|Reachable|HttpStatus|AuthSchemesOffered|NtlmOffered|EpaTokenChecking|EpaSource|Esc8RiskFromMetadata|ESC8Confirmed|ESC8NeedsEpaCheck|ESC8Mitigated|ESC8Candidate|HasSidSecurityExtension|RequestAttributesHasSAN|IsEnrollmentAgentCert|HasAnyPurposeOrNoEKU|OnBehalfOfCallerMismatch|NameFlag.*|EnrollmentFlag.*)$') {
        return $text
    }
    if ($ColumnName -match 'EKU|OID|AuthEKUsMatched') { return $text }

    # Multi-valued cells FIRST: split on ; or | and tokenize EACH element on its
    # own. This must precede whole-value resolution -- otherwise a principal list
    # like "CORP\svc; BUILTIN\Administrators" collapses to a single token (the
    # token-map / canonical-label / fallback-prefix lookups match the whole string
    # or its trailing segment and drop the other principals). Splitting first keeps
    # every enrollment / Manage CA / ACL principal as its own token.
    if ($text -match ';|\|') {
        $delimiter = if ($text -match ';') { ';' } else { '|' }
        $parts = $text -split [regex]::Escape($delimiter)
        $scrubbedParts = foreach ($part in $parts) {
            $p = $part.Trim()
            if ($p) { Invoke-FreeTextHardening -ColumnName $ColumnName -Value (Get-TokenForAtomicValue -ColumnName $ColumnName -Value $p) }
            else { $p }
        }
        return ($scrubbedParts -join $delimiter)
    }

    # Exact value first.
    $exact = Get-TokenForAtomicValue -ColumnName $ColumnName -Value $text
    if ($exact -ne $text -or (Is-AlreadyToken -Value $exact)) { return $exact }

    # Free-text fallback.
    if ($ColumnName -match 'Subject|Issuer|Distinguished|RequestAttributes|SAN|Principal|Enroll|Permission|ACL|Allow|Dangerous|Owner|Group|Name|Dns|DNS|Email|URI|Url|URL|Host') {
        return Invoke-FreeTextHardening -ColumnName $ColumnName -Value $text
    }

    return $text
}

# Post-scrub safety net: scan a finished file for (a) explicit sensitive terms
# such as the AD domain FQDN / NetBIOS name, and (b) residual identifiers that
# hardening should have removed (emails/UPNs, IPv4, DOMAIN\user, bare FQDNs).
# Anything already in token form is ignored. Returns $true if clean.
function Test-ScrubbedForLeaks {
    param(
        [Parameter(Mandatory)][string]$CsvPath,
        [string[]]$SensitiveTerms = @()
    )

    Write-Host ""
    Write-Host "[*] Post-scrub leak check: $([System.IO.Path]::GetFileName($CsvPath))"
    $text = [System.IO.File]::ReadAllText($CsvPath)
    $findings = New-Object System.Collections.Generic.List[object]

    # (a) Explicit sensitive terms -- exact, case-insensitive.
    foreach ($term in $SensitiveTerms) {
        if ([string]::IsNullOrWhiteSpace($term)) { continue }
        $count = ([regex]::Matches($text, [regex]::Escape($term.Trim()), 'IgnoreCase')).Count
        if ($count -gt 0) {
            $findings.Add([pscustomobject]@{ Type = "SensitiveTerm '$($term.Trim())'"; Count = $count; Samples = "" })
        }
    }

    # (b) Residual identifier patterns that should have been tokenized.
    $patterns = @(
        [pscustomobject]@{ Type = "Email/UPN";    Rx = '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b' },
        [pscustomobject]@{ Type = "IPv4";         Rx = '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b' },
        [pscustomobject]@{ Type = "DOMAIN\user";  Rx = '(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]+\\[A-Za-z0-9_.\-$]+' },
        [pscustomobject]@{ Type = "Bare FQDN";    Rx = '\b(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+\b' }
    )

    foreach ($p in $patterns) {
        $leaks = @()
        foreach ($m in [regex]::Matches($text, $p.Rx)) {
            $v = $m.Value
            if (Is-AlreadyToken -Value $v) { continue }
            if ($v -match '^([0-9]+\.)+[0-9]+$') { continue }   # OID / version string
            $leaks += $v
        }
        $leaks = @($leaks | Select-Object -Unique)
        if ($leaks.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Type    = $p.Type
                Count   = $leaks.Count
                Samples = (($leaks | Select-Object -First 5) -join ", ")
            })
        }
    }

    if ($findings.Count -eq 0) {
        Write-Host "[+] Leak check PASSED: no sensitive terms or residual identifiers found." -ForegroundColor Green
        return $true
    }

    Write-Host "[!] Leak check found POTENTIAL leaks -- review before uploading:" -ForegroundColor Red
    foreach ($f in $findings) {
        $msg = "    - {0}: {1} occurrence(s)" -f $f.Type, $f.Count
        if ($f.Samples) { $msg += "  e.g. $($f.Samples)" }
        Write-Host $msg -ForegroundColor Red
    }
    Write-Host "[!] Re-run hardening (menu option 6) and/or add these to the token map." -ForegroundColor Yellow
    return $false
}

# Redact explicit sensitive terms (org / vendor / NetBIOS / CA names the analyst
# listed) that carry NO identifier shape, so the regex hardening passes never catch
# them -- e.g. an org name like "Noridian" embedded in a template DisplayName. Each
# term is a literal: resolve its token ONCE via the shared tokenizer and substitute,
# so the same term collapses to the same token across every file. Applied during the
# scrub itself so the post-scrub leak check passes on the FIRST pass.
function Protect-SensitiveTerms {
    param(
        [Parameter(Mandatory)][string]$Text,
        [string[]]$SensitiveTerms = @()
    )
    $out = $Text
    foreach ($term in $SensitiveTerms) {
        $t = ([string]$term).Trim()
        if ($t.Length -lt 3) { continue }   # skip 1-2 char terms: too collision-prone
        $prefix = if ($t -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { "DNS" } else { "X500" }
        $tok = Get-Token -Value $t -Prefix $prefix
        $out = [regex]::Replace($out, [regex]::Escape($t), $tok.Replace('$', '$$'), 'IgnoreCase')
    }
    return $out
}

function Invoke-ScrubCsv {
    param(
        [Parameter(Mandatory)][string]$InputCsv,
        [Parameter(Mandatory)][string]$OutputCsv,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [string[]]$AdditionalBroadLabels = @(),
        [string[]]$SensitiveTerms = @()
    )

    Write-Section "Stage 5: Scrub $([System.IO.Path]::GetFileName($InputCsv))"

    if (-not (Test-Path $InputCsv)) { throw "InputCsv not found: $InputCsv" }

    [void](Get-SessionSalt)
    $script:AdditionalBroadLabels = $AdditionalBroadLabels
    [void](Import-TokenMap -TokenMapCsv $TokenMapCsv)

    Write-Host "Importing CSV: $InputCsv"
    $raw = @(Import-Csv $InputCsv)
    $totalRows = $raw.Count
    $rowNumber = 0

    $scrubbedRows = foreach ($row in $raw) {
        $rowNumber++
        if ($rowNumber % 500 -eq 0) {
            Write-Progress -Activity "Scrubbing AD CS CSV" -Status "Processing row $rowNumber of $totalRows" -PercentComplete ([int](($rowNumber / [math]::Max($totalRows, 1)) * 100))
        }

        $new = [ordered]@{}
        foreach ($prop in $row.PSObject.Properties) {
            $new[$prop.Name] = Scrub-Field -ColumnName $prop.Name -Value $prop.Value
        }

        # Identity-comparison columns for issued-cert exports.
        $rawRequester = Get-RowValueByNames -Row $row -Names @("RequesterName", "Request.RequesterName", "CallerName", "Request.CallerName")
        $rawSanUpn    = Get-RowValueByNames -Row $row -Names @("SAN_UPN", "SubjectAltNameUPN", "UPN")

        if (-not [string]::IsNullOrWhiteSpace($rawRequester) -or -not [string]::IsNullOrWhiteSpace($rawSanUpn)) {
            $requesterIdentity = Resolve-IdentityValue -ColumnName "RequesterName" -Value $rawRequester
            $sanUpnIdentity    = Resolve-IdentityValue -ColumnName "SAN_UPN" -Value $rawSanUpn

            $sameIdentity = $false
            if ($requesterIdentity.Token -and $sanUpnIdentity.Token -and $requesterIdentity.Token -eq $sanUpnIdentity.Token) {
                $sameIdentity = $true
            }

            if     ([string]::IsNullOrWhiteSpace($rawSanUpn))      { $mappingStatus = "NoSANUPN" }
            elseif (-not $requesterIdentity.Token)                 { $mappingStatus = "RequesterMissingOrUnmapped" }
            elseif (-not $sanUpnIdentity.Token)                    { $mappingStatus = "SANUPNMissingOrUnmapped" }
            elseif ($sameIdentity)                                 { $mappingStatus = "SameIdentity" }
            elseif (-not $requesterIdentity.Mapped -or -not $sanUpnIdentity.Mapped) { $mappingStatus = "DifferentOrUnmappedIdentity" }
            else                                                   { $mappingStatus = "DifferentMappedIdentity" }

            $new["RequesterIdentityToken"]         = $requesterIdentity.Token
            $new["SAN_UPN_IdentityToken"]          = $sanUpnIdentity.Token
            $new["RequesterMappedToAD"]            = $requesterIdentity.Mapped
            $new["SAN_UPN_MappedToAD"]             = $sanUpnIdentity.Mapped
            $new["RequesterIdentityMappingStatus"] = $requesterIdentity.Status
            $new["SAN_UPN_IdentityMappingStatus"]  = $sanUpnIdentity.Status
            $new["RequesterSanUPNSameIdentity"]    = $sameIdentity
            $new["IdentityMappingStatus"]          = $mappingStatus
        }

        # ESC9/ESC10 -- SID security extension. The raw embedded SID (column
        # SidSecurityExtensionSid) was tokenized by the field loop above; because
        # the token map keys a principal's objectSid to the SAME token as its
        # name/UPN, a legitimate cert resolves the embedded SID to the requester's
        # own token. Promote it to a token column and compare. A missing extension
        # or a non-matching SID is the ESC9 / strong-mapping signal the skill reads.
        if ($new.Contains("SidSecurityExtensionSid")) {
            $new["SidSecurityExtensionToken"] = $new["SidSecurityExtensionSid"]
            [void]$new.Remove("SidSecurityExtensionSid")
        }
        $sidExtToken   = [string]$new["SidSecurityExtensionToken"]
        $reqIdToken    = [string]$new["RequesterIdentityToken"]
        $hasSidExtFlag = ([string]$new["HasSidSecurityExtension"] -eq "True")
        if (-not $hasSidExtFlag -or [string]::IsNullOrWhiteSpace($sidExtToken)) {
            $new["SidExtensionMatchesRequester"] = "Unknown"
        }
        elseif ([string]::IsNullOrWhiteSpace($reqIdToken)) {
            $new["SidExtensionMatchesRequester"] = "Unknown"
        }
        elseif ($sidExtToken -eq $reqIdToken) {
            $new["SidExtensionMatchesRequester"] = "True"
        }
        else {
            $new["SidExtensionMatchesRequester"] = "False"
        }

        # Deterministic benign-noise classifier for the strong-mapping signal. A SID
        # mismatch on a machine / auto-enrollment certificate that carries no SAN UPN
        # is the expected pre-KB5014754 pattern, not impersonation. Tagging it here
        # lets the analysis suppress the bulk noise by data instead of by prose, while
        # still surfacing any SID mismatch that targets a real user/HV identity.
        $imStatus = [string]$new["IdentityMappingStatus"]
        $reqTok   = [string]$new["RequesterIdentityToken"]
        $isMachineRequester = (
            $reqTok -like "COMPUTER_*" -or $reqTok -like "HV_COMPUTER_*" -or
            ("$rawRequester").Trim().EndsWith('$')
        )
        $new["SidMismatchLikelyBenign"] = [bool](
            ([string]$new["SidExtensionMatchesRequester"] -eq "False") -and
            ($imStatus -eq "NoSANUPN") -and
            $isMachineRequester
        )

        [pscustomobject]$new
    }

    Write-Progress -Activity "Scrubbing AD CS CSV" -Completed

    # Leak hardening is part of the scrub itself -- not a separate step. Render the
    # scrubbed rows to CSV text in memory, run the whole-file hardening pass over
    # it, and write ONE final file that is both scrubbed and hardened.
    $outFull = Resolve-OutPath -Path $OutputCsv
    $csvText = (($scrubbedRows | ConvertTo-Csv -NoTypeInformation) -join "`r`n") + "`r`n"
    Write-Host "Applying inline leak hardening..."
    $csvText = Invoke-LeakHardeningText -Text $csvText
    # Redact the analyst's explicit sensitive terms (org / vendor names that have no
    # identifier shape) in the SAME pass, so the leak check below passes first time.
    $csvText = Protect-SensitiveTerms -Text $csvText -SensitiveTerms $SensitiveTerms
    [System.IO.File]::WriteAllText($outFull, $csvText, [System.Text.Encoding]::UTF8)

    Write-Host "Input rows:  $totalRows"
    Write-Host "Output file (scrubbed + hardened): $outFull"

    # Post-scrub verification. This should pass on the first try now; the block below
    # is a safety net -- if anything still slipped through it AUTOMATICALLY re-hardens
    # the SAME file in place (no prompt, no _HARDENED copy).
    $clean = Test-ScrubbedForLeaks -CsvPath $outFull -SensitiveTerms $SensitiveTerms
    if (-not $clean) {
        Write-Host "[*] Residue detected -- automatically re-hardening in place (same filename)..." -ForegroundColor Yellow
        $reText = [System.IO.File]::ReadAllText($outFull)
        $reText = Invoke-LeakHardeningText -Text $reText
        $reText = Protect-SensitiveTerms -Text $reText -SensitiveTerms $SensitiveTerms
        [System.IO.File]::WriteAllText($outFull, $reText, [System.Text.Encoding]::UTF8)
        [void](Test-ScrubbedForLeaks -CsvPath $outFull -SensitiveTerms $SensitiveTerms)
    }

    Write-Host "Reminder: upload only scrubbed CSVs and high_value_targets_scrubbed.csv, never the token map." -ForegroundColor Yellow
    return $outFull
}

# =====================================================================
# REGION: Stage 6 -- Leak-harden an already-scrubbed CSV (whole-text pass)
# =====================================================================

# Whole-file hardening. Mirrors the original Repair-*-SIMPLE passes (which were
# designed to run over raw CSV text), but routes every match through the shared
# Get-Token so the token map, canonical labels, OID-preservation and HMAC length
# are identical to the scrubber.
#
# IMPORTANT: this set deliberately omits the per-field SID / DOMAIN\user / DN
# passes. Over raw CSV text their broad character classes (e.g. "...=[^;]+")
# would run past a cell's closing quote/comma and swallow neighbouring columns.
# The value-capturing classes here all stop at quotes, commas and whitespace.
function Invoke-LeakHardeningText {
    param([Parameter(Mandatory)][string]$Text)

    $out = $Text

    # CertificateTemplate:name
    $out = [regex]::Replace($out, '(?im)(\bCertificateTemplate\s*:\s*)([A-Za-z0-9_.\-]+)', {
        param($m)
        if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value }
        return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "TEMPLATE")
    })

    # cdc/rmd/ccm markers in request attributes
    $out = [regex]::Replace($out, '(?im)(\b(?:cdc|rmd|ccm)\s*:\s*)([A-Za-z0-9_.\-]+)', {
        param($m)
        if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value }
        return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "DNS")
    })

    # SAN markers. Positive value class -> inherently stops at quote/comma/space,
    # so it is safe to run across the whole CSV.
    $out = [regex]::Replace($out, '(?im)(\b(?:DNS Name|Principal Name|RFC822 Name|URL|URI|IP Address)\s*=\s*)([A-Za-z0-9_.@:\-/]+)', {
        param($m)
        $label = $m.Groups[1].Value
        $value = $m.Groups[2].Value
        if (Is-AlreadyToken -Value $value) { return $m.Value }
        if ($label -match '(?i)IP Address') { return $label + (Get-Token -Value $value -Prefix "IP") }
        if ($label -match '(?i)Principal Name|RFC822 Name') { return $label + (Get-Token -Value $value -Prefix "UNMAPPED_UPN") }
        if ($value -match '@') { return $label + (Get-Token -Value $value -Prefix "UNMAPPED_UPN") }
        return $label + (Get-Token -Value $value -Prefix "DNS")
    })

    # Emails / UPNs anywhere else
    $out = [regex]::Replace($out, '\b[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', {
        param($m)
        if (Is-AlreadyToken -Value $m.Value) { return $m.Value }
        return Get-Token -Value $m.Value -Prefix "UNMAPPED_UPN"
    })

    # IPv4 addresses
    $out = [regex]::Replace($out, '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b', {
        param($m)
        if (Is-AlreadyToken -Value $m.Value) { return $m.Value }
        return Get-Token -Value $m.Value -Prefix "IP"
    })

    # FQDNs (avoid OIDs / decimal version strings)
    $out = [regex]::Replace($out, '\b(?=[A-Za-z0-9.-]*[A-Za-z])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b', {
        param($m)
        $value = $m.Value
        if (Is-AlreadyToken -Value $value) { return $value }
        if ($value -match '^([0-9]+\.)+[0-9]+$') { return $value }
        if ($value -match '^\d+(?:\.\d+)+$')     { return $value }
        return Get-Token -Value $value -Prefix "DNS"
    })

    # Long raw hex identifiers (serials / hashes), if any survived
    $out = [regex]::Replace($out, '(?<![A-Za-z0-9_])[0-9a-fA-F]{20,}(?![A-Za-z0-9_])', {
        param($m)
        if (Is-AlreadyToken -Value $m.Value) { return $m.Value }
        return Get-Token -Value $m.Value -Prefix "CERT"
    })

    return $out
}

function Invoke-HardenScrubbedCsv {
    param(
        [Parameter(Mandatory)][string]$InputCsv,
        [Parameter(Mandatory)][string]$OutputCsv,
        [Parameter(Mandatory)][string]$TokenMapCsv
    )

    Write-Section "Stage 6: Leak-harden $([System.IO.Path]::GetFileName($InputCsv))"

    if (-not (Test-Path $InputCsv)) { throw "InputCsv not found: $InputCsv" }

    [void](Get-SessionSalt)
    [void](Import-TokenMap -TokenMapCsv $TokenMapCsv)

    Write-Host "Reading: $InputCsv"
    $text = [System.IO.File]::ReadAllText($InputCsv)
    Write-Host "Input size: $($text.Length) characters"
    Write-Host "Hardening free-text values..."

    # CSV-safe whole-file passes (see Invoke-LeakHardeningText). Each match still
    # routes through the shared Get-Token, so any value tokenized here is byte-for-
    # byte identical to the same value tokenized during scrubbing.
    $text = Invoke-LeakHardeningText -Text $text

    $outFull = Resolve-OutPath -Path $OutputCsv
    [System.IO.File]::WriteAllText($outFull, $text, [System.Text.Encoding]::UTF8)

    Write-Host "Output written to: $outFull"
    Write-Host "Output size: $($text.Length) characters"
    return $outFull
}

# =====================================================================
# REGION: Interactive stage wrappers (prompt for inputs)
# =====================================================================

function Invoke-Interactive-Export {
    $caConfig = Select-CAConfig
    $includeRevoked = Read-YesNo -Prompt "Also export REVOKED certs into the same file (for ESC1 demo/sanity checks)" -Default $false
    $default = Join-Path $script:WorkDir "exported_certs_normalized_UNSCRUBBED.csv"
    $outCsv = Read-DefaultString -Prompt "Output CSV path" -Default $default
    $maxRows = Read-DefaultInt -Prompt "Max rows (0 = all)" -Default 0
    return Invoke-ExportIssuedCerts -CAConfig $caConfig -OutCsv $outCsv -MaxRows $maxRows -IncludeRevoked:$includeRevoked
}

function Invoke-Interactive-Trim {
    $defaultIn = Join-Path $script:WorkDir "exported_certs_normalized_UNSCRUBBED.csv"
    $inCsv = Read-DefaultString -Prompt "Input UNSCRUBBED exported-cert CSV" -Default $defaultIn
    $yearsDefault = if ($env:ADCS_AUDIT_YEARS_BACK) { [int]$env:ADCS_AUDIT_YEARS_BACK } else { 3 }
    $years = Read-DefaultInt -Prompt "Keep how many years back" -Default $yearsDefault
    # Default to trimming the file in place (same name) so we don't litter the
    # working folder with a second copy. The prompt still lets you redirect it.
    $outCsv = Read-DefaultString -Prompt "Output CSV path (default: overwrite the input in place)" -Default $inCsv
    return Invoke-TrimIssuedCerts -InputCsv $inCsv -OutCsv $outCsv -YearsBack $years
}

function Invoke-Interactive-Templates {
    $default = Join-Path $script:WorkDir "adcs_template_inventory_UNSCRUBBED.csv"
    $outCsv = Read-DefaultString -Prompt "Output template inventory CSV path" -Default $default
    return Invoke-ExportTemplateInventory -OutCsv $outCsv
}

function Invoke-Interactive-CASecurity {
    $caConfig = Select-CAConfig
    $defaultCa  = Join-Path $script:WorkDir "adcs_ca_security_UNSCRUBBED.csv"
    $outCa  = Read-DefaultString -Prompt "Output CA security CSV path" -Default $defaultCa
    $defaultAcl = Join-Path $script:WorkDir "adcs_pki_object_acls_UNSCRUBBED.csv"
    $outAcl = Read-DefaultString -Prompt "Output PKI object ACL CSV path" -Default $defaultAcl
    $outDc = ""
    $dcCred = $null
    if (Read-YesNo -Prompt "Also collect per-DC KB5014754 enforcement (needs remote registry to DCs)" -Default $true) {
        $defaultDc = Join-Path $script:WorkDir "adcs_dc_enforcement_UNSCRUBBED.csv"
        $outDc = Read-DefaultString -Prompt "Output DC enforcement CSV path" -Default $defaultDc
        Write-Host "  The DC reads run as your current logon. If that account cannot read the DCs'" -ForegroundColor Yellow
        Write-Host "  registry (e.g. it is not a Domain Admin), supply an alternate credential to get" -ForegroundColor Yellow
        Write-Host "  confirmed LIVE reads (over WinRM/WMI) instead of the SYSVOL/GPP intended-value fallback." -ForegroundColor Yellow
        if (Read-YesNo -Prompt "  Use an alternate credential for the DC reads" -Default $false) {
            try { $dcCred = Get-Credential -Message "Account that can read the domain controllers' registry (e.g. Domain Admin)" }
            catch { $dcCred = $null }
            if (-not $dcCred) { Write-Host "  No credential supplied -- DC reads will use your current logon." -ForegroundColor Yellow }
        }
    }
    $outWeb = ""
    $probe = $false
    $epaTest = $false
    $epaCred = $null
    if (Read-YesNo -Prompt "Also collect web-enrollment (ESC8) surface from AD metadata" -Default $true) {
        $defaultWeb = Join-Path $script:WorkDir "adcs_web_enrollment_UNSCRUBBED.csv"
        $outWeb = Read-DefaultString -Prompt "Output web-enrollment CSV path" -Default $defaultWeb
        Write-Host "  The active probe makes outbound HTTP/HTTPS connections to your CA web endpoints" -ForegroundColor Yellow
        Write-Host "  (no credentials sent) to confirm reachability + NTLM auth. May need change control." -ForegroundColor Yellow
        $probe = Read-YesNo -Prompt "  Actively probe endpoints to confirm exploitability" -Default $false
        if ($probe) {
            Write-Host "  EXPERIMENTAL behavioral EPA test: signs in to each HTTPS endpoint TWICE as a" -ForegroundColor Yellow
            Write-Host "  supplied account (with vs without channel binding) to detect Extended Protection." -ForegroundColor Yellow
            Write-Host "  No coercion/relay -- two logons as that account; generates auth events. Untested build." -ForegroundColor Yellow
            $epaTest = Read-YesNo -Prompt "  Run the behavioral EPA test (needs a low-priv test credential)" -Default $false
            if ($epaTest) {
                try { $epaCred = Get-Credential -Message "Test account to authenticate to web enrollment (any user that can reach certsrv)" }
                catch { $epaCred = $null }
                if (-not $epaCred) { Write-Host "  No credential supplied -- skipping behavioral EPA test." -ForegroundColor Yellow; $epaTest = $false }
            }
        }
    }
    return Invoke-ExportCaAndPkiSecurity -OutCaCsv $outCa -OutPkiAclCsv $outAcl -OutDcEnforcementCsv $outDc -OutWebEnrollmentCsv $outWeb -ProbeWebEnrollment:$probe -TestEpaBehavioral:$epaTest -WebEnrollmentCredential $epaCred -DCRemoteCredential $dcCred -CAConfig $caConfig
}

function Invoke-Interactive-TokenMap {
    if ($script:NoTokenization) { throw 'Token-map creation is unavailable with -NoTokenization. This run is local-only.' }
    $defaultMap = Join-Path $script:WorkDir "adcs_token_map_DO_NOT_UPLOAD.csv"
    $tokenMap = Read-DefaultString -Prompt "Token map output path (KEEP PRIVATE)" -Default $defaultMap
    $defaultHvt = Join-Path $script:WorkDir "high_value_targets_scrubbed.csv"
    $hvt = Read-DefaultString -Prompt "High-value targets output path (Cowork-safe)" -Default $defaultHvt
    $skipComputers = -not (Read-YesNo -Prompt "Include computer accounts" -Default $true)

    $broadRaw = Read-DefaultString -Prompt "Extra broad enrollment group names (comma-separated, blank for none)" -Default ""
    $broad = @()
    if (-not [string]::IsNullOrWhiteSpace($broadRaw)) {
        $broad = @($broadRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    [void](Get-SessionSalt)
    return Invoke-BuildTokenMap -TokenMapCsv $tokenMap -HighValueTargetsCsv $hvt -SkipComputers:$skipComputers -AdditionalBroadPrincipalNames $broad
}

function Invoke-Interactive-Scrub {
    if ($script:NoTokenization) { throw 'Scrubbing is unavailable with -NoTokenization. This run is local-only.' }
    # Scrub EVERY *_UNSCRUBBED.csv in the working folder in one go, asking the
    # shared questions (token map, broad labels, sensitive terms) ONCE rather than
    # per file. Falls back to a single-file prompt if none are present.
    $targets = @(Get-ChildItem -Path $script:WorkDir -Filter "*_UNSCRUBBED.csv" -File -ErrorAction SilentlyContinue | Sort-Object Name)
    if ($targets.Count -eq 0) {
        $one = Read-DefaultString -Prompt "No *_UNSCRUBBED.csv in the working folder. Path to a single UNSCRUBBED CSV to scrub"
        if (-not (Test-Path $one)) { throw "Input not found: $one" }
        $targets = @(Get-Item $one)
    }
    else {
        Write-Host "Found $($targets.Count) UNSCRUBBED file(s) to scrub:"
        foreach ($f in $targets) { Write-Host "  - $($f.Name)" }
    }

    $defaultMap = Join-Path $script:WorkDir "adcs_token_map_DO_NOT_UPLOAD.csv"
    $tokenMap = Read-DefaultString -Prompt "Token map path" -Default $defaultMap

    $broadRaw = Read-DefaultString -Prompt "Extra broad labels to treat as BROAD_DOMAIN_USERS (comma-separated, blank for none)" -Default ""
    $broad = @()
    if (-not [string]::IsNullOrWhiteSpace($broadRaw)) {
        $broad = @($broadRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    # Asked once, reused for every file. Hardening + leak check (with automatic
    # in-place re-harden on failure) are built into each Invoke-ScrubCsv call.
    $sensitive = Get-SensitiveTerms
    [void](Get-SessionSalt)

    $outputs = @()
    foreach ($f in $targets) {
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($f.FullName) -replace '(?i)_UNSCRUBBED$', ''
        $outCsv = Join-Path $script:WorkDir ("{0}_scrubbed.csv" -f $stem)
        Write-Host ""
        Write-Host "=== Scrubbing $($f.Name) -> $([System.IO.Path]::GetFileName($outCsv)) ===" -ForegroundColor Cyan
        $outputs += (Invoke-ScrubCsv -InputCsv $f.FullName -OutputCsv $outCsv -TokenMapCsv $tokenMap -AdditionalBroadLabels $broad -SensitiveTerms $sensitive)
    }
    Write-Host ""
    Write-Host "Scrubbed $($outputs.Count) file(s)." -ForegroundColor Green
    return $outputs
}

function Invoke-Interactive-Harden {
    if ($script:NoTokenization) { throw 'Leak hardening is unavailable with -NoTokenization because no scrubbed package exists.' }
    $inCsv = Read-DefaultString -Prompt "Input scrubbed CSV to harden"
    # Harden in place by default (same filename) -- no _HARDENED copy.
    $outCsv = Read-DefaultString -Prompt "Output hardened CSV path (default: harden in place)" -Default $inCsv
    $defaultMap = Join-Path $script:WorkDir "adcs_token_map_DO_NOT_UPLOAD.csv"
    $tokenMap = Read-DefaultString -Prompt "Token map path" -Default $defaultMap
    [void](Get-SessionSalt)
    return Invoke-HardenScrubbedCsv -InputCsv $inCsv -OutputCsv $outCsv -TokenMapCsv $tokenMap
}

function Invoke-Interactive-All {
    Write-Section "Full pipeline"
    Write-Host "Stages 1, 3, 3b and 4 need a domain-joined machine with CA/AD rights."
    Write-Host "You can skip any stage whose inputs already exist."
    Write-Host ""

    if ($script:NoTokenization) {
        Write-Host 'LOCAL-ONLY MODE: tokenization, scrubbing, safe manifests, and safe bundles are disabled.' -ForegroundColor Yellow
        Write-Host 'Raw exports and all reports will remain under *_DO_NOT_UPLOAD folders. Do not use this mode for AI or vendor sharing.' -ForegroundColor Yellow
    }
    else { [void](Get-SessionSalt) }

    $issuedUnscrubbed = $null
    if (Read-YesNo -Prompt "Stage 1: export certs from the CA now" -Default $true) {
        $issuedUnscrubbed = Invoke-Interactive-Export
    }
    else {
        $issuedUnscrubbed = Read-DefaultString -Prompt "Path to existing UNSCRUBBED exported-cert CSV" -Default (Join-Path $script:WorkDir "exported_certs_normalized_UNSCRUBBED.csv")
    }

    if (Read-YesNo -Prompt "Stage 2: trim to last N years" -Default $true) {
        $yearsDefault = if ($env:ADCS_AUDIT_YEARS_BACK) { [int]$env:ADCS_AUDIT_YEARS_BACK } else { 3 }
        $years = Read-DefaultInt -Prompt "Keep how many years back" -Default $yearsDefault
        # Trim in place (overwrite the export) so the working folder keeps one file.
        $issuedUnscrubbed = Invoke-TrimIssuedCerts -InputCsv $issuedUnscrubbed -OutCsv $issuedUnscrubbed -YearsBack $years
    }

    $templateUnscrubbed = $null
    if (Read-YesNo -Prompt "Stage 3: export template inventory now" -Default $true) {
        $templateUnscrubbed = Invoke-ExportTemplateInventory -OutCsv (Join-Path $script:WorkDir "adcs_template_inventory_UNSCRUBBED.csv")
    }
    else {
        $templateUnscrubbed = Read-DefaultString -Prompt "Path to existing UNSCRUBBED template inventory CSV (blank to skip)" -Default ""
    }

    $caSecUnscrubbed = $null
    $pkiAclUnscrubbed = $null
    $dcEnfUnscrubbed = $null
    $webUnscrubbed = $null
    if (Read-YesNo -Prompt "Stage 3b: export CA security + PKI ACLs + DC enforcement + web enrollment (ESC5/6/7/8/11 + KB5014754) now" -Default $true) {
        $caSecCfg = Select-CAConfig
        $probeWeb = $false
        $epaTest = $false
        $epaCred = $null
        $dcCred = $null
        Write-Host "  DC enforcement (KB5014754) is read over the network. If your current logon can't" -ForegroundColor Yellow
        Write-Host "  read the DCs' registry, supply an alternate credential for confirmed LIVE reads" -ForegroundColor Yellow
        Write-Host "  (over WinRM/WMI) instead of the SYSVOL/GPP intended-value fallback." -ForegroundColor Yellow
        if (Read-YesNo -Prompt "  Use an alternate credential for the DC reads" -Default $false) {
            try { $dcCred = Get-Credential -Message "Account that can read the domain controllers' registry (e.g. Domain Admin)" } catch { $dcCred = $null }
            if (-not $dcCred) { Write-Host "  No credential supplied -- DC reads will use your current logon." -ForegroundColor Yellow }
        }
        if (Read-YesNo -Prompt "  Actively probe web-enrollment endpoints for ESC8 (outbound HTTP/HTTPS to CA hosts, no creds)" -Default $false) {
            $probeWeb = $true
            if (Read-YesNo -Prompt "  Also run the EXPERIMENTAL behavioral EPA test (two logons per HTTPS endpoint as a test account)" -Default $false) {
                try { $epaCred = Get-Credential -Message "Test account to authenticate to web enrollment (any user that can reach certsrv)" } catch { $epaCred = $null }
                $epaTest = [bool]$epaCred
            }
        }
        $caSecResult = Invoke-ExportCaAndPkiSecurity `
            -OutCaCsv (Join-Path $script:WorkDir "adcs_ca_security_UNSCRUBBED.csv") `
            -OutPkiAclCsv (Join-Path $script:WorkDir "adcs_pki_object_acls_UNSCRUBBED.csv") `
            -OutDcEnforcementCsv (Join-Path $script:WorkDir "adcs_dc_enforcement_UNSCRUBBED.csv") `
            -OutWebEnrollmentCsv (Join-Path $script:WorkDir "adcs_web_enrollment_UNSCRUBBED.csv") `
            -ProbeWebEnrollment:$probeWeb -TestEpaBehavioral:$epaTest -WebEnrollmentCredential $epaCred `
            -DCRemoteCredential $dcCred `
            -CAConfig $caSecCfg
        $caSecUnscrubbed  = $caSecResult.CaCsv
        $pkiAclUnscrubbed = $caSecResult.PkiAclCsv
        $dcEnfUnscrubbed  = $caSecResult.DcCsv
        $webUnscrubbed    = $caSecResult.WebCsv
    }
    else {
        $caSecUnscrubbed  = Read-DefaultString -Prompt "Path to existing UNSCRUBBED CA security CSV (blank to skip)" -Default ""
        $pkiAclUnscrubbed = Read-DefaultString -Prompt "Path to existing UNSCRUBBED PKI object ACL CSV (blank to skip)" -Default ""
        $dcEnfUnscrubbed  = Read-DefaultString -Prompt "Path to existing UNSCRUBBED DC enforcement CSV (blank to skip)" -Default ""
        $webUnscrubbed    = Read-DefaultString -Prompt "Path to existing UNSCRUBBED web enrollment CSV (blank to skip)" -Default ""
    }

    if ($script:NoTokenization) {
        $moved = Move-LocalOnlyRawExports -Root $script:WorkDir
        Write-Section 'Local-only collection complete'
        Write-Host "Moved $moved raw export(s) into Raw_DO_NOT_UPLOAD." -ForegroundColor Yellow
        Write-Host 'Run: .\Invoke-ADCSAuditPipeline.ps1 -Stage Analyze -NoTokenization -NonInteractive -WorkDir <same folder>' -ForegroundColor Cyan
        return [pscustomobject]@{ PackageMode='LocalOnlyNoTokenization'; SafeUploadEligible=$false; RawExports=$moved }
    }

    $tokenMap = Join-Path $script:WorkDir "adcs_token_map_DO_NOT_UPLOAD.csv"
    if (Read-YesNo -Prompt "Stage 4: build the token map + high-value targets now" -Default $true) {
        $skipComputers = -not (Read-YesNo -Prompt "Include computer accounts" -Default $true)
        $tokenMap = Invoke-BuildTokenMap -TokenMapCsv $tokenMap -HighValueTargetsCsv (Join-Path $script:WorkDir "high_value_targets_scrubbed.csv") -SkipComputers:$skipComputers
    }
    else {
        $tokenMap = Read-DefaultString -Prompt "Path to existing token map" -Default $tokenMap
    }

    # Scrubbing now hardens inline and runs the leak check, so each file needs a
    # single call. Ask once for the sensitive terms used by every leak check.
    $sensitive = Get-SensitiveTerms

    # Scrub + harden issued/revoked export.
    if ($issuedUnscrubbed -and (Test-Path $issuedUnscrubbed)) {
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($issuedUnscrubbed) -replace '(?i)_UNSCRUBBED$', ''
        [void](Invoke-ScrubCsv -InputCsv $issuedUnscrubbed -OutputCsv (Join-Path $script:WorkDir "${stem}_scrubbed.csv") -TokenMapCsv $tokenMap -SensitiveTerms $sensitive)
    }

    # Scrub + harden template inventory.
    if ($templateUnscrubbed -and (Test-Path $templateUnscrubbed)) {
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($templateUnscrubbed) -replace '(?i)_UNSCRUBBED$', ''
        [void](Invoke-ScrubCsv -InputCsv $templateUnscrubbed -OutputCsv (Join-Path $script:WorkDir "${stem}_scrubbed.csv") -TokenMapCsv $tokenMap -SensitiveTerms $sensitive)
    }

    # Scrub + harden CA security + PKI object ACLs.
    if ($caSecUnscrubbed -and (Test-Path $caSecUnscrubbed)) {
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($caSecUnscrubbed) -replace '(?i)_UNSCRUBBED$', ''
        [void](Invoke-ScrubCsv -InputCsv $caSecUnscrubbed -OutputCsv (Join-Path $script:WorkDir "${stem}_scrubbed.csv") -TokenMapCsv $tokenMap -SensitiveTerms $sensitive)
    }
    if ($pkiAclUnscrubbed -and (Test-Path $pkiAclUnscrubbed)) {
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($pkiAclUnscrubbed) -replace '(?i)_UNSCRUBBED$', ''
        [void](Invoke-ScrubCsv -InputCsv $pkiAclUnscrubbed -OutputCsv (Join-Path $script:WorkDir "${stem}_scrubbed.csv") -TokenMapCsv $tokenMap -SensitiveTerms $sensitive)
    }
    if ($dcEnfUnscrubbed -and (Test-Path $dcEnfUnscrubbed)) {
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($dcEnfUnscrubbed) -replace '(?i)_UNSCRUBBED$', ''
        [void](Invoke-ScrubCsv -InputCsv $dcEnfUnscrubbed -OutputCsv (Join-Path $script:WorkDir "${stem}_scrubbed.csv") -TokenMapCsv $tokenMap -SensitiveTerms $sensitive)
    }
    if ($webUnscrubbed -and (Test-Path $webUnscrubbed)) {
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($webUnscrubbed) -replace '(?i)_UNSCRUBBED$', ''
        [void](Invoke-ScrubCsv -InputCsv $webUnscrubbed -OutputCsv (Join-Path $script:WorkDir "${stem}_scrubbed.csv") -TokenMapCsv $tokenMap -SensitiveTerms $sensitive)
    }

    # Self-describing run manifest (scrubbed files, row counts, salt fingerprint).
    [void](Write-RunManifest -WorkDir $script:WorkDir)

    Write-Section "Full pipeline complete"
    Write-Host "Upload only the *_scrubbed.csv files, high_value_targets_scrubbed.csv, and adcs_audit_manifest.json." -ForegroundColor Green
    Write-Host "NEVER upload the token map: $tokenMap" -ForegroundColor Red
}

# =====================================================================
# REGION: Menu / driver
# =====================================================================

function Show-Menu {
    Write-Host ""
    Write-Host "CertifEye - AD CS ESC Audit Pipeline" -ForegroundColor Green
    Write-Host "Working folder: $script:WorkDir"
    Write-Host ""
    Write-Host "  1) Export certs from a CA, issued + optional revoked  (needs CA access)"
    Write-Host "  2) Trim exported certs to the last N years"
    Write-Host "  3) Export certificate template inventory              (needs AD/LDAP)"
    Write-Host "  4) Export CA/PKI/DC/web security (ESC5/6/7/8/11+KB)   (needs CA + AD/LDAP)"
    Write-Host "  5) Build identity token map + high-value file         (needs AD/LDAP)"
    Write-Host "  6) Scrub ALL UNSCRUBBED CSVs (hardened + auto re-harden on residue)"
    Write-Host "  7) Re-run leak hardening on a scrubbed CSV (in place)"
    Write-Host "  8) Run the full pipeline"
    Write-Host "  Q) Quit"
    Write-Host ""
}

function Start-Pipeline {
    # Resolve working directory.
    if ($Stage -eq 'Analyze' -and [string]::IsNullOrWhiteSpace($script:WorkDir)) {
        $script:WorkDir = (Get-Location).Path
    }
    elseif ([string]::IsNullOrWhiteSpace($script:WorkDir)) {
        $script:WorkDir = Read-DefaultString -Prompt "Working folder for inputs/outputs" -Default (Get-Location).Path
    }
    $script:WorkDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($script:WorkDir)
    if (-not (Test-Path $script:WorkDir)) {
        New-Item -Path $script:WorkDir -ItemType Directory -Force | Out-Null
    }

    if ($script:NoTokenization -and $Stage -in @('TokenMap','Scrub','Harden')) {
        throw "-NoTokenization cannot be used with -Stage $Stage. Use -Stage All for local-only collection, then -Stage Analyze -NoTokenization for private reports."
    }
    if ($script:NoTokenization -and -not $Stage) {
        throw '-NoTokenization requires an explicit -Stage All (collection) or -Stage Analyze (private analysis). It is not available as a console setting.'
    }
    if ($NonInteractive -and $Stage -ne 'Analyze') {
        throw 'NonInteractive collection is intentionally disabled. Use -Stage Analyze with explicit paths for deterministic processing, or run the legacy collector interactively.'
    }

    if ($Stage -eq 'Analyze') {
        Invoke-ExplicitAnalysis -Root $script:WorkDir -LocalOnly:$script:NoTokenization
        return
    }

    # Legacy single-stage mode. These stages retain their original prompts and
    # domain/CA access behavior.
    if ($Stage) {
        switch ($Stage) {
            'Export'     { [void](Invoke-Interactive-Export) }
            'Trim'       { [void](Invoke-Interactive-Trim) }
            'Templates'  { [void](Invoke-Interactive-Templates) }
            'CASecurity' { [void](Invoke-Interactive-CASecurity) }
            'TokenMap'   { [void](Invoke-Interactive-TokenMap) }
            'Scrub'      { [void](Invoke-Interactive-Scrub) }
            'Harden'     { [void](Invoke-Interactive-Harden) }
            'All'        { Invoke-Interactive-All }
        }
        if (-not $script:NoTokenization) { Publish-LegacyPackage -Root $script:WorkDir }
        return
    }

    # Interactive menu loop.
    while ($true) {
        Show-Menu
        $choice = Read-Host "Select an option"
        switch ($choice.Trim().ToUpperInvariant()) {
            '1' { try { [void](Invoke-Interactive-Export) }     catch { Write-Host "Stage failed: $($_.Exception.Message)" -ForegroundColor Red } }
            '2' { try { [void](Invoke-Interactive-Trim) }       catch { Write-Host "Stage failed: $($_.Exception.Message)" -ForegroundColor Red } }
            '3' { try { [void](Invoke-Interactive-Templates) }  catch { Write-Host "Stage failed: $($_.Exception.Message)" -ForegroundColor Red } }
            '4' { try { [void](Invoke-Interactive-CASecurity) } catch { Write-Host "Stage failed: $($_.Exception.Message)" -ForegroundColor Red } }
            '5' { try { [void](Invoke-Interactive-TokenMap) }   catch { Write-Host "Stage failed: $($_.Exception.Message)" -ForegroundColor Red } }
            '6' { try { [void](Invoke-Interactive-Scrub) }      catch { Write-Host "Stage failed: $($_.Exception.Message)" -ForegroundColor Red } }
            '7' { try { [void](Invoke-Interactive-Harden) }     catch { Write-Host "Stage failed: $($_.Exception.Message)" -ForegroundColor Red } }
            '8' { try { Invoke-Interactive-All }                catch { Write-Host "Pipeline failed: $($_.Exception.Message)" -ForegroundColor Red } }
            'Q' { Write-Host "Bye."; return }
            default { Write-Host "Unrecognized choice: $choice" -ForegroundColor Yellow }
        }
    }
}

function Start-CertifEyeConsole {
    $session = @{ WorkDir=$WorkDir; Stage=if($Stage){$Stage}else{'All'}; SaltFile=$SaltFile; SaltFromEnv=$SaltFromEnv; InputDir=$InputDir; OutputDir=$OutputDir; WorkingDir=$WorkingDir; _NoTokenization=[bool]$NoTokenization }
    $commands = @{
        plan = { param($args,$s) $local=[bool]$s._NoTokenization;[pscustomobject]@{Tool='CertifEye';Stage=[string]$s.Stage;WorkDir=[string]$s.WorkDir;PackageMode=if($local){'LocalOnlyNoTokenization'}else{'TokenizedSafePackage'};SafeUploadEligible=(-not $local);CollectionRequiresInteractive=$true;AnalysisInput=if($s.InputDir){[string]$s.InputDir}elseif($local){'<WorkDir>\Raw_DO_NOT_UPLOAD'}else{'<WorkDir>\Scrubbed'}} | Format-List }
        doctor = { param($args,$s) Write-AssessmentDoctorReport -Checks @(Get-AssessmentDoctorReport -RequiredModules @('ActiveDirectory') -RequiredCommands @('certutil.exe') -WorkDir ([string]$s.WorkDir)) }
        collect = { param($args,$s) if(-not $s.WorkDir){throw 'Use set WorkDir <path> before collect.'};$p=@{Action='Collect';WorkDir=[string]$s.WorkDir;Stage=[string]$s.Stage;HmacLength=$HmacLength};if($s._NoTokenization){$p.NoTokenization=$true}else{if($s.SaltFile){$p.SaltFile=[string]$s.SaltFile}elseif($s.SaltFromEnv){$p.SaltFromEnv=[string]$s.SaltFromEnv}};& $PSCommandPath @p -PassThru }
        analyze = { param($args,$s) if(-not $s.WorkDir){throw 'Use set WorkDir <path> before analyze.'};$p=@{Action='Analyze';NonInteractive=$true;WorkDir=[string]$s.WorkDir;SkipQa=$SkipQa};if($s._NoTokenization){$p.NoTokenization=$true};foreach($name in 'InputDir','OutputDir','WorkingDir'){if($s[$name]){$p[$name]=[string]$s[$name]}};& $PSCommandPath @p -PassThru }
        validate = { param($args,$s) $root=[string]$s.WorkDir;if(-not $root){throw 'Use set WorkDir <path> before validate.'};$p=@{Action='Validate';WorkDir=$root;PassThru=$true};if($s._NoTokenization){$p.NoTokenization=$true};& $PSCommandPath @p | Format-List }
    }
    Start-AssessmentInteractive -ToolName 'CertifEye' -Subtitle 'Privacy-preserving AD CS assessment.' -BannerInfo @{Version='v2.1.0-rc1';Author='glides';Repo='github.com/glides/CertifEye'} -Commands $commands -Session $session -Examples @('set WorkDir C:\Assessments\CertifEye','set SaltFile C:\Secure\assessment.salt','set Stage All','plan','collect','analyze','validate') -CompletionValues @{'set'=@('WorkDir','Stage','SaltFile','SaltFromEnv','InputDir','OutputDir','WorkingDir');'Stage'=@('Export','Trim','Templates','CASecurity','TokenMap','Scrub','Harden','Analyze','All')}
}

# Make WorkDir available to all functions as a session value.
$script:WorkDir = $WorkDir
$script:AdditionalBroadLabels = @()

if($Version){[pscustomobject]@{Tool='CertifEye';Version='2.1.0-rc1';SchemaVersion='certifeye-exports/v1';TokenContractVersion=$script:AssessmentTokenContractVersion};return}
if($NoTokenization -and $SafeBundlePath){throw '-SafeBundlePath cannot be used with -NoTokenization. Local-only artifacts are never upload-safe.'}
if($PlanOnly -or $Action -eq 'Plan'){
    [pscustomobject]@{Tool='CertifEye';Stage=if($Stage){$Stage}else{'All'};WorkDir=$WorkDir;CollectionRequiresInteractive=$true;WritesFiles=$false;PackageMode=if($NoTokenization){'LocalOnlyNoTokenization'}else{'TokenizedSafePackage'};SafeUploadEligible=(-not $NoTokenization)}
    return
}
if($Action -eq 'Doctor'){Get-AssessmentDoctorReport -RequiredModules @('ActiveDirectory') -RequiredCommands @('certutil.exe') -WorkDir $WorkDir;return}
if($Action -eq 'Validate'){
    if(-not $WorkDir){throw '-WorkDir is required for validation.'}
    if($NoTokenization){
        $localManifest=Join-Path $WorkDir 'Private_DO_NOT_UPLOAD\certifeye_local_only_manifest_DO_NOT_UPLOAD.json'
        $local=[pscustomobject]@{Valid=$false;PackageMode='LocalOnlyNoTokenization';SafeUploadEligible=$false;Reason='Tokenization was explicitly disabled; this run has no safe upload package.';LocalManifest=$localManifest}
        if($PassThru){$local}else{$local|Format-List};return
    }
    $validation=Test-AssessmentSafePackage -ScrubbedDir (Join-Path $WorkDir 'Scrubbed') -ManifestPath (Join-Path $WorkDir 'Scrubbed\adcs_upload_manifest.json') -PassThru
    if($SafeBundlePath -and $validation.Valid){New-AssessmentSafeBundle -ScrubbedDir (Join-Path $WorkDir 'Scrubbed') -ManifestPath (Join-Path $WorkDir 'Scrubbed\adcs_upload_manifest.json') -OutputPath $SafeBundlePath -Force:$Force|Out-Null}
    if($PassThru){$validation}else{$validation|Format-List};return
}
if($Action -eq 'Analyze'){$Stage='Analyze'}
elseif($Action -eq 'Collect' -and -not $Stage){$Stage='All'}
$legacyInvocation = [bool]$Stage -or @($PSBoundParameters.Keys | Where-Object { $_ -notin @('Action','Version','PlanOnly','PassThru','NoTokenization') }).Count -gt 0
if(($Action -eq 'Interactive' -or (-not $Action -and -not $legacyInvocation)) -and -not $NonInteractive){Start-CertifEyeConsole|Out-Null;return}
Start-Pipeline
