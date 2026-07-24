[CmdletBinding()]
param(
    [ValidateSet('All','all-esc-enterprise','hardened-baseline','mixed-enterprise')]
    [string]$Scenario = 'All',
    [string]$Destination = (Join-Path ([IO.Path]::GetTempPath()) 'CertifEye-Demo'),
    [switch]$IncludeQa,
    [switch]$Replace
)

$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
$pipeline = Join-Path $project 'Invoke-ADCSAuditPipeline.ps1'
$sampleRoot = Join-Path $project 'synthetic-samples'
$names = if ($Scenario -eq 'All') {
    @('all-esc-enterprise','hardened-baseline','mixed-enterprise')
} else {
    @($Scenario)
}

$results = foreach ($name in $names) {
    $input = Join-Path $sampleRoot "$name\Scrubbed"
    $sourceManifest = Join-Path $input 'adcs_upload_manifest.json'
    if (-not (Test-Path -LiteralPath $sourceManifest)) {
        throw "Synthetic scenario manifest is missing: $sourceManifest"
    }
    $manifest = Get-Content -LiteralPath $sourceManifest -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $manifest.synthetic -or $manifest.scenario -ne $name) {
        throw "Refusing a package that is not the expected synthetic scenario: $name"
    }

    $target = Join-Path $Destination $name
    if ((Test-Path -LiteralPath $target) -and (Get-ChildItem -LiteralPath $target -Force -ErrorAction SilentlyContinue)) {
        if (-not $Replace) {
            throw "Destination is not empty: $target. Choose another path or use -Replace."
        }
        Remove-Item -LiteralPath $target -Recurse -Force
    }
    $output = Join-Path $target 'Reports'
    $working = Join-Path $target 'Working'
    New-Item -ItemType Directory -Path $output,$working -Force | Out-Null

    $parameters = @{
        Action = 'Analyze'
        NonInteractive = $true
        WorkDir = $target
        InputDir = $input
        OutputDir = $output
        WorkingDir = $working
    }
    if (-not $IncludeQa) { $parameters.SkipQa = $true }
    & $pipeline @parameters | Out-Host

    $resultPath = Join-Path $working 'results.json'
    if (-not (Test-Path -LiteralPath $resultPath)) { throw "Analysis did not create results.json for $name." }
    $analysis = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $artifacts = @(Get-ChildItem -LiteralPath $output -File)
    if (-not $artifacts.Count -or @($artifacts | Where-Object Length -le 0).Count) {
        throw "One or more report artifacts are missing or empty for $name."
    }
    [pscustomobject]@{
        Scenario = $name
        CertificateRows = [int]$analysis.meta.cert_rows
        FindingCount = @($analysis.findings).Count
        EscTypes = @($analysis.findings.ESCType | Sort-Object -Unique) -join ', '
        AssessmentDate = [string]$analysis.meta.generated_on
        Reports = $output
        ArtifactCount = $artifacts.Count
    }
}

$results | Format-Table -AutoSize
$results
