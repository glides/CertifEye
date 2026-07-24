[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ProjectRoot,
    [Parameter(Mandatory)][string]$Version,
    [string]$OutputDir,
    [switch]$Force
)

$ErrorActionPreference='Stop'
$project=(Resolve-Path -LiteralPath $ProjectRoot).Path
$projectName=Split-Path -Leaf $project
if(-not $OutputDir){$OutputDir=Join-Path (Split-Path -Parent $project) 'releases'}
New-Item -ItemType Directory -Path $OutputDir -Force|Out-Null
$zip=Join-Path $OutputDir ($projectName+'-'+$Version+'.zip')
if((Test-Path -LiteralPath $zip) -and -not $Force){throw "Release already exists: $zip"}

$repoRoot=(& git -C $project rev-parse --show-toplevel 2>$null|Select-Object -First 1)
if(-not $repoRoot){throw 'Project is not inside a Git working tree. Release packaging requires a reviewed tracked-file allowlist.'}
$repoRoot=(Resolve-Path -LiteralPath $repoRoot).Path
$projectPrefix=$project.Substring($repoRoot.Length).TrimStart('\','/').Replace('\','/')
$tracked=@(& git -C $repoRoot ls-files -- $(if($projectPrefix){$projectPrefix}else{'.'}))
if(-not $tracked){throw 'No tracked project files were found.'}

$deny='(?i)(^|/)(\.git|Raw_DO_NOT_UPLOAD|Private_DO_NOT_UPLOAD|DO_NOT_UPLOAD_Private|Output|Working|releases|dev_docs|__pycache__)(/|$)|token[_-]?map|salt|run_manifest|\.pyc$|\.log$'
$files=New-Object Collections.Generic.List[object]
foreach($relativeRepo in $tracked){
    $relative=$relativeRepo.Replace('\','/')
    if($projectPrefix){if(-not $relative.StartsWith($projectPrefix+'/')){continue};$relative=$relative.Substring($projectPrefix.Length+1)}
    if($relative -match $deny){continue}
    $source=Join-Path $project ($relative.Replace('/','\'))
    if(Test-Path -LiteralPath $source -PathType Leaf){$files.Add([pscustomobject]@{Relative=$relative;Source=$source})}
}
if(-not $files.Count){throw 'The release allowlist is empty after deny rules.'}

$stage=Join-Path ([IO.Path]::GetTempPath()) ('assessment-release-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage -Force|Out-Null
try{
    foreach($file in $files){$destination=Join-Path $stage ($file.Relative.Replace('/','\'));$parent=Split-Path -Parent $destination;if($parent){New-Item -ItemType Directory -Path $parent -Force|Out-Null};Copy-Item -LiteralPath $file.Source -Destination $destination -Force}
    $checksums=@(Get-ChildItem -LiteralPath $stage -Recurse -File|Sort-Object FullName|ForEach-Object{$relative=$_.FullName.Substring($stage.Length).TrimStart('\').Replace('\','/');$hash=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant();"$hash  $relative"})
    [IO.File]::WriteAllLines((Join-Path $stage 'RELEASE_SHA256SUMS.txt'),$checksums,[Text.UTF8Encoding]::new($false))
    if(Test-Path -LiteralPath $zip){Remove-Item -LiteralPath $zip -Force}
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force
} finally {if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force}}

$result=Get-Item -LiteralPath $zip
if($result.Length -le 0){throw 'Release ZIP is empty.'}
[pscustomobject]@{Project=$projectName;Version=$Version;Path=$result.FullName;Bytes=$result.Length;FileCount=$files.Count;Sha256=(Get-FileHash -LiteralPath $result.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
