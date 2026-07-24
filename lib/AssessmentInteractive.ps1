<#
.SYNOPSIS
Shared, vendorable runtime foundation for the assessment-suite collectors.
.DESCRIPTION
Provides a command-whitelisted interactive console, assessment-token/v1 HMAC
helpers, safe package validation, safe bundle creation, and host diagnostics.
The file is intentionally dependency-free and compatible with Windows
PowerShell 5.1 and PowerShell 7.
#>

$script:AssessmentTokenContractVersion = 'assessment-token/v1'
$script:AssessmentUploadManifestVersion = 'assessment-upload-manifest/v1'

function Resolve-AssessmentSaltInput {
    [CmdletBinding()]
    param(
        [string]$Salt,
        [string]$SaltFile,
        [string]$SaltFromEnv,
        [switch]$PromptWhenMissing
    )
    $sources = @($Salt, $SaltFile, $SaltFromEnv) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    if ($sources.Count -gt 1) { throw 'Specify only one of -Salt, -SaltFile, or -SaltFromEnv.' }
    if ($SaltFile) {
        if (-not (Test-Path -LiteralPath $SaltFile -PathType Leaf)) { throw "Salt file was not found: $SaltFile" }
        $value = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $SaltFile).Path).Trim()
        if (-not $value) { throw 'The salt file is empty.' }
        return $value
    }
    if ($SaltFromEnv) {
        $value = [Environment]::GetEnvironmentVariable($SaltFromEnv)
        if ([string]::IsNullOrWhiteSpace($value)) { throw "Salt environment variable '$SaltFromEnv' is empty or unavailable." }
        return $value
    }
    if ($Salt) { return $Salt }
    if (-not $PromptWhenMissing) { throw 'A salt is required. Use -SaltFile or -SaltFromEnv for repeatable runs.' }
    $secure = Read-Host 'Run salt (masked; keep private)' -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    if ([string]::IsNullOrWhiteSpace($value)) { throw 'Salt cannot be empty.' }
    return $value
}

function Normalize-AssessmentTokenValue {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value, [string]$Prefix = 'VALUE')
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim() -replace "`r|`n", ' '
    switch -Regex ($Prefix.ToUpperInvariant()) {
        '^(UPN|EMAIL)$' { $v = $v -replace '(?i)^(smtp:|mailto:)', '' }
        '^(DNS|HOST|COMPUTER|DOMAIN)$' { $v = $v.TrimEnd('.') }
        '^GUID$' { try { $v = ([guid]$v).Guid } catch { } }
        '^SID$' { $v = $v -replace '\s+', '' }
        '^IP$' { try { $v = ([Net.IPAddress]::Parse($v)).ToString() } catch { } }
    }
    return $v.Trim().ToLowerInvariant()
}

function New-AssessmentHmacToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Salt,
        [ValidateRange(16,64)][int]$HmacLength = 24,
        [hashtable]$TokenByKey,
        [hashtable]$ValueByToken
    )
    $normalized = Normalize-AssessmentTokenValue -Value $Value -Prefix $Prefix
    if (-not $normalized) { return '' }
    $key = $Prefix.ToUpperInvariant() + '|' + $normalized
    if ($TokenByKey -and $TokenByKey.ContainsKey($key)) { return [string]$TokenByKey[$key] }
    $hmac = New-Object Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes($Salt)
        $bytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))
    }
    finally { $hmac.Dispose() }
    $hex = ([BitConverter]::ToString($bytes).Replace('-', '')).Substring(0, $HmacLength).ToUpperInvariant()
    $token = $Prefix.ToUpperInvariant() + '_' + $hex
    if ($ValueByToken -and $ValueByToken.ContainsKey($token) -and [string]$ValueByToken[$token] -ne $normalized) {
        throw "Token collision detected for $token. Increase -HmacLength and start a new run."
    }
    if ($TokenByKey) { $TokenByKey[$key] = $token }
    if ($ValueByToken) { $ValueByToken[$token] = $normalized }
    return $token
}

function New-AssessmentRunId {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ToolName)
    $safeName = ($ToolName -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLowerInvariant()
    return '{0}-{1}-{2}' -f $safeName, (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
}

function Get-AssessmentFileRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    $rows = -1
    if ($item.Extension -ieq '.csv') { try { $rows = @(Import-Csv -LiteralPath $item.FullName).Count } catch { $rows = -1 } }
    $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    return [ordered]@{ File=$item.Name; Rows=$rows; Bytes=$item.Length; Sha256=$hash }
}

function Get-AssessmentManifestFileNames {
    param([Parameter(Mandatory)]$Manifest)
    $names = New-Object Collections.Generic.List[string]
    foreach ($entry in @($Manifest.Files) + @($Manifest.files) + @($Manifest.ScrubbedFiles) + @($Manifest.scrubbedFiles) + @($Manifest.Exports)) {
        if ($entry -is [string]) { if ($entry) { $names.Add($entry) } ; continue }
        foreach ($property in 'File','file','Name','name') {
            if ($entry -and $entry.PSObject.Properties[$property] -and [string]$entry.$property) { $names.Add([string]$entry.$property); break }
        }
    }
    return @($names | Sort-Object -Unique)
}

function Test-AssessmentSafePackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScrubbedDir,
        [Parameter(Mandatory)][string]$ManifestPath,
        [switch]$PassThru
    )
    $issues = New-Object Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $ScrubbedDir -PathType Container)) { $issues.Add('Scrubbed directory is missing.') }
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { $issues.Add('Safe upload manifest is missing.') }
    $manifest = $null
    if ($issues.Count -eq 0) {
        try { $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop }
        catch { $issues.Add('Safe upload manifest is not valid JSON.') }
    }
    $forbidden = '(?i)(token[_-]?map|salt|raw_do_not_upload|private_do_not_upload|do_not_upload_private|unscrubbed|run_manifest)'
    $listed = @()
    if ($manifest) { $listed = @(Get-AssessmentManifestFileNames -Manifest $manifest) }
    foreach ($file in @(Get-ChildItem -LiteralPath $ScrubbedDir -File -ErrorAction SilentlyContinue)) {
        if ($file.Name -match $forbidden) { $issues.Add("Private-looking file is present in Scrubbed: $($file.Name)") }
    }
    foreach ($name in $listed) {
        if ($name -match $forbidden) { $issues.Add("Manifest lists a private-looking file: $name"); continue }
        if ([IO.Path]::GetFileName($name) -ne $name) { $issues.Add("Manifest contains a path instead of a filename: $name"); continue }
        if (-not (Test-Path -LiteralPath (Join-Path $ScrubbedDir $name) -PathType Leaf) -and -not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $ManifestPath) $name) -PathType Leaf)) {
            $issues.Add("Manifest-listed file is missing: $name")
        }
    }
    $result = [pscustomobject]@{ Valid=($issues.Count -eq 0); IssueCount=$issues.Count; Issues=@($issues); ManifestFileCount=$listed.Count }
    if (-not $result.Valid -and -not $PassThru) { throw ('Safe package validation failed: ' + ($issues -join '; ')) }
    return $result
}

function New-AssessmentSafeBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScrubbedDir,
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$Force
    )
    [void](Test-AssessmentSafePackage -ScrubbedDir $ScrubbedDir -ManifestPath $ManifestPath)
    if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) { throw "Safe bundle already exists: $OutputPath" }
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $names = @(Get-AssessmentManifestFileNames -Manifest $manifest)
    $stage = Join-Path ([IO.Path]::GetTempPath()) ('assessment-safe-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    try {
        foreach ($name in $names) {
            $source = Join-Path $ScrubbedDir $name
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { $source = Join-Path (Split-Path -Parent $ManifestPath) $name }
            if (Test-Path -LiteralPath $source -PathType Leaf) { Copy-Item -LiteralPath $source -Destination (Join-Path $stage $name) -Force }
        }
        Copy-Item -LiteralPath $ManifestPath -Destination (Join-Path $stage ([IO.Path]::GetFileName($ManifestPath))) -Force
        if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Force }
        Compress-Archive -LiteralPath (Get-ChildItem -LiteralPath $stage -File | Select-Object -ExpandProperty FullName) -DestinationPath $OutputPath -Force
    }
    finally { if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force } }
    return Get-Item -LiteralPath $OutputPath
}

function Get-AssessmentDoctorReport {
    [CmdletBinding()]
    param([string[]]$RequiredModules=@(), [string[]]$RequiredCommands=@(), [string]$WorkDir)
    $checks = New-Object Collections.Generic.List[object]
    $checks.Add([pscustomobject]@{Check='PowerShell';Status=if($PSVersionTable.PSVersion.Major -ge 5){'Pass'}else{'Fail'};Detail=$PSVersionTable.PSVersion.ToString()})
    $checks.Add([pscustomobject]@{Check='PrimarySupport';Status=if($PSVersionTable.PSEdition -eq 'Desktop'){'Pass'}else{'Review'};Detail='Windows PowerShell 5.1 is primary; PowerShell 7 depends on installed Microsoft modules/providers.'})
    foreach ($module in $RequiredModules) { $available=[bool](Get-Module -ListAvailable -Name $module);$checks.Add([pscustomobject]@{Check="Module:$module";Status=if($available){'Pass'}else{'Unavailable'};Detail=''}) }
    foreach ($command in $RequiredCommands) { $available=[bool](Get-Command $command -ErrorAction SilentlyContinue);$checks.Add([pscustomobject]@{Check="Command:$command";Status=if($available){'Pass'}else{'Unavailable'};Detail=''}) }
    $python = Get-Command python,py -ErrorAction SilentlyContinue | Select-Object -First 1
    $checks.Add([pscustomobject]@{Check='Python';Status=if($python){'Pass'}else{'Optional'};Detail=if($python){$python.Source}else{'Collection is available; static analysis requires Python 3.9+.'}})
    if ($WorkDir) {
        try { $resolved=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkDir);$parent=Split-Path -Parent $resolved;if(-not $parent){$parent=(Get-Location).Path};$checks.Add([pscustomobject]@{Check='WorkDir';Status=if(Test-Path -LiteralPath $parent){'Pass'}else{'Fail'};Detail=$resolved}) }
        catch { $checks.Add([pscustomobject]@{Check='WorkDir';Status='Fail';Detail='Path could not be resolved.'}) }
    }
    # Enumerate a concrete array. `@($genericList)` triggers an argument-type
    # binder failure in some PowerShell 7 hosts.
    return $checks.ToArray()
}

function Write-AssessmentWrappedLine {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Text,
        [ValidateRange(0,12)][int]$Indent = 2,
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::Gray,
        [ValidateRange(44,100)][int]$MaximumWidth = 76
    )
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    $width = $MaximumWidth
    try { if (-not [Console]::IsOutputRedirected) { $width = [Math]::Min($MaximumWidth, [Math]::Max(44, [Console]::BufferWidth - 2)) } } catch { }
    $available = [Math]::Max(20, $width - $Indent)
    $line = ''
    foreach ($word in ($Text -split '\s+')) {
        if (-not $line) { $line = $word; continue }
        if (($line.Length + 1 + $word.Length) -gt $available) {
            Write-Host ((' ' * $Indent) + $line) -ForegroundColor $ForegroundColor
            $line = $word
        }
        else { $line += ' ' + $word }
    }
    if ($line) { Write-Host ((' ' * $Indent) + $line) -ForegroundColor $ForegroundColor }
}

function Write-AssessmentDoctorReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Checks)
    Write-Host ''
    Write-Host 'Environment preflight' -ForegroundColor Cyan
    foreach ($check in $Checks) {
        $status = [string]$check.Status
        $color = switch ($status) {
            'Pass' { 'Green' }
            'Review' { 'Yellow' }
            'Optional' { 'DarkGray' }
            'Unavailable' { 'Yellow' }
            default { 'Red' }
        }
        Write-Host ('  [{0,-11}] {1}' -f $status.ToUpperInvariant(), $check.Check) -ForegroundColor $color
        if ($check.Detail) { Write-AssessmentWrappedLine -Text ([string]$check.Detail) -Indent 4 -ForegroundColor DarkGray }
    }
    Write-Host '  Tip: Pass means the prerequisite was found; Review/Unavailable tells you what may limit collection.' -ForegroundColor DarkGray
}

function Split-AssessmentCommandLine {
    param([string]$Line)
    $result = New-Object Collections.Generic.List[string]
    foreach ($match in [regex]::Matches($Line, '("(?:[^"\\]|\\.)*"|''(?:[^'']|'''')*''|\S+)')) {
        $value = $match.Value
        if ($value.Length -ge 2 -and $value[0] -eq '"' -and $value[$value.Length-1] -eq '"') { $value=$value.Substring(1,$value.Length-2) -replace '\\"','"' }
        elseif ($value.Length -ge 2 -and $value[0] -eq "'" -and $value[$value.Length-1] -eq "'") { $value=$value.Substring(1,$value.Length-2) -replace "''","'" }
        $result.Add($value)
    }
    return @($result)
}

function Get-AssessmentCompletions {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Buffer,
        [Parameter(Mandatory)][string[]]$Allowed,
        [hashtable]$CompletionValues=@{}
    )
    $parts=@(Split-AssessmentCommandLine $Buffer)
    $trailingSpace=$Buffer -match '\s$'
    if($parts.Count -le 1 -and -not $trailingSpace){
        return @($Allowed|Where-Object{$_ -like "$Buffer*"})
    }
    if($trailingSpace){
        $last=''
        $previous=if($parts.Count){$parts[-1]}else{''}
    } else {
        $last=if($parts.Count){$parts[-1]}else{''}
        $previous=if($parts.Count -gt 1){$parts[-2]}else{''}
    }
    if($previous -eq 'help'){return @($Allowed|Where-Object{$_ -like "$last*"})}
    if($previous -eq 'options'){
        $optionCandidates=if($CompletionValues.ContainsKey('options')){$CompletionValues['options']}elseif($CompletionValues.ContainsKey('set')){$CompletionValues['set']}else{@()}
        return @($optionCandidates|Where-Object{$_ -like "$last*"})
    }
    if($CompletionValues.ContainsKey($previous)){return @($CompletionValues[$previous]|Where-Object{$_ -like "$last*"})}
    if($last -match '[\\/:]' -or $previous -match '(?i)path|dir|file|out|work'){
        $parent=Split-Path -Parent $last;if(-not $parent){$parent='.'};$leaf=Split-Path -Leaf $last
        try{return @(Get-ChildItem -LiteralPath $parent -ErrorAction Stop|Where-Object{$_.Name -like "$leaf*"}|ForEach-Object{$_.FullName})}catch{return @()}
    }
    return @()
}

function Step-AssessmentCompletionCycle {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Buffer,
        [bool]$CycleActive=$false,
        [AllowEmptyString()][string]$CycleBase='',
        [string[]]$Candidates=@(),
        [int]$CycleIndex=-1,
        [string[]]$NewCandidates=@(),
        [switch]$Reverse
    )
    if(-not $CycleActive){
        $CycleBase=$Buffer
        $Candidates=@($NewCandidates)
        if(-not $Candidates.Count){
            return [pscustomobject]@{Active=$false;BaseBuffer='';Candidates=@();Index=-1;Buffer=$Buffer}
        }
        $CycleActive=$true
        $CycleIndex=if($Reverse){$Candidates.Count-1}else{0}
    } else {
        if(-not $Candidates.Count){
            return [pscustomobject]@{Active=$false;BaseBuffer='';Candidates=@();Index=-1;Buffer=$Buffer}
        }
        if($Reverse){$CycleIndex=($CycleIndex-1+$Candidates.Count)%$Candidates.Count}
        else{$CycleIndex=($CycleIndex+1)%$Candidates.Count}
    }
    $parts=@(Split-AssessmentCommandLine $CycleBase)
    if($parts.Count -le 1 -and $CycleBase -notmatch '\s$'){
        $completed=$Candidates[$CycleIndex]
    } else {
        $last=if($CycleBase -match '\s$'){''}elseif($parts.Count){$parts[-1]}else{''}
        $completed=$CycleBase.Substring(0,$CycleBase.Length-$last.Length)+$Candidates[$CycleIndex]
    }
    return [pscustomobject]@{
        Active=$CycleActive
        BaseBuffer=$CycleBase
        Candidates=@($Candidates)
        Index=$CycleIndex
        Buffer=$completed
    }
}

function Start-AssessmentInteractive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ToolName,
        [Parameter(Mandatory)][hashtable]$Commands,
        [string[]]$Examples=@(),
        [hashtable]$Session=@{},
        [hashtable]$CompletionValues=@{},
        [string]$Subtitle='Privacy-preserving defensive assessment',
        [hashtable]$BannerInfo=@{}
    )
    $builtIns=@('help','options','set','plan','collect','analyze','validate','last','doctor','examples','clear','exit')
    $allowed=@($builtIns+@($Commands.Keys))|Sort-Object -Unique
    $optionNames=if($CompletionValues.ContainsKey('set')){@($CompletionValues['set'])}else{@($Session.Keys|Where-Object{$_ -notmatch '^_' -and $_ -notin @('LastCommand','LastResult')}|Sort-Object)}
    $localOnlyMode = [bool]$Session['_NoTokenization']
    $CompletionValues['options']=@($optionNames)
    $optionSources=@{}
    foreach($optionName in $optionNames){
        $optionSources[$optionName]=if($Session.ContainsKey($optionName) -and $null -ne $Session[$optionName] -and [string]$Session[$optionName] -ne ''){'Startup/default'}else{'Not set'}
    }
    $optionMeta=@{
        WorkDir=@{Required='collect and validate; used for analyzer defaults';Default='none';Purpose='Writable assessment run root. New runs place raw, scrubbed, private, output, and working data beneath it.';Example='set WorkDir C:\Assessments\CertifEye'}
        Stage=@{Required='collector-specific';Default='collector default';Purpose='Selects the CertifEye collection or analysis stage.';Example='set Stage All'}
        Mode=@{Required='collector-specific';Default='collector default';Purpose='Selects the collector scope, such as Interactive, CoreMVP, or a focused module.';Example='set Mode Interactive'}
        Profile=@{Required='when the collector uses an assessment profile';Default='collector default';Purpose='Selects the documented assessment or compliance profile.';Example='set Profile NIST-800-53r5'}
        SaltFile=@{Required='one repeatable salt source for collection';Default='none';Purpose='Path to a protected salt file. Its value and path are hidden from options, previews, and last-command output.';Example='set SaltFile C:\Secure\assessment.salt'}
        SaltFromEnv=@{Required='alternative to SaltFile';Default='none';Purpose='Environment-variable name containing the run salt. The salt value is never displayed.';Example='set SaltFromEnv ASSESSMENT_SALT'}
        InputDir=@{Required='analyze when WorkDir is not used';Default='<WorkDir>\Scrubbed';Purpose='Explicit scrubbed input package for offline analysis.';Example='set InputDir C:\Assessments\Run01\Scrubbed'}
        OutputDir=@{Required='optional analyzer override';Default='<WorkDir>\Output';Purpose='Destination for safe reports and machine exports.';Example='set OutputDir C:\Assessments\Run01\Output'}
        WorkingDir=@{Required='optional analyzer override';Default='<WorkDir>\Working';Purpose='Local analyzer state and QA workspace; do not upload it.';Example='set WorkingDir C:\Assessments\Run01\Working'}
    }
    $helpText=[ordered]@{
        help=@('help [command]','Show all console commands or detailed help for one command.','help collect')
        options=@('options [name]','Show current values, requirements, defaults, allowed values, purpose, and safe examples. Salt sources are masked.','options','options WorkDir')
        set=@('set <name> <value>','Store an in-memory option for this console session. Option names and enum values support Tab completion; quote paths containing spaces.','set WorkDir "C:\Assessments\CertifEye Demo"')
        plan=@('plan','Preview paths, stages or modules, evidence limits, and package boundaries. It does not collect assessment data.','options WorkDir','set WorkDir C:\Assessments\CertifEye','plan')
        collect=@('collect','Run the reviewed read-only collection plan. Review the final summary for private and safe package locations and partial evidence.','set WorkDir C:\Assessments\CertifEye','set SaltFile C:\Secure\assessment.salt','plan','collect')
        analyze=@('analyze','Run the static analyzer against scrubbed input and create supported reports and exports. Collection itself does not require Python.','set WorkDir C:\Assessments\CertifEye','analyze')
        validate=@('validate','Verify schemas, manifest and file agreement, package boundaries, nonempty artifacts, and safe-output exclusions.','collect','validate')
        doctor=@('doctor','Check PowerShell, required modules and commands, the configured working path, Python, and likely evidence limitations before collection. It makes no assessment-data changes.','set WorkDir C:\Assessments\CertifEye','doctor')
        last=@('last','Show the previous command, safe session settings, and structured result. Salt values, salt paths, and internal console state are never shown.','last')
        examples=@('examples','Show the collector''s safe, copyable workflow examples. Review and edit paths before running them.','examples')
        clear=@('clear','Clear the display without changing session options, command history, or collected data.','clear')
        exit=@('exit','Leave the assessment console and return to PowerShell. In-memory options are discarded.','exit')
    }
    $history=New-Object Collections.Generic.List[string];$historyIndex=0
    $Session['LastCommand']=$null;$Session['LastResult']=$null
    function Read-AssessmentLine([string]$Prompt, [string]$PromptLabel) {
        $rawAvailable=$true
        try {
            $null=$Host.UI.RawUI
            $null=[Console]::BufferWidth
            $left=[Console]::CursorLeft
            $top=[Console]::CursorTop
            [Console]::SetCursorPosition($left,$top)
            if([Console]::IsInputRedirected -or [Console]::IsOutputRedirected){$rawAvailable=$false}
        }
        catch{$rawAvailable=$false}
        if(-not $rawAvailable){return Read-Host $Prompt}
        $buffer='';$cursor=0;$cycleActive=$false;$cycleBase='';$cycle=@();$cycleIndex=-1;$historyIndex=$history.Count
        $originLeft=[Console]::CursorLeft
        $originTop=[Console]::CursorTop
        $lineState=@{RenderedLength=$Prompt.Length}
        $writePrompt={
            $prior=[Console]::ForegroundColor
            try {
                [Console]::ForegroundColor=[ConsoleColor]::Cyan; [Console]::Write('(')
                [Console]::ForegroundColor=[ConsoleColor]::White; [Console]::Write($PromptLabel)
                [Console]::ForegroundColor=[ConsoleColor]::Cyan; [Console]::Write(') > ')
            }
            finally { [Console]::ForegroundColor=$prior }
        }
        $redraw={
            param([string]$Text,[int]$CursorPosition)
            $full=$Prompt+$Text
            $width=[Math]::Max(2,[Console]::BufferWidth)
            $capacity=[Math]::Max(1,$width-$originLeft-1)
            $clearLength=[Math]::Min([Math]::Max([int]$lineState.RenderedLength,$full.Length),$capacity)
            [Console]::SetCursorPosition($originLeft,$originTop)
            [Console]::Write((' ' * $clearLength))
            [Console]::SetCursorPosition($originLeft,$originTop)
            & $writePrompt
            [Console]::Write($Text)
            $lineState.RenderedLength=$full.Length
            $absolute=$originLeft+$Prompt.Length+$CursorPosition
            if($absolute -lt $width){[Console]::SetCursorPosition($absolute,$originTop)}
        }
        & $writePrompt
        $oldTreatControlC = [Console]::TreatControlCAsInput
        [Console]::TreatControlCAsInput = $true
        try {
        while($true){
            $key=[Console]::ReadKey($true)
            if(($key.Modifiers -band [ConsoleModifiers]::Control) -and $key.Key -eq [ConsoleKey]::C){[Console]::WriteLine();return 'exit'}
            if($key.Key -eq [ConsoleKey]::Enter){[Console]::WriteLine();return $buffer}
            if($key.Key -eq [ConsoleKey]::LeftArrow -and $cursor -gt 0){$cursor--;$cycleActive=$false;$cycle=@();$cycleIndex=-1;& $redraw $buffer $cursor;continue}
            if($key.Key -eq [ConsoleKey]::RightArrow -and $cursor -lt $buffer.Length){$cursor++;$cycleActive=$false;$cycle=@();$cycleIndex=-1;& $redraw $buffer $cursor;continue}
            if($key.Key -eq [ConsoleKey]::Home){$cursor=0;$cycleActive=$false;$cycle=@();$cycleIndex=-1;& $redraw $buffer $cursor;continue}
            if($key.Key -eq [ConsoleKey]::End){$cursor=$buffer.Length;$cycleActive=$false;$cycle=@();$cycleIndex=-1;& $redraw $buffer $cursor;continue}
            if($key.Key -eq [ConsoleKey]::UpArrow -and $history.Count){$historyIndex=[Math]::Max(0,$historyIndex-1);$buffer=$history[$historyIndex];$cursor=$buffer.Length;$cycleActive=$false;$cycle=@();$cycleIndex=-1;& $redraw $buffer $cursor;continue}
            if($key.Key -eq [ConsoleKey]::DownArrow -and $history.Count){$historyIndex=[Math]::Min($history.Count,$historyIndex+1);$buffer=if($historyIndex -lt $history.Count){$history[$historyIndex]}else{''};$cursor=$buffer.Length;$cycleActive=$false;$cycle=@();$cycleIndex=-1;& $redraw $buffer $cursor;continue}
            if($key.Key -eq [ConsoleKey]::Backspace -and $cursor -gt 0){$buffer=$buffer.Remove($cursor-1,1);$cursor--;$cycleActive=$false;$cycle=@();$cycleIndex=-1;& $redraw $buffer $cursor;continue}
            if($key.Key -eq [ConsoleKey]::Delete -and $cursor -lt $buffer.Length){$buffer=$buffer.Remove($cursor,1);$cycleActive=$false;$cycle=@();$cycleIndex=-1;& $redraw $buffer $cursor;continue}
            if($key.Key -eq [ConsoleKey]::Escape){$buffer='';$cursor=0;$cycleActive=$false;$cycle=@();$cycleIndex=-1;& $redraw $buffer $cursor;continue}
            if($key.Key -eq [ConsoleKey]::Tab){
                $matches=if($cycleActive){@()}else{@(Get-AssessmentCompletions -Buffer $buffer -Allowed $allowed -CompletionValues $CompletionValues)}
                $reverse=($key.Modifiers -band [ConsoleModifiers]::Shift) -ne 0
                $completion=Step-AssessmentCompletionCycle -Buffer $buffer -CycleActive $cycleActive -CycleBase $cycleBase -Candidates $cycle -CycleIndex $cycleIndex -NewCandidates $matches -Reverse:$reverse
                $cycleActive=$completion.Active;$cycleBase=$completion.BaseBuffer;$cycle=@($completion.Candidates);$cycleIndex=$completion.Index
                if($cycleActive){$buffer=$completion.Buffer;$cursor=$buffer.Length;& $redraw $buffer $cursor}
                continue
            }
            if($key.KeyChar -and -not[char]::IsControl($key.KeyChar)){$buffer=$buffer.Insert($cursor,[string]$key.KeyChar);$cursor++;$cycleActive=$false;$cycle=@();$cycleIndex=-1;& $redraw $buffer $cursor}
        }
        }
        finally { [Console]::TreatControlCAsInput = $oldTreatControlC }
    }
    if($BannerInfo.Count){
        function Write-AssessmentBannerRow([string]$Text, [ConsoleColor]$TextColor, [int]$Indent = 2) {
            $innerWidth = $width - 2
            $padding = [Math]::Max(0, $innerWidth - $Indent - $Text.Length)
            Write-Host '║' -ForegroundColor DarkCyan -NoNewline
            Write-Host (' ' * $Indent) -NoNewline
            Write-Host $Text -ForegroundColor $TextColor -NoNewline
            Write-Host (' ' * $padding) -NoNewline
            Write-Host '║' -ForegroundColor DarkCyan
        }
        $width=70;$line=('═' * ($width-2))
        Write-Host ''
        Write-Host ('╔'+$line+'╗') -ForegroundColor DarkCyan
        Write-AssessmentBannerRow -Text ('[>_] '+$ToolName) -TextColor Magenta -Indent 4
        Write-AssessmentBannerRow -Text $Subtitle -TextColor DarkGray -Indent 4
        Write-Host ('╠'+$line+'╣') -ForegroundColor DarkCyan
        foreach($label in @('Version','Author','Repo')){
            if($BannerInfo.ContainsKey($label)){
                Write-AssessmentBannerRow -Text ('> {0,-10} {1}' -f $label,[string]$BannerInfo[$label]) -TextColor Cyan -Indent 2
            }
        }
        Write-Host ('╚'+$line+'╝') -ForegroundColor DarkCyan
        Write-Host ''
    }
    else { Write-Host '';Write-Host ('  >_ '+$ToolName) -ForegroundColor Cyan;Write-Host ('  '+$Subtitle) -ForegroundColor DarkGray }
    Write-Host '  Type help; Tab completes; Up/Down recall history; exit returns to PowerShell.' -ForegroundColor DarkGray
    :AssessmentConsoleLoop while($true){
        $line=(Read-AssessmentLine "($ToolName) > " $ToolName).Trim();if(-not $line){continue};$history.Add($line);$parts=@(Split-AssessmentCommandLine $line);$name=$parts[0].ToLowerInvariant();$args=@($parts|Select-Object -Skip 1)
        if($name -notin $allowed){Write-Warning "Unknown command '$name'. Type help.";continue};$Session['LastCommand']=$line
        switch($name){
            'exit'{
                $answer = Read-Host "Exit $ToolName interactive console [Y/n]"
                if([string]::IsNullOrWhiteSpace($answer) -or $answer.Trim() -match '^(?i)y(es)?$'){
                    Write-Host 'Goodbye.' -ForegroundColor DarkGray
                    return $Session
                }
                continue AssessmentConsoleLoop
            }
            'clear'{Clear-Host;continue AssessmentConsoleLoop}
            'help'{
                if($args.Count){
                    $topic=$args[0].ToLowerInvariant()
                    if($helpText.Contains($topic)){
                        $lines=@($helpText[$topic])
                        Write-Host $lines[0] -ForegroundColor Cyan
                        Write-AssessmentWrappedLine -Text $lines[1] -Indent 2 -ForegroundColor Gray
                        if($lines.Count -gt 2){
                            Write-Host '  Examples:' -ForegroundColor DarkCyan
                            for($lineIndex=2;$lineIndex -lt $lines.Count;$lineIndex++){
                                Write-Host ('    '+$lines[$lineIndex]) -ForegroundColor Green
                            }
                        }
                    }
                    elseif($topic -in $allowed){Write-Host "$topic - Collector-specific command. Run examples for a safe usage pattern."}
                    else{Write-Warning "Unknown help topic '$topic'. Available commands: $($allowed -join ', ')"}
                } else {
                    Write-Host ('Commands: '+($allowed -join ', '))
                    Write-Host 'Typical workflow: options -> set -> doctor -> plan -> collect -> analyze -> validate.' -ForegroundColor DarkGray
                    Write-Host 'Use help <command> for details and examples; use options <name> for requirements.' -ForegroundColor DarkGray
                }
                continue AssessmentConsoleLoop
            }
            'examples'{
                Write-Host 'Safe workflow examples' -ForegroundColor Cyan
                $Examples|ForEach-Object{Write-Host ('  '+$_) -ForegroundColor Green}
                continue AssessmentConsoleLoop
            }
            'options'{
                $selected=@($optionNames)
                if($args.Count){
                    $requested=$args[0]
                    $canonical=@($optionNames|Where-Object{$_ -ieq $requested}|Select-Object -First 1)
                    if(-not $canonical.Count){Write-Warning "Unknown option '$requested'. Available options: $($optionNames -join ', ')";continue AssessmentConsoleLoop}
                    $selected=@($canonical[0])
                }
                if(-not $args.Count){
                    Write-Host 'Current session options' -ForegroundColor Cyan
                    foreach($key in $selected){
                        $value=if($localOnlyMode -and $key -match '(?i)salt'){'<not needed - local-only mode>'}elseif($key -match '(?i)salt' -and $Session[$key]){'<configured - hidden>'}elseif($Session[$key]){[string]$Session[$key]}else{'<not set>'}
                        if($value.Length -gt 52){$value=$value.Substring(0,49)+'...'}
                        Write-Host ('  {0,-14} {1}' -f $key,$value)
                    }
                    Write-Host 'Use options <name> for requirement, default, allowed values, purpose, and example.' -ForegroundColor DarkGray
                    continue AssessmentConsoleLoop
                }
                foreach($key in $selected){
                    $meta=if($optionMeta.ContainsKey($key)){$optionMeta[$key]}else{@{Required='collector-specific';Default='collector default';Purpose='Collector-specific session option.';Example="set $key <value>"}}
                    if($localOnlyMode -and $key -match '(?i)salt'){
                        $meta=@{Required='Not needed in local-only mode';Default='not used';Purpose='Tokenization was disabled by the explicit launch argument. No salt or token map is created.';Example='Not applicable'}
                    }
                    elseif($localOnlyMode -and $key -eq 'InputDir'){
                        $meta=@{Required='optional analyzer override';Default='<WorkDir>\Raw_DO_NOT_UPLOAD';Purpose='Local-only analysis reads raw local exports. This input must never be uploaded.';Example='set InputDir C:\Assessments\Run01\Raw_DO_NOT_UPLOAD'}
                    }
                    elseif($localOnlyMode -and $key -eq 'OutputDir'){
                        $meta=@{Required='optional analyzer override';Default='<WorkDir>\Private_DO_NOT_UPLOAD\Output';Purpose='Local-only reports may contain identifiable values and remain private.';Example='set OutputDir C:\Assessments\Run01\Private_DO_NOT_UPLOAD\Output'}
                    }
                    elseif($localOnlyMode -and $key -eq 'WorkingDir'){
                        $meta=@{Required='optional analyzer override';Default='<WorkDir>\Private_DO_NOT_UPLOAD\Working';Purpose='Private analyzer workspace for a local-only run; do not upload it.';Example='set WorkingDir C:\Assessments\Run01\Private_DO_NOT_UPLOAD\Working'}
                    }
                    $value=if($localOnlyMode -and $key -match '(?i)salt'){'<not needed - local-only mode>'}elseif($key -match '(?i)salt' -and $Session[$key]){'<configured - hidden>'}elseif($Session[$key]){[string]$Session[$key]}else{'<not set>'}
                    $allowedValues=if($CompletionValues.ContainsKey($key)){@($CompletionValues[$key]) -join ', '}elseif($key -match '(?i)dir|file|work'){'path'}else{'collector-defined'}
                    Write-Host $key -ForegroundColor Cyan
                    Write-Host "  Current  : $value"
                    Write-Host "  Source   : $($optionSources[$key])"
                    Write-Host "  Required : $($meta.Required)"
                    Write-Host "  Default  : $($meta.Default)"
                    Write-Host "  Allowed  : $allowedValues"
                    Write-Host '  Purpose  :' -ForegroundColor DarkCyan
                    Write-AssessmentWrappedLine -Text ([string]$meta.Purpose) -Indent 4 -ForegroundColor Gray
                    Write-Host "  Example  : $($meta.Example)" -ForegroundColor Green
                }
                continue AssessmentConsoleLoop
            }
            'set'{
                if($args.Count -ge 2){
                    $requested=$args[0]
                    $canonical=@($optionNames|Where-Object{$_ -ieq $requested}|Select-Object -First 1)
                    if(-not $canonical.Count){Write-Warning "Unknown option '$requested'. Use options to list valid names.";continue AssessmentConsoleLoop}
                    $key=$canonical[0]
                    $value=$args[1..($args.Count-1)]-join ' '
                    if($CompletionValues.ContainsKey($key)){
                        $allowedValue=@($CompletionValues[$key]|Where-Object{$_ -ieq $value}|Select-Object -First 1)
                        if(-not $allowedValue.Count){Write-Warning "Invalid value '$value' for $key. Allowed: $($CompletionValues[$key] -join ', ')";continue AssessmentConsoleLoop}
                        $value=$allowedValue[0]
                    }
                    $Session[$key]=$value
                    $optionSources[$key]='Interactive set'
                    if($key -match '(?i)salt'){Write-Host "$key set (hidden)."}else{Write-Host "$key set."}
                }else{Write-Host 'Usage: set <name> <value>. Run options to list valid names.' -ForegroundColor Yellow}
                continue AssessmentConsoleLoop
            }
            'last'{$safe=[ordered]@{};foreach($key in $Session.Keys){if($key -notmatch '(?i)salt' -and $key -notmatch '^_'){$safe[$key]=$Session[$key]}};[pscustomobject]$safe|Format-List;continue AssessmentConsoleLoop}
        }
        $handler=$null;if($Commands.ContainsKey($name)){$handler=$Commands[$name]}elseif($Commands.ContainsKey('_'+$name)){$handler=$Commands['_'+$name]}
        if(-not $handler){Write-Host "$name is not implemented by this collector." -ForegroundColor Yellow;continue}
        try{$Session['LastResult']=& $handler $args $Session}catch{Write-Warning "Command failed [$name]: $($_.Exception.Message)"}
    }
}
