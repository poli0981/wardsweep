#Requires -Version 7.0
<#
.SYNOPSIS
    Runs the automatable half of spike S3 and writes a transcript.

.DESCRIPTION
    Drives every S3 acceptance check from docs/13-P0-SPIKES.md that does not
    need a human to look at the screen, and asserts on the S3| facts the broker
    and UI emit. The checks that cannot be scripted — how many UAC prompts
    appear and when — are in RUNBOOK.md and are gated behind -Interactive.

    Nothing here is destructive. The spike binaries perform no removal of any
    kind; this script creates a state directory, runs them, and force-stops the
    spike's own processes.

.PARAMETER Interactive
    Also run the elevation checks, which raise a real UAC prompt and therefore
    need someone at the keyboard.

.PARAMETER SkipBuild
    Use whatever is already staged in bin/.

.PARAMETER StateDirectory
    Where the spike keeps its database and session file. Never
    %ProgramData%\WardSweep, which is the real product's state root.

.PARAMETER TranscriptPath
    Where to write the transcript. Defaults to inside the state directory
    rather than the repository: a transcript contains the full paths of a real
    machine and the launching user's SID, which is the same reason
    .gitignore excludes raw observation snapshots.
#>
[CmdletBinding()]
param(
    [switch] $Interactive,
    [switch] $SkipBuild,
    [string] $StateDirectory = (Join-Path $env:LOCALAPPDATA 'WardSweep\spike-s3'),
    [string] $TranscriptPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$spikeRoot = Split-Path -Parent $PSScriptRoot
$binaries = Join-Path $spikeRoot 'bin'
$broker = Join-Path $binaries 's3-broker.exe'
$ui = Join-Path $binaries 'S3.Ui.exe'
$intruder = Join-Path $binaries 'S3.Intruder.exe'

if (-not $TranscriptPath) {
    $TranscriptPath = Join-Path $StateDirectory ('transcript-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

$script:Checks = [System.Collections.Generic.List[object]]::new()
$script:Transcript = [System.Collections.Generic.List[string]]::new()

function Write-Line {
    param([string] $Text, [string] $Colour = 'Gray')
    $script:Transcript.Add($Text)
    Write-Host $Text -ForegroundColor $Colour
}

function Write-Section {
    param([string] $Title)
    Write-Line ''
    Write-Line "=== $Title ===" 'Cyan'
}

function Add-Check {
    param(
        [Parameter(Mandatory)] [string] $Criterion,
        [Parameter(Mandatory)] [string] $Name,
        [bool] $Passed = $false,
        [switch] $Skipped,
        [string] $Detail = ''
    )
    # SKIP is not a quiet PASS. A check that could not run says so, and the exit
    # code counts only real failures — otherwise "ran it from the wrong shell"
    # and "the design is broken" look identical in the summary.
    $status = if ($Skipped) { 'SKIP' } elseif ($Passed) { 'PASS' } else { 'FAIL' }
    $script:Checks.Add([pscustomobject]@{
        Criterion = $Criterion
        Name      = $Name
        Status    = $status
        Detail    = $Detail
    })
    $colour = switch ($status) { 'PASS' { 'Green' } 'FAIL' { 'Red' } default { 'Yellow' } }
    Write-Line ("  [{0}] {1} — {2}" -f $status, $Name, $Detail) $colour
}

# Run something and return its output as an array of lines, echoing as it goes.
function Invoke-Capture {
    param([string] $FilePath, [string[]] $Arguments)
    Write-Line ("  > {0} {1}" -f (Split-Path -Leaf $FilePath), ($Arguments -join ' ')) 'DarkGray'
    $output = & $FilePath @Arguments 2>&1 | ForEach-Object { "$_" }
    # Echoed, not just recorded. The transcript is written at the end, so a run
    # that dies part-way leaves nothing behind — and a silent harness is one you
    # cannot debug from the console you are watching.
    foreach ($line in $output) {
        $script:Transcript.Add("    $line")
        Write-Host "    $line" -ForegroundColor DarkGray
    }
    return @($output)
}

# The value of one key from an S3| fact line matching a selector.
#
# The line must both match the selector and actually carry the key. Matching on
# the selector alone silently returns $null whenever two fact lines share a
# prefix — which reads exactly like the check failing.
function Get-Fact {
    param([string[]] $Lines, [string] $Selector, [string] $Key)
    $pattern = "\|{0}=" -f [regex]::Escape($Key)
    $match = $Lines |
        Where-Object { ($_ -like "S3|$Selector*") -and ($_ -match $pattern) } |
        Select-Object -Last 1
    if (-not $match) { return $null }
    foreach ($field in ($match -split '\|')) {
        if ($field -like "$Key=*") { return $field.Substring($Key.Length + 1) }
    }
    return $null
}

function Get-EventSequence {
    param([string[]] $Lines)
    $seqs = foreach ($line in $Lines) {
        if ($line -match '^S3\|event\|seq=(\d+)\|') { [int]$Matches[1] }
    }
    return @($seqs)
}

function Start-Broker {
    param([string] $Session, [string] $LogPath, [string[]] $Extra = @())
    $arguments = @(
        '--session', $Session,
        '--state-dir', $StateDirectory,
        '--expect-client', 'S3.Ui.exe'
    ) + $Extra
    Write-Line ("  > start s3-broker {0}" -f ($arguments -join ' ')) 'DarkGray'
    return Start-Process -FilePath $broker -ArgumentList $arguments -NoNewWindow -PassThru `
        -RedirectStandardOutput $LogPath -RedirectStandardError "$LogPath.err"
}

function Stop-Broker {
    param($Process)
    if ($Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $Process.WaitForExit(5000) | Out-Null
    }
}

function Read-BrokerLog {
    param([string] $LogPath)
    if (-not (Test-Path -LiteralPath $LogPath)) { return @() }
    return @(Get-Content -LiteralPath $LogPath -ErrorAction SilentlyContinue)
}

# Block until a log has at least $Count lines matching $Pattern.
#
# Used to kill the broker at a known point rather than at a convenient one.
function Wait-ForFact {
    param([string] $LogPath, [string] $Pattern, [int] $Count = 1, [int] $TimeoutMs = 20000)
    $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
    while ((Get-Date) -lt $deadline) {
        $hits = @(Read-BrokerLog $LogPath | Where-Object { $_ -like $Pattern })
        if ($hits.Count -ge $Count) { return $true }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

# Kill anything the spike left behind.
#
# A broker that outlived its section keeps the database open, so the next
# section's Reset-State cannot delete it and that section then measures the
# previous one's leftovers. Only the spike's own binaries are matched, by exact
# name; nothing else on the machine is touched.
function Stop-StrayProcesses {
    $strays = @(Get-Process -Name 's3-broker', 'S3.Ui', 'S3.Intruder' -ErrorAction SilentlyContinue)
    foreach ($stray in $strays) {
        Write-Line ("  stopping stray {0} (pid {1})" -f $stray.ProcessName, $stray.Id) 'Yellow'
        Stop-Process -Id $stray.Id -Force -ErrorAction SilentlyContinue
    }
    if ($strays.Count -gt 0) { Start-Sleep -Milliseconds 300 }
}

# Clear the database and session file, and say so if it did not work.
#
# This used to swallow every failure. It cost a run: a leaked broker held
# jobs.db open, the delete silently did nothing, and the next case measured a
# database it had not written — which surfaced as an unexplained FAIL rather
# than as "the file is still locked".
function Reset-State {
    Stop-StrayProcesses
    if (-not (Test-Path -LiteralPath $StateDirectory)) {
        New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
        return
    }

    $stale = @(Get-ChildItem -LiteralPath $StateDirectory -Filter 'jobs.db*' -ErrorAction SilentlyContinue)
    $stale += @(Get-Item -LiteralPath (Join-Path $StateDirectory 'session.json') -ErrorAction SilentlyContinue)
    foreach ($file in $stale) {
        try {
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
        }
        catch {
            Write-Line ("  WARNING: could not delete {0} — {1}" -f $file.Name, $_.Exception.Message) 'Red'
            Write-Line '  the next check will measure leftovers from the previous one' 'Red'
        }
    }
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

Write-Line "Spike S3 — split-privilege architecture" 'White'
Write-Line "state directory : $StateDirectory"
Write-Line "transcript      : $TranscriptPath"
Write-Line "interactive     : $Interactive"

if (-not $SkipBuild) {
    Write-Section 'Build'
    Push-Location (Join-Path $spikeRoot 'broker')
    try {
        cargo build 2>&1 | ForEach-Object { $script:Transcript.Add("    $_") }
        if ($LASTEXITCODE -ne 0) { throw 'the broker did not build' }
    }
    finally { Pop-Location }

    New-Item -ItemType Directory -Path $binaries -Force | Out-Null
    Copy-Item (Join-Path $spikeRoot 'broker\target\debug\s3-broker.exe') $binaries -Force

    foreach ($project in @('ui\S3.Ui.csproj', 'intruder\S3.Intruder.csproj')) {
        dotnet build (Join-Path $spikeRoot $project) -c Release -o $binaries 2>&1 |
            ForEach-Object { $script:Transcript.Add("    $_") }
        if ($LASTEXITCODE -ne 0) { throw "$project did not build" }
    }
    Write-Line '  built and staged into bin/' 'Green'
}

New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null

# ---------------------------------------------------------------------------
# Preflight — is this shell elevated?
# ---------------------------------------------------------------------------
#
# An elevated shell starts an elevated child with no prompt, so criteria 1 and 2
# measure nothing from one: the audit broker inherits high integrity and reports
# elevated=true, and no consent prompt ever appears at Apply. Reporting that as
# a FAIL would be wrong — the design is fine, the shell is not — so those checks
# are skipped and said to be skipped. Everything else is elevation-independent
# and still runs.

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$hostElevated = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Line ("host shell elevated : {0}" -f $hostElevated)
if ($hostElevated) {
    Write-Line '' 
    Write-Line 'WARNING: this shell is elevated. Criteria 1 and 2 cannot be measured from it —' 'Yellow'
    Write-Line 'an elevated parent spawns an elevated child silently. Rerun from a normal shell.' 'Yellow'
}

# ---------------------------------------------------------------------------
# Criterion 1 — unelevated audit
# ---------------------------------------------------------------------------

Write-Section 'Criterion 1 — unelevated audit, no UAC prompt'
if ($hostElevated) {
    Add-Check -Criterion 'C1' -Name 'broker reports an unelevated token' -Skipped `
        -Detail 'host shell is elevated; the child inherits it and the check would measure the shell'
    Add-Check -Criterion 'C1' -Name 'a synthetic audit scan completes over the pipe' -Skipped `
        -Detail 'skipped with the rest of C1'
}
else {
    Reset-State
    $session = [guid]::NewGuid().ToString()
    $output = Invoke-Capture $ui @('spawn-audit', '--session', $session, '--state-dir', $StateDirectory, '--broker', $broker)

    Add-Check -Criterion 'C1' -Name 'broker reports an unelevated token' `
        -Passed ((Get-Fact $output 'audit|' 'elevated') -eq 'false') `
        -Detail ("elevated={0}" -f (Get-Fact $output 'audit|' 'elevated'))

    Add-Check -Criterion 'C1' -Name 'a synthetic audit scan completes over the pipe' `
        -Passed ((Get-Fact $output 'audit|scan_complete' 'scan_complete') -eq 'True') `
        -Detail ("total={0}" -f (Get-Fact $output 'audit|scan_complete' 'total'))
}

# ---------------------------------------------------------------------------
# Criterion 3a — the DACL on the live object
# ---------------------------------------------------------------------------

Write-Section 'Criterion 3a — pipe DACL, read back off the handle'
if ($hostElevated) {
    # The audit broker did not run, so borrow a pipe from a broker started here.
    Reset-State
    $session = [guid]::NewGuid().ToString()
    $daclLog = Join-Path $StateDirectory 'broker-dacl.log'
    $daclProcess = Start-Broker -Session $session -LogPath $daclLog
    Start-Sleep -Milliseconds 800
    $output = Read-BrokerLog $daclLog
    Stop-Broker $daclProcess
}
$daclAcceptable = Get-Fact $output 'dacl|observed' 'acceptable'
Add-Check -Criterion 'C3a' -Name 'DACL is protected, names the user, and grants nobody else' `
    -Passed ($daclAcceptable -eq 'true') `
    -Detail ("observed={0}" -f (Get-Fact $output 'dacl|observed' 'observed'))

Add-Check -Criterion 'C3a' -Name 'no Everyone ACE' `
    -Passed ((Get-Fact $output 'dacl|observed' 'everyone') -eq 'false') -Detail 'WD absent'

Add-Check -Criterion 'C3a' -Name 'no Authenticated Users ACE' `
    -Passed ((Get-Fact $output 'dacl|observed' 'authenticated_users') -eq 'false') -Detail 'AU absent'

# ---------------------------------------------------------------------------
# Criteria 3b, 3c, 4 — who is allowed to talk to the broker
# ---------------------------------------------------------------------------

Write-Section 'Criteria 3b/3c/4 — client verification and the single instance'
Reset-State
$session = [guid]::NewGuid().ToString()
$log = Join-Path $StateDirectory 'broker-clients.log'
$process = Start-Broker -Session $session -LogPath $log -Extra @('--ticks-per-stage', '40', '--tick-ms', '250')
Start-Sleep -Milliseconds 800

try {
    $intruderOutput = Invoke-Capture $intruder @('connect', $session, '3000')
    $brokerLog = Read-BrokerLog $log

    Add-Check -Criterion 'C3b/C4' -Name 'a different image is refused, though the DACL admits it' `
        -Passed ((Get-Fact $brokerLog 'accept|' 'verdict') -eq 'refused') `
        -Detail ("reason={0}" -f (Get-Fact $brokerLog 'accept|' 'reason'))

    $refusedAfterConnect = (Get-Fact $intruderOutput 'intruder|mode=connect' 'refused_after_connect')
    $helloOutcome = ($intruderOutput | Where-Object { $_ -like 'S3|intruder|*hello=*' } | Select-Object -Last 1)
    Add-Check -Criterion 'C3b' -Name 'the intruder is hung up on before it can issue a command' `
        -Passed (($refusedAfterConnect -eq 'true') -or ($helloOutcome -like '*disconnected_by_broker*') -or ($helloOutcome -like '*closed_without_reply*')) `
        -Detail ("refused_after_connect={0}; {1}" -f $refusedAfterConnect, $helloOutcome)

    # Hold the single instance with a real client, then try a second one.
    $streamLog = Join-Path $StateDirectory 'ui-holding.log'
    $holder = Start-Process -FilePath $ui -NoNewWindow -PassThru -RedirectStandardOutput $streamLog `
        -RedirectStandardError "$streamLog.err" `
        -ArgumentList @('stream', '--session', $session, '--state-dir', $StateDirectory, '--stop-after', '200')
    Start-Sleep -Seconds 2

    $secondOutput = Invoke-Capture $intruder @('second', $session, '2000')
    $secondResult = Get-Fact $secondOutput 'intruder|' 'result'
    Add-Check -Criterion 'C3c' -Name 'a second client does not get served while the first holds the instance' `
        -Passed ($secondResult -ne 'connected') `
        -Detail ("result={0} (docs/08 says 'refused, not queued'; WaitNamedPipe in fact queues the waiter)" -f $secondResult)

    # Criterion 5 needs this client gone abruptly, so kill it rather than ask.
    Write-Section 'Criterion 5 — UI killed mid-stream, broker continues, UI reconnects'
    Stop-Process -Id $holder.Id -Force -ErrorAction SilentlyContinue
    $holder.WaitForExit(5000) | Out-Null
    $firstLeg = Read-BrokerLog $streamLog
    $firstSeqs = Get-EventSequence $firstLeg
    Write-Line ("  first leg saw {0} events, up to seq {1}" -f $firstSeqs.Count, ($firstSeqs | Measure-Object -Maximum).Maximum)

    Start-Sleep -Milliseconds 500
    $brokerLog = Read-BrokerLog $log
    Add-Check -Criterion 'C5' -Name 'the broker notices the client is gone and keeps the job running' `
        -Passed ((Get-Fact $brokerLog 'client-gone' 'job_continues') -eq 'true') `
        -Detail ("client-gone at_seq={0}" -f (Get-Fact $brokerLog 'client-gone' 'at_seq'))

    $secondLeg = Invoke-Capture $ui @('resume', '--session', $session, '--state-dir', $StateDirectory)
    $secondSeqs = Get-EventSequence $secondLeg

    $all = @($firstSeqs) + @($secondSeqs)
    $duplicates = @($all | Group-Object | Where-Object Count -gt 1 | ForEach-Object { $_.Name })
    $sorted = @($all | Sort-Object)
    $expected = if ($sorted.Count -gt 0) { 1..($sorted[-1]) } else { @() }
    $missing = @(Compare-Object -ReferenceObject $expected -DifferenceObject $sorted |
        Where-Object SideIndicator -eq '<=' | ForEach-Object { $_.InputObject })

    Add-Check -Criterion 'C5' -Name 'the resumed stream has no gap' `
        -Passed ($missing.Count -eq 0) `
        -Detail ("{0} events across two legs, missing: {1}" -f $all.Count, ($(if ($missing.Count) { $missing -join ',' } else { 'none' })))

    Add-Check -Criterion 'C5' -Name 'the resumed stream has no duplicate' `
        -Passed ($duplicates.Count -eq 0) `
        -Detail ("duplicates: {0}" -f ($(if ($duplicates.Count) { $duplicates -join ',' } else { 'none' })))

    # ---------------------------------------------------------------------
    # Pipe squatting during the elevation handover
    # ---------------------------------------------------------------------

    Write-Section 'Handover — FILE_FLAG_FIRST_PIPE_INSTANCE against a squatter'
    $squat = Invoke-Capture $broker @('--session', $session, '--mode', 'squat', '--state-dir', $StateDirectory)
    Add-Check -Criterion 'Handover' -Name 'a second process cannot create an instance of a live pipe name' `
        -Passed ((Get-Fact $squat 'squat|' 'result') -eq 'refused') `
        -Detail ("result={0}" -f (Get-Fact $squat 'squat|' 'result'))
}
finally {
    Stop-Broker $process
}

# ---------------------------------------------------------------------------
# Criterion 6 — broker killed, UI reads state read-only, per journal mode
# ---------------------------------------------------------------------------

Write-Section 'Criterion 6 — broker force-killed, database opened read-only'

# The fourth case is the counterfactual: WAL with the per-stage checkpoint
# turned off. Without it, "WAL survives a kill" would be an untested attribution
# — the checkpoint might be doing all the work, or none of it.
$cases = @(
    @{ Journal = 'wal';      Checkpoint = $true  },
    @{ Journal = 'delete';   Checkpoint = $true  },
    @{ Journal = 'truncate'; Checkpoint = $true  },
    @{ Journal = 'wal';      Checkpoint = $false }
)

foreach ($case in $cases) {
    $journal = $case.Journal
    $label = if ($case.Checkpoint) { $journal } else { "$journal, no checkpoint" }
    Reset-State
    $session = [guid]::NewGuid().ToString()
    $log = Join-Path $StateDirectory ("broker-{0}.log" -f ($label -replace '[^a-z]', '-'))
    # --stall-commit-ms holds each commit transaction open, and the broker says
    # so on the way in. The harness waits for the *third* such window, so stages
    # 0 and 1 are committed and stage 2's journal is on disk uncommitted at the
    # moment of the kill.
    #
    # An earlier version just slept and killed. It passed four runs and failed
    # the fifth, because whether a hot journal existed depended on where the
    # kill happened to land — which is how a real hazard gets recorded as a pass.
    $extra = @(
        '--journal-mode', $journal,
        '--ticks-per-stage', '3', '--tick-ms', '80',
        '--stall-commit-ms', '1500'
    )
    if (-not $case.Checkpoint) { $extra += '--no-checkpoint' }
    $process = Start-Broker -Session $session -LogPath $log -Extra $extra
    Start-Sleep -Milliseconds 500

    try {
        $streamLog = Join-Path $StateDirectory ("ui-{0}.log" -f ($label -replace '[^a-z]', '-'))
        $holder = Start-Process -FilePath $ui -NoNewWindow -PassThru -RedirectStandardOutput $streamLog `
            -RedirectStandardError "$streamLog.err" `
            -ArgumentList @('stream', '--session', $session, '--state-dir', $StateDirectory, '--stop-after', '200')
        $inTransaction = Wait-ForFact -LogPath $log -Pattern 'S3|commit|*state=stalling*' -Count 3
        if (-not $inTransaction) {
            Write-Line '  WARNING: never observed a third commit window; the kill is not positioned' 'Yellow'
        }

        # Force-kill the writer with a write transaction open. This is the state
        # that decides whether a read-only open is possible at all.
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        $process.WaitForExit(5000) | Out-Null
        Stop-Process -Id $holder.Id -Force -ErrorAction SilentlyContinue

        $leftovers = @(Get-ChildItem -LiteralPath $StateDirectory -Filter 'jobs.db*' |
            ForEach-Object { $_.Name }) -join ','
        Write-Line "  journal=$journal leftovers: $leftovers"

        $stateOutput = Invoke-Capture $ui @('read-state', '--state-dir', $StateDirectory)
        $result = Get-Fact $stateOutput 'read-state|' 'result'
        $lastSeq = [int](Get-Fact $stateOutput 'read-state|' 'last_seq')
        $stages = [int](Get-Fact $stateOutput 'read-state|' 'stages_completed')

        # Every row is recorded rather than gated. Which journal modes survive a
        # kill inside a transaction is the measurement; failing the run because
        # one of them does not would hide the answer behind a red tick.
        # docs/03 only needs *a* mode that works, and the result document names it.
        Add-Check -Criterion 'C6' -Name "journal_mode=$label : killed inside a transaction" -Passed $true `
            -Detail ("read-only open={0}; stages_completed={1} of 7; last_seq={2}; files={3}" -f `
                $result, $stages, $lastSeq, $leftovers)
    }
    finally {
        Stop-Broker $process
    }
}

# ---------------------------------------------------------------------------
# Criterion 6, continued — the same read, where the reader cannot write
# ---------------------------------------------------------------------------
#
# Everything above ran with the database under %LOCALAPPDATA%, which the UI
# owns. docs/03-ARCHITECTURE.md puts the real one under
# %ProgramData%\WardSweep\jobs\, where a medium-integrity UI typically has read
# access and nothing more — and SQLite needs to *write* the -shm file to read a
# WAL database. So the result above may not transfer, and the difference is
# worth measuring rather than recording as an open question.
#
# Simulated with the read-only file attribute rather than by editing an ACL:
# it blocks a write open just as effectively, is scoped to files this script
# copied, and changes no security setting on the machine.

Write-Section 'Criterion 6 — the same read, with the sidecar files unwritable'
$sealed = Join-Path $StateDirectory 'sealed'
try {
    Remove-Item -LiteralPath $sealed -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $sealed -Force | Out-Null

    # The last case left a WAL database with an uncheckpointed -wal behind.
    $copied = @()
    foreach ($file in @('jobs.db', 'jobs.db-wal', 'jobs.db-shm')) {
        $source = Join-Path $StateDirectory $file
        if (Test-Path -LiteralPath $source) {
            Copy-Item -LiteralPath $source -Destination $sealed -Force
            $target = Join-Path $sealed $file
            Set-ItemProperty -LiteralPath $target -Name IsReadOnly -Value $true
            $copied += $file
        }
    }
    Write-Line "  sealed copies: $($copied -join ',')"

    $writableOutput = Invoke-Capture $ui @('read-state', '--state-dir', $StateDirectory)
    $sealedOutput = Invoke-Capture $ui @('read-state', '--state-dir', $StateDirectory, '--database', (Join-Path $sealed 'jobs.db'))
    $sealedResult = Get-Fact $sealedOutput 'read-state|' 'result'

    # Recorded, not gated, and either answer changes the design. If it fails,
    # the UI cannot read job state from %ProgramData% at all and the broker has
    # to hand the snapshot over some other way.
    Add-Check -Criterion 'C6' -Name 'read-only open when the sidecar files cannot be written' -Passed $true `
        -Detail ("result={0}; error={1}" -f $sealedResult, (Get-Fact $sealedOutput 'read-state|' 'error'))

    # Succeeding is not enough — a read that silently returns the pre-WAL state
    # would look identical from the outside and be far worse than a failure.
    $sealedSeq = Get-Fact $sealedOutput 'read-state|' 'last_seq'
    $writableSeq = Get-Fact $writableOutput 'read-state|' 'last_seq'
    Add-Check -Criterion 'C6' -Name 'the unwritable read is current, not stale' `
        -Passed (($sealedResult -eq 'ok') -and ($sealedSeq -eq $writableSeq)) `
        -Detail ("sealed last_seq={0}, writable last_seq={1}" -f $sealedSeq, $writableSeq)

    # And the counter-test: the base file on its own. In WAL mode with no
    # checkpoint it holds nothing at all, not even the schema — so anything that
    # collects jobs.db without its sidecars (a diagnostics bundle, a backup)
    # gathers a file that is not a database.
    $baseOnly = Join-Path $StateDirectory 'base-only'
    New-Item -ItemType Directory -Path $baseOnly -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $StateDirectory 'jobs.db') -Destination $baseOnly -Force
    $baseOutput = Invoke-Capture $ui @('read-state', '--state-dir', $StateDirectory, '--database', (Join-Path $baseOnly 'jobs.db'))
    Add-Check -Criterion 'C6' -Name 'jobs.db without its -wal is not self-contained' -Passed $true `
        -Detail ("result={0}; error={1}" -f `
            (Get-Fact $baseOutput 'read-state|' 'result'), (Get-Fact $baseOutput 'read-state|' 'error'))
    Remove-Item -LiteralPath $baseOnly -Recurse -Force -ErrorAction SilentlyContinue
}
finally {
    if (Test-Path -LiteralPath $sealed) {
        Get-ChildItem -LiteralPath $sealed -Force | ForEach-Object {
            Set-ItemProperty -LiteralPath $_.FullName -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $sealed -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Duplex probe — does a synchronous handle serialise read against write?
# ---------------------------------------------------------------------------

Write-Section 'Probe — synchronous handle, concurrent read and write'
Reset-State
$session = [guid]::NewGuid().ToString()
$log = Join-Path $StateDirectory 'broker-duplex.log'
$process = Start-Process -FilePath $broker -NoNewWindow -PassThru -RedirectStandardOutput $log `
    -RedirectStandardError "$log.err" `
    -ArgumentList @('--session', $session, '--mode', 'duplex-probe', '--state-dir', $StateDirectory)
try {
    Start-Sleep -Milliseconds 800
    Invoke-Capture $ui @('duplex-client', '--session', $session, '--state-dir', $StateDirectory) | Out-Null
    $process.WaitForExit(15000) | Out-Null
    $probe = Read-BrokerLog $log
    foreach ($line in $probe) { $script:Transcript.Add("    $line") }

    $serialised = Get-Fact $probe 'duplex|serialised' 'serialised'
    $controlMs = Get-Fact $probe 'duplex|control_write_ms' 'control_write_ms'
    $writeMs = Get-Fact $probe 'duplex|write_ms' 'write_ms'
    Write-Line ("  control_write_ms={0} (no read outstanding), write_ms={1} (read outstanding), read_ms={2}, serialised={3}" -f `
        $controlMs, $writeMs, (Get-Fact $probe 'duplex|read_ms' 'read_ms'), $serialised)

    # Recorded, not asserted. Either answer is a legitimate finding; it decides
    # whether the real broker needs FILE_FLAG_OVERLAPPED to keep ScanCancel
    # reachable while it streams, and that is a design consequence rather than
    # a pass or a fail.
    Add-Check -Criterion 'Probe' -Name 'concurrent read and write on a synchronous handle' `
        -Passed ($null -ne $serialised) `
        -Detail ("control={0}ms, contended={1}ms, serialised={2} (recorded, not a gate)" -f `
            $controlMs, $writeMs, $serialised)
}
finally {
    Stop-Broker $process
}

# ---------------------------------------------------------------------------
# Criterion 2 — one prompt, at apply. Needs a human.
# ---------------------------------------------------------------------------

Write-Section 'Criterion 2 — elevation'
if ($Interactive -and $hostElevated) {
    Add-Check -Criterion 'C2' -Name 'one prompt, at apply' -Skipped `
        -Detail 'host shell is elevated; no prompt would appear and the count would be meaningless'
}
elseif ($Interactive) {
    Write-Line '  A UAC prompt is about to appear. Accept it. See RUNBOOK.md.' 'Yellow'
    Reset-State
    $session = [guid]::NewGuid().ToString()
    $factFile = Join-Path $StateDirectory 'broker-elevated.facts'
    Remove-Item -LiteralPath $factFile -Force -ErrorAction SilentlyContinue

    $output = Invoke-Capture $ui @(
        'spawn-apply', '--session', $session, '--state-dir', $StateDirectory,
        '--broker', $broker, '--fact-file', $factFile)

    $elevated = Get-Fact $output 'apply|elevated' 'elevated'
    # @() around the pipeline: Where-Object yields $null when nothing matches,
    # and $null.Count is a hard error under Set-StrictMode.
    $declined = @($output | Where-Object { $_ -like '*uac_declined*' }).Count -gt 0
    $fatal = @($output | Where-Object { $_ -like 'S3|fatal|*' })

    if ($declined) {
        Add-Check -Criterion 'C2' -Name 'a declined prompt starts no job' -Passed $true `
            -Detail 'ERROR_CANCELLED surfaced as uac_declined; nothing was written'
    }
    elseif ($fatal.Count -gt 0) {
        Add-Check -Criterion 'C2' -Name 'the elevated broker was reachable' -Passed $false `
            -Detail ("the UI reported: {0}" -f ($fatal -join '; '))
    }
    else {
        Add-Check -Criterion 'C2' -Name 'the broker spawned with runas is elevated' `
            -Passed ($elevated -eq 'true') -Detail ("elevated={0}" -f $elevated)
        $facts = @(Read-BrokerLog $factFile)
        Add-Check -Criterion 'C2' -Name 'the elevated broker reports through --fact-file' `
            -Passed ($facts.Count -gt 0) `
            -Detail ("{0} facts; runas forces UseShellExecute so stdout cannot be inherited" -f $facts.Count)
        Add-Check -Criterion 'C2' -Name 'the elevated broker ran the job to completion' `
            -Passed ($null -ne (Get-Fact $output 'apply|last_seq' 'last_seq')) `
            -Detail ("last_seq={0}" -f (Get-Fact $output 'apply|last_seq' 'last_seq'))
    }
}
else {
    Write-Line '  skipped — rerun with -Interactive. RUNBOOK.md covers the manual observation.' 'Yellow'
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Section 'Summary'
$failed = @($script:Checks | Where-Object { $_.Status -eq 'FAIL' })
$skipped = @($script:Checks | Where-Object { $_.Status -eq 'SKIP' })
foreach ($check in $script:Checks) {
    Write-Line ("  {0,-9} {1,-5} {2}" -f $check.Criterion, $check.Status, $check.Name)
}
Write-Line ''
Write-Line ("{0} checks, {1} failed, {2} skipped" -f $script:Checks.Count, $failed.Count, $skipped.Count) `
    $(if ($failed.Count) { 'Red' } elseif ($skipped.Count) { 'Yellow' } else { 'Green' })

New-Item -ItemType Directory -Path (Split-Path -Parent $TranscriptPath) -Force | Out-Null
$script:Transcript | Set-Content -LiteralPath $TranscriptPath -Encoding utf8
Write-Host "transcript written to $TranscriptPath" -ForegroundColor Cyan

exit $failed.Count
