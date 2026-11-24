[CmdletBinding()]
param(
    [Parameter(Mandatory)] $Page,
    [Parameter(Mandatory)] $App
)

$controls = $App.GetControls($Page, @(
    'TxtSource', 'TxtTarget', 'TxtScope', 'BtnPickSource', 'BtnPickTarget', 'BtnBrowseScope',
    'ChkIncludeFiles', 'ChkOverrideGuard', 'RbModeScan', 'RbModeLive', 'BtnPreview',
    'BtnExecute', 'BtnVerify', 'TxtPreviewStatus', 'TxtConfirm', 'GrdPreview',
    'TxtPreviewSummary', 'GrdExecute', 'PbExecute', 'GrdVerify', 'TxtVerifySummary'
))
$helperPath = Join-Path $PSScriptRoot 'SwapAcl.ps1'
$state = [pscustomobject]@{
    Source = $null
    Target = $null
    Generation = 0
    Preview = $null
    LastRun = $null
    RefreshForScan = $null
}
$Page.Tag.State = $state
$auditPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Logs\swap-audit.jsonl'
$protectedSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0', 'S-1-1-0', 'S-1-5-11')

$writeAudit = {
    param([hashtable]$Event)

    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($auditPath))
    $Event.ts = [DateTime]::UtcNow.ToString('o')
    $Event.operator = "$env:USERDOMAIN\$env:USERNAME"
    $Event.host = $env:COMPUTERNAME
    Add-Content -LiteralPath $auditPath -Value ($Event | ConvertTo-Json -Compress) -Encoding UTF8 -ErrorAction Stop
}.GetNewClosure()

$invalidate = {
    $state.Generation++
    $state.Preview = $null
    $App.CancelAsync($Page.Tag, 'SwapPreview')
    $controls.GrdPreview.ItemsSource = $null
    $controls.TxtConfirm.Clear()
    $controls.BtnExecute.IsEnabled = $false
    $controls.TxtPreviewStatus.Text = 'Preview required before execute.'
    $controls.TxtPreviewSummary.Text = ''
}.GetNewClosure()

$setMode = {
    $controls.RbModeScan.IsEnabled = $null -ne $App.CurrentScanId
    if (-not $controls.RbModeScan.IsEnabled) { $controls.RbModeLive.IsChecked = $true }
    $controls.ChkIncludeFiles.IsEnabled = [bool]$controls.RbModeLive.IsChecked
    if (-not $controls.ChkIncludeFiles.IsEnabled) { $controls.ChkIncludeFiles.IsChecked = $false }
}.GetNewClosure()

$state.RefreshForScan = {
    & $invalidate
    & $setMode
    $state.LastRun = $null
    $controls.BtnVerify.IsEnabled = $false
    $controls.GrdExecute.ItemsSource = $null
    $controls.GrdVerify.ItemsSource = $null
    $controls.TxtVerifySummary.Text = ''
}.GetNewClosure()

$contextMatches = {
    param($Inputs)

    $Inputs.Generation -eq $state.Generation -and
        $Inputs.DbPath -eq $App.DbPath -and $Inputs.ScanId -eq $App.CurrentScanId
}.GetNewClosure()

$applyPreview = {
    param($Result, $Owner)

    if (-not (& $contextMatches $Result.Inputs)) { return }

    $count = $Result.Rows.Count
    $controls.GrdPreview.ItemsSource = $Result.Rows
    $controls.TxtPreviewSummary.Text = "Checked $($Result.Visited) path(s). $count will change, $($Result.Skipped) reparse path(s) skipped, $($Result.Errors) read or enumeration error(s)."
    $App.SetStatus("ACL Swap preview: $count affected path(s), $($Result.Errors) error(s).")
    if ($count -eq 0) {
        $controls.TxtPreviewStatus.Text = 'No explicit source rules found.'
        return
    }

    & $writeAudit @{
        event = 'preview'; mode = $Result.Inputs.Mode; scope = $Result.Inputs.Scope
        sourceSid = $Result.Inputs.SourceSid; targetSid = $Result.Inputs.TargetSid
        folderCount = $count; errors = $Result.Errors
    }
    $state.Preview = $Result
    $controls.TxtPreviewStatus.Text = 'Preview ready. Type APPLY to enable Execute.'
}.GetNewClosure()

$reportProgress = {
    param($Progress, $Owner)

    $message = "Checked $($Progress.Visited) path(s), $($Progress.Matches) match(es), $($Progress.Errors) error(s)."
    $controls.TxtPreviewSummary.Text = "$message`nCurrent: $($Progress.Path)"
    $App.BusyText.Text = $message
    $App.SetStatus($message)
}.GetNewClosure()

$runPreview = {
    & $invalidate
    try {
        . $helperPath
        if (-not $state.Source -or -not $state.Target -or $state.Source.Sid -eq $state.Target.Sid) {
            throw 'Choose distinct source and target principals.'
        }
        if ($state.Source.Sid -in $protectedSids -and -not $controls.ChkOverrideGuard.IsChecked) {
            throw 'The source is a protected well-known SID. An override is required.'
        }
        if ($state.Target.Sid -in $protectedSids) { throw 'The target is a protected well-known SID.' }
        $scope = ConvertTo-ShareAclPath $controls.TxtScope.Text
        $protectedPaths = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, (Split-Path -Parent $env:USERPROFILE))
        if ($scope.TrimEnd('\') -eq [IO.Path]::GetPathRoot($scope).TrimEnd('\') -or $scope -in $protectedPaths) {
            throw 'Choose a scope below the drive, share, or system folder root.'
        }

        $mode = if ($controls.RbModeScan.IsChecked) { 'scan' } else { 'live' }
        if ($mode -eq 'scan' -and $null -eq $App.CurrentScanId) { throw 'Select a scan first.' }
        $request = @{
            Generation = $state.Generation; ScanId = $App.CurrentScanId; Mode = $mode; Scope = $scope
            SourceSid = [string]$state.Source.Sid; SourceName = [string]$state.Source.Name
            TargetSid = [string]$state.Target.Sid; TargetName = [string]$state.Target.Name
            TargetSam = $state.Target.Sam; TargetType = $state.Target.Type
            IncludeFiles = $mode -eq 'live' -and [bool]$controls.ChkIncludeFiles.IsChecked
            HelperPath = $helperPath
        }
        $controls.TxtPreviewStatus.Text = 'Checking live rules…'

        [void]$App.StartAsync($Page.Tag, 'SwapPreview', "Checking $scope…", $request, {
            param($Ctx)

            . $Ctx.HelperPath
            if ((Test-ShareAclReparsePath $Ctx.Scope) -or -not [IO.Directory]::Exists($Ctx.Scope)) {
                throw "The scope must be an accessible directory without reparse points: $($Ctx.Scope)"
            }
            $queue = [System.Collections.Generic.Queue[string]]::new()
            $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $errors = 0
            $skipped = 0
            if ($Ctx.Mode -eq 'scan') {
                $candidates = Invoke-SqliteQuery -DataSource $Ctx.DbPath -Query @'
SELECT DISTINCT f.path
FROM aces a JOIN folders f ON f.folder_id = a.folder_id
WHERE f.scan_id = @scan AND a.trustee_sid = @sid AND a.is_inherited = 0
ORDER BY f.path
'@ -SqlParameters @{ scan = $Ctx.ScanId; sid = $Ctx.SourceSid }
                foreach ($candidate in $candidates) {
                    try {
                        $path = ConvertTo-ShareAclPath $candidate.path
                        if (Test-ShareAclPathInScope $path $Ctx.Scope) { $queue.Enqueue($path) }
                    } catch { $errors++ }
                }
            } else {
                $queue.Enqueue($Ctx.Scope)
            }

            $rows = [System.Collections.Generic.List[object]]::new()
            while ($queue.Count -gt 0) {
                $path = $queue.Dequeue()
                if (-not $visited.Add($path)) { continue }
                if (($visited.Count % 25) -eq 0 -and $null -ne $Ctx.ProgressQueue) {
                    $Ctx.ProgressQueue.Enqueue(@{ Visited = $visited.Count; Matches = $rows.Count; Errors = $errors; Path = $path })
                }

                try {
                    if (Test-ShareAclReparsePath $path) { $skipped++; continue }
                    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    if (-not $item.PSIsContainer -and -not $Ctx.IncludeFiles) { continue }
                } catch { $errors++; continue }

                try {
                    $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
                    $descriptor = Get-ShareAclDescriptor $acl
                    $source = @(Get-ShareAclExplicitRules $descriptor.DiscretionaryAcl $Ctx.SourceSid)
                    if ($source.Count -gt 0) {
                        $rows.Add([pscustomobject]@{
                            Path = $path; Inh = if ($acl.AreAccessRulesProtected) { 'N' } else { 'Y' }
                            AceCount = $source.Count; Signature = Get-ShareAclRuleSignature $source
                            SourceRights = ($source | ForEach-Object {
                                '{0} {1} ({2})' -f $_.AceType, ([System.Security.AccessControl.FileSystemRights]$_.AccessMask), $_.AceFlags
                            }) -join '; '
                        })
                    }
                } catch { $errors++ }

                if ($Ctx.Mode -eq 'live' -and $item.PSIsContainer) {
                    try {
                        foreach ($child in Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop) {
                            if ($child.PSIsContainer -or $Ctx.IncludeFiles) { $queue.Enqueue($child.FullName) }
                        }
                    } catch { $errors++ }
                }
            }

            [pscustomobject]@{ Inputs = $Ctx; Rows = $rows.ToArray(); Visited = $visited.Count; Errors = $errors; Skipped = $skipped }
        }, $applyPreview, 'ACL Swap preview failed', $reportProgress)
    } catch {
        $App.ShowError('ACL Swap preview failed', $_.Exception.Message)
    }
}.GetNewClosure()

$runExecute = {
    $preview = $state.Preview
    if ($App.SwapExecuting -or $null -eq $preview -or -not (& $contextMatches $preview.Inputs) -or
        $controls.TxtConfirm.Text.Trim() -ne 'APPLY') { return }

    . $helperPath
    $inputs = $preview.Inputs
    $runId = [guid]::NewGuid().ToString()
    $outcomes = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
    $controls.GrdExecute.ItemsSource = $outcomes
    $controls.PbExecute.Maximum = $preview.Rows.Count
    $controls.PbExecute.Value = 0
    $state.LastRun = $null
    $controls.BtnVerify.IsEnabled = $false
    $App.SwapExecuting = $true
    $App.Window.IsEnabled = $false
    try {
        & $invalidate
        $App.Query(@'
INSERT INTO swap_runs(run_id, started_utc, operator, host, source_sid, source_name,
                      target_sid, target_name, scope_root, based_on_scan, discovery_mode, folder_count)
VALUES (@id, @started, @op, @hostname, @source, @sourceName, @target, @targetName, @scope, @scan, @mode, @count)
'@, @{
            id = $runId; started = [DateTime]::UtcNow.ToString('o'); op = "$env:USERDOMAIN\$env:USERNAME"
            hostname = $env:COMPUTERNAME; source = $inputs.SourceSid; sourceName = $inputs.SourceName
            target = $inputs.TargetSid; targetName = $inputs.TargetName; scope = $inputs.Scope
            scan = if ($inputs.Mode -eq 'scan') { $inputs.ScanId } else { [DBNull]::Value }
            mode = $inputs.Mode; count = $preview.Rows.Count
        }) | Out-Null
        & $writeAudit @{ event = 'execute_begin'; runId = $runId; mode = $inputs.Mode; folderCount = $preview.Rows.Count }

        $ok = 0
        $failed = 0
        foreach ($row in $preview.Rows) {
            try {
                if (-not (Test-ShareAclPathInScope $row.Path $inputs.Scope)) { throw "Path is outside scope: $($row.Path)" }
                $result = Invoke-ShareAclReplacement $row.Path $inputs.SourceSid $inputs.TargetSid $row.Signature
            } catch {
                $result = @{ Code = 'fail'; Detail = $_.Exception.Message }
            }
            if ($result.Code -eq 'ok') { $ok++ }
            if ($result.Code -eq 'fail') { $failed++ }
            $outcomes.Add([pscustomobject]@{
                When = [DateTime]::Now.ToString('HH:mm:ss'); Path = $row.Path
                Result = $result.Code.ToUpperInvariant(); Detail = $result.Detail; Expected = $result.Expected
            })
            & $writeAudit @{
                event = 'execute_op'; runId = $runId; path = $row.Path
                result = $result.Code; detail = $result.Detail; expectedTargetRules = $result.Expected
            }
            $App.Query(@'
INSERT INTO swap_results(run_id, path, result, detail, when_utc) VALUES (@id, @path, @result, @detail, @when)
'@, @{ id = $runId; path = $row.Path; result = $result.Code; detail = $result.Detail; when = [DateTime]::UtcNow.ToString('o') }) | Out-Null
            $controls.PbExecute.Value++
            $Page.Dispatcher.Invoke([Action]{}, 'Background')
        }

        & $writeAudit @{ event = 'execute_end'; runId = $runId; ok = $ok; failed = $failed }
        $App.Query(@'
UPDATE swap_runs SET completed_utc = @done, ok_count = @ok, fail_count = @failed WHERE run_id = @id
'@, @{ id = $runId; done = [DateTime]::UtcNow.ToString('o'); ok = $ok; failed = $failed }) | Out-Null
        if ($ok -gt 0) {
            $App.Query(@'
INSERT INTO principals(sid, name, domain, sam_account_name, principal_type, is_well_known, last_resolved_utc)
VALUES (@sid, @name, @domain, @sam, @type, 0, @now) ON CONFLICT(sid) DO NOTHING
'@, @{
                sid = $inputs.TargetSid; name = $inputs.TargetName; domain = $env:USERDOMAIN
                sam = $inputs.TargetSam; type = $inputs.TargetType; now = [DateTime]::UtcNow.ToString('o')
            }) | Out-Null
        }
        $App.SetStatus("ACL Swap complete: $ok replaced, $failed failed, $($outcomes.Count - $ok - $failed) skipped or changed since preview.")
    } catch {
        $App.Window.IsEnabled = $true
        $App.ShowError('ACL Swap stopped', "Run $runId. $($_.Exception.Message) Review the execute log for paths already processed.")
    } finally {
        $state.LastRun = [pscustomobject]@{ Id = $runId; Inputs = $inputs; Outcomes = $outcomes }
        $controls.BtnVerify.IsEnabled = $outcomes.Count -gt 0
        $App.Window.IsEnabled = $true
        $App.SwapExecuting = $false
    }
}.GetNewClosure()

$runVerify = {
    $run = $state.LastRun
    if ($null -eq $run) { return }
    . $helperPath
    $clean = 0
    $rows = foreach ($row in $run.Outcomes) {
        $status = 'NOT_APPLIED'
        $detail = $row.Detail
        if ($row.Result -eq 'OK') {
            try {
                if (Test-ShareAclReparsePath $row.Path) { throw 'A reparse point is now present in the path.' }
                $descriptor = Get-ShareAclDescriptor (Get-Acl -LiteralPath $row.Path -ErrorAction Stop)
                $source = @(Get-ShareAclExplicitRules $descriptor.DiscretionaryAcl $run.Inputs.SourceSid)
                $target = @(Get-ShareAclExplicitRules $descriptor.DiscretionaryAcl $run.Inputs.TargetSid)
                if ($source.Count -gt 0) {
                    $status = 'SOURCE_REMAINS'
                    $detail = "$($source.Count) explicit source rule(s) remain."
                } elseif ($target.Count -eq 0 -or (Get-ShareAclRuleSignature $target) -cne $row.Expected) {
                    $status = 'TARGET_MISMATCH'
                    $detail = 'The explicit target rules differ from the recorded replacement.'
                } else {
                    $status = 'OK'
                    $detail = 'Explicit source rules removed and target rules match.'
                    $clean++
                }
            } catch {
                $status = 'ERROR'
                $detail = $_.Exception.Message
            }
        }
        [pscustomobject]@{ Path = $row.Path; Status = $status; Detail = $detail }
    }
    $controls.GrdVerify.ItemsSource = @($rows)
    $controls.TxtVerifySummary.Text = "Run $($run.Id): $clean verified, $($run.Outcomes.Count - $clean) not verified."
    $App.SetStatus($controls.TxtVerifySummary.Text)
    try { & $writeAudit @{ event = 'verify'; runId = $run.Id; clean = $clean; notVerified = $run.Outcomes.Count - $clean } }
    catch { $App.ShowError('Verify audit failed', $_.Exception.Message) }
}.GetNewClosure()

$controls.BtnPickSource.Add_Click({
    $defaultSource = if ($App.CurrentScanId) { 'Database' } else { 'ActiveDirectory' }
    $pick = $App.PickPrincipal('Pick the source principal (to be replaced)', $defaultSource)
    if ($pick) {
        $state.Source = $pick
        $controls.TxtSource.Text = "$($pick.Name)   [$($pick.Type)]   $($pick.Sid)"
        & $invalidate
    }
}.GetNewClosure())
$controls.BtnPickTarget.Add_Click({
    $pick = $App.PickPrincipal('Pick the target principal (replacement)', 'ActiveDirectory')
    if ($pick) {
        $state.Target = $pick
        $controls.TxtTarget.Text = "$($pick.Name)   [$($pick.Type)]   $($pick.Sid)"
        & $invalidate
    }
}.GetNewClosure())
$controls.BtnBrowseScope.Add_Click({
    $dialog = [System.Windows.Forms.FolderBrowserDialog]::new()
    try {
        $dialog.Description = 'Pick the scope root for the substitution'
        $dialog.SelectedPath = $controls.TxtScope.Text
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $controls.TxtScope.Text = $dialog.SelectedPath }
    } finally { $dialog.Dispose() }
}.GetNewClosure())
$controls.TxtScope.Add_TextChanged($invalidate)
$controls.ChkIncludeFiles.Add_Click($invalidate)
$controls.ChkOverrideGuard.Add_Click($invalidate)
$modeChanged = { & $setMode; & $invalidate }.GetNewClosure()
$controls.RbModeScan.Add_Click($modeChanged)
$controls.RbModeLive.Add_Click($modeChanged)
$controls.TxtConfirm.Add_TextChanged({
    $controls.BtnExecute.IsEnabled = -not $App.SwapExecuting -and $null -ne $state.Preview -and
        (& $contextMatches $state.Preview.Inputs) -and $controls.TxtConfirm.Text.Trim() -eq 'APPLY'
}.GetNewClosure())
$controls.BtnPreview.Add_Click($runPreview)
$controls.BtnExecute.Add_Click($runExecute)
$controls.BtnVerify.Add_Click($runVerify)
$Page.Add_Unloaded({
    $App.CancelAsync($Page.Tag, 'SwapPreview')
    foreach ($grid in @($controls.GrdPreview, $controls.GrdExecute, $controls.GrdVerify)) { $grid.ItemsSource = $null }
    $state.Preview = $null
    $state.LastRun = $null
}.GetNewClosure())

$controls.RbModeScan.IsChecked = $null -ne $App.CurrentScanId
$controls.RbModeLive.IsChecked = -not $controls.RbModeScan.IsChecked
& $setMode
& $invalidate

if ($App.NavContext) {
    $context = $App.NavContext
    $App.NavContext = $null
    if ($context.Scope) { $controls.TxtScope.Text = [string]$context.Scope }
    if ($context.SourceSid) {
        $state.Source = @{ Sid = [string]$context.SourceSid; Name = [string]$context.SourceName }
        $controls.TxtSource.Text = "$($state.Source.Name)   [from Findings]   $($state.Source.Sid)"
    }
}
