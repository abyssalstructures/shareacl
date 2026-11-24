#Requires -Version 7.0
#Requires -Modules PSSQLite, NTFSSecurity

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'ShareAcl.Database.ps1')
. (Join-Path $repo 'ShareAcl.GUI/Pages/SwapAcl.ps1')

function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Set-TestRule([string]$Path, [string]$Sid, [string]$Rights, [string]$Type = 'Allow') {
    $acl = Get-Acl -LiteralPath $Path
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        [System.Security.Principal.SecurityIdentifier]::new($Sid), $Rights, $Type)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-TestSignature([string]$Path, [string]$Sid) {
    $descriptor = Get-ShareAclDescriptor (Get-Acl -LiteralPath $Path)
    Get-ShareAclRuleSignature @(Get-ShareAclExplicitRules $descriptor.DiscretionaryAcl $Sid)
}

function Invoke-TestScript([string]$Script, [string[]]$Arguments) {
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Get-Process -Id $PID).Path
    $start.UseShellExecute = $false
    foreach ($argument in @('-NoProfile', '-File', $Script) + $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::Start($start)
    try { $process.WaitForExit(); $process.ExitCode }
    finally { $process.Dispose() }
}

$junction = $null
$base = [IO.Directory]::CreateTempSubdirectory('shareacl-regression-').FullName
$originalModulePath = $env:PSModulePath
$originalDirectoryFixture = $env:SHAREACL_TEST_DIRECTORY
try {
    foreach ($file in Get-ChildItem -LiteralPath $repo -Recurse -File -Filter '*.ps1') {
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$parseErrors)
        Assert-Test ($parseErrors.Count -eq 0) "PowerShell parse failed in $($file.Name): $parseErrors"
    }
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $repo 'ShareAcl.GUI') -Recurse -File -Filter '*.xaml') {
        $reader = [System.Xml.XmlReader]::Create($file.FullName)
        try { $null = [System.Windows.Markup.XamlReader]::Load($reader) }
        finally { $reader.Dispose() }
    }
    Write-Host 'PASS: PowerShell and WPF XAML load'

    $scope = ConvertTo-ShareAclPath (Join-Path $base 'Team_100%')
    $sibling = ConvertTo-ShareAclPath "$($scope)Archive"
    $sub = Join-Path $scope 'Sub'
    $file = Join-Path $sub 'test.txt'
    $null = [IO.Directory]::CreateDirectory($sub)
    $null = [IO.Directory]::CreateDirectory($sibling)
    [IO.File]::WriteAllText($file, 'fixture')
    Assert-Test (Test-ShareAclPathInScope $scope $scope) 'Scope root was excluded.'
    Assert-Test (Test-ShareAclPathInScope $sub $scope) 'Descendant was excluded.'
    Assert-Test (-not (Test-ShareAclPathInScope $sibling $scope)) 'Similarly named sibling was included.'
    $unc = ConvertTo-ShareAclPath '\\server\share\Team_100%\'
    Assert-Test (Test-ShareAclPathInScope '\\SERVER\SHARE\team_100%\child' $unc) 'UNC descendant was excluded.'
    Assert-Test (-not (Test-ShareAclPathInScope '\\server\share\Team_100%Archive' $unc)) 'UNC sibling was included.'
    $junction = Join-Path $scope 'Junction'
    $null = New-Item -ItemType Junction -Path $junction -Target $sibling
    $null = [IO.Directory]::CreateDirectory((Join-Path $sibling 'Outside'))
    Assert-Test (Test-ShareAclReparsePath (Join-Path $junction 'Outside')) 'A junction ancestor was missed.'
    Write-Host 'PASS: Scope boundaries, literal names, UNC paths and reparse ancestors'

    $source = 'S-1-5-21-100-200-300-1101'
    $target = 'S-1-5-21-100-200-300-1102'
    Set-TestRule $file $source ReadData
    Set-TestRule $file $source WriteData Deny
    Set-TestRule $file $target ReadAttributes
    $approved = Get-TestSignature $file $source
    Assert-Test ([bool]$approved) 'Test ACL did not contain the source rules.'
    $skip = Invoke-ShareAclReplacement $file $source $target 'outdated preview'
    Assert-Test ($skip.Code -eq 'noop' -and (Get-TestSignature $file $source) -ceq $approved) 'A stale preview changed the ACL.'
    $before = (Get-Acl -LiteralPath $file).Sddl
    & {
        $attempts = [System.Collections.Generic.List[string]]::new()
        function Set-ShareAclDacl {
            param([string]$Path, $Security)
            $attempts.Add($Path)
            $flags = [Reflection.BindingFlags]'Instance, NonPublic'
            $type = $Security.GetType()
            $null = $type.GetMethod('ReadLock', $flags).Invoke($Security, $null)
            try {
                foreach ($section in 'AccessRulesModified', 'AuditRulesModified', 'OwnerModified', 'GroupModified') {
                    $modified = $type.GetProperty($section, $flags).GetValue($Security)
                    Assert-Test ($modified -eq ($section -eq 'AccessRulesModified')) "Unexpected write flag for $section."
                }
            } finally {
                $null = $type.GetMethod('ReadUnlock', $flags).Invoke($Security, $null)
            }
            throw 'Simulated ACL write failure'
        }
        $failure = $null
        try { Invoke-ShareAclReplacement $file $source $target $approved | Out-Null }
        catch { $failure = $_ }
        Assert-Test ($attempts.Count -eq 1 -and $failure.Exception.Message -like '*Simulated ACL write failure*') `
            "Expected one complete DACL write attempt, got $($attempts.Count). $($failure.Exception.Message)"
    }
    Assert-Test ((Get-Acl -LiteralPath $file).Sddl -ceq $before) 'Failed replacement left a partial ACL.'
    $auditSection = [System.Security.AccessControl.AccessControlSections]::Audit
    $auditBefore = $null
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ([System.Security.Principal.WindowsPrincipal]::new($identity).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $audit = [System.Security.AccessControl.FileSecurity]::new()
        $audit.SetAuditRuleProtection($true, $false)
        $audit.AddAuditRule([System.Security.AccessControl.FileSystemAuditRule]::new(
            $identity.User, [System.Security.AccessControl.FileSystemRights]::ReadData, [System.Security.AccessControl.AuditFlags]::Success))
        [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($file), $audit)
        $auditBefore = (Get-Acl -LiteralPath $file -Audit).GetSecurityDescriptorSddlForm($auditSection)
        Assert-Test ($auditBefore -like 'S:P*(*') 'The elevated fixture could not seed a protected audit rule.'
    }
    $replaced = Invoke-ShareAclReplacement $file $source $target $approved
    Assert-Test ($replaced.Code -eq 'ok' -and -not (Get-TestSignature $file $source)) 'Source rules were not replaced.'
    Assert-Test ((Get-TestSignature $file $target) -ceq $replaced.Expected) 'Written target ACL differs from its staged rules.'
    if ($auditBefore) {
        Assert-Test ((Get-Acl -LiteralPath $file -Audit).GetSecurityDescriptorSddlForm($auditSection) -ceq $auditBefore) 'Swap changed the protected audit rule.'
        Write-Host 'PASS: Elevated NTFS swap preserves the protected SACL'
    }
    Write-Host 'PASS: Real NTFS file replacement preserves expected target rules and rejects drift'

    $database = Join-Path $base 'audit.db'
    Initialize-ShareAclDatabaseFile $database
    $collector = Join-Path $repo 'Invoke-ShareAclCollector.ps1'
    $code = Invoke-TestScript $collector @('-Database', $database, '-RootPath', $scope, '-BatchSize', '1')
    Assert-Test ($code -eq 0) 'Collector failed on a normal scan.'
    $scan = Invoke-SqliteQuery -DataSource $database -Query 'SELECT * FROM scans WHERE scan_id = 1'
    Assert-Test ($scan.total_folders -eq 3 -and $scan.folder_count -eq 3) 'Counting and collection disagreed on the junction.'
    Assert-Test ($scan.status -eq 'completed') 'Normal scan status is incorrect.'
    $rootRow = Invoke-SqliteQuery -DataSource $database -Query 'SELECT parent_id FROM folders WHERE scan_id = 1 AND depth = 0'
    Assert-Test ($null -eq $rootRow.parent_id) 'The scan root was given a parent.'

    $roots = ConvertTo-Json -InputObject @($scope) -Compress
    Invoke-SqliteQuery -DataSource $database -Query @'
INSERT INTO scans(scan_id, started_utc, root_paths_json, status, max_depth, total_folders)
VALUES (2,'now',@roots,'running',1,2), (3,'now',@roots,'counting',0,NULL), (4,'now',@roots,'running',1,2);
INSERT INTO folders_pending(scan_id, path, parent_id, depth) VALUES (3,@root,NULL,0), (4,@child,NULL,1);
INSERT INTO folders(scan_id, path, parent_id, depth, inheritance_enabled, visited_utc) VALUES (4,@root,NULL,0,1,'now');
INSERT INTO aces(folder_id, trustee_sid, access_control_type, rights_text, rights_mask, inheritance_flags, propagation_flags, is_inherited)
VALUES (last_insert_rowid(), @source, 'Allow', 'ReadData', 1, 'None', 'None', 0);
INSERT INTO scan_errors(scan_id, path, phase, message, logged_utc) VALUES (4,@root,'acl','fixture','now');
'@ -SqlParameters @{ roots = $roots; root = $scope; child = $sub; source = $source } | Out-Null
    $code = Invoke-TestScript $collector @('-Database', $database, '-Resume', '-ScanId', '3')
    Assert-Test ($code -eq 0) 'Resuming the counting phase failed.'
    $code = Invoke-TestScript $collector @('-Database', $database, '-Resume', '-ScanId', '4', '-BatchSize', '1')
    Assert-Test ($code -eq 0) 'Resuming the collection phase failed.'
    $scans = @(Invoke-SqliteQuery -DataSource $database -Query 'SELECT * FROM scans WHERE scan_id BETWEEN 2 AND 4 ORDER BY scan_id')
    Assert-Test ($scans[0].status -eq 'running') 'Resume changed the wrong scan.'
    Assert-Test ($scans[1].status -eq 'completed' -and $scans[1].total_folders -eq 1 -and $scans[1].folder_count -eq 1) 'Counting resume lost the original depth.'
    $exact = Invoke-SqliteQuery -DataSource $database -Query @'
SELECT (SELECT COUNT(*) FROM scan_errors WHERE scan_id = 4) AS errors,
       (SELECT COUNT(*) FROM aces a JOIN folders f ON a.folder_id = f.folder_id WHERE f.scan_id = 4) AS aces
'@
    Assert-Test ($scans[2].status -eq 'completed' -and $scans[2].folder_count -eq 2 -and $scans[2].processed_folders -eq 2 -and
        $scans[2].ace_count -eq $exact.aces -and $scans[2].error_count -eq $exact.errors) 'Resumed totals omit already committed rows.'
    Write-Host 'PASS: Collector and counting/running resume with real SQLite and NTFS'

    $backupTest = Join-Path $base 'original.db'
    $stage = Join-Path $base 'replacement.db'
    Initialize-ShareAclDatabaseFile $backupTest
    Initialize-ShareAclDatabaseFile $stage
    Invoke-SqliteQuery -DataSource $backupTest -Query "INSERT INTO scans(started_utc, root_paths_json, status) VALUES ('now','[]','completed')" | Out-Null
    $blocked = $false
    try { Publish-ShareAclDatabaseFile "$stage-missing" $backupTest $true }
    catch { $blocked = $true }
    $originalCount = Invoke-SqliteQuery -DataSource $backupTest -Query 'SELECT COUNT(*) FROM scans' -As SingleValue
    Assert-Test ($blocked -and $originalCount -eq 1) 'A failed publish discarded the original database.'
    Publish-ShareAclDatabaseFile $stage $backupTest $true
    $newCount = Invoke-SqliteQuery -DataSource $backupTest -Query 'SELECT COUNT(*) FROM scans' -As SingleValue
    Assert-Test ($newCount -eq 0) 'The initialized replacement was not published.'
    Write-Host 'PASS: Failed database publication preserves the original; valid publication replaces it'

    $legacy = Join-Path $base 'legacy.db'
    $legacySchema = Get-Content -LiteralPath (Join-Path $repo 'schema.sql') -Raw
    $legacySchema = $legacySchema -replace '(?s)(notes\s+TEXT),.*?max_depth\s+INTEGER', '$1'
    $legacySchema = $legacySchema -replace '(last_resolved_utc\s+TEXT NOT NULL),\r?\n\s+orphan_confirmed\s+INTEGER NOT NULL DEFAULT 0', '$1'
    Invoke-SqliteQuery -DataSource $legacy -Query $legacySchema | Out-Null
    Invoke-SqliteQuery -DataSource $legacy -Query @'
INSERT INTO scans(scan_id,started_utc,root_paths_json,status) VALUES (9,'now','[]','completed');
INSERT INTO folders(scan_id,path,depth,inheritance_enabled,visited_utc) VALUES (9,'kept',0,1,'now');
INSERT INTO principals(sid,principal_type,last_resolved_utc) VALUES ('legacy','Orphaned','old');
'@ | Out-Null
    Initialize-ShareAclDatabaseFile $legacy
    Initialize-ShareAclDatabaseFile $legacy
    $migrated = Invoke-SqliteQuery -DataSource $legacy -Query 'SELECT s.scan_id,s.max_depth,f.path FROM scans s JOIN folders f ON f.scan_id=s.scan_id'
    $flag = Invoke-SqliteQuery -DataSource $legacy -Query "SELECT orphan_confirmed FROM principals WHERE sid = 'legacy'" -As SingleValue
    Assert-Test ($migrated.scan_id -eq 9 -and $migrated.path -eq 'kept' -and $flag -eq 0) 'Legacy database migration lost data or treated a legacy orphan as confirmed.'
    Write-Host 'PASS: Older scan databases migrate without losing audit rows'

    $mockModules = Join-Path $base 'Modules'
    $mockAd = Join-Path $mockModules 'ActiveDirectory'
    $null = [IO.Directory]::CreateDirectory($mockAd)
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Fixtures/ActiveDirectory.psm1') -Destination $mockAd
    $env:PSModulePath = "$mockModules;$originalModulePath"
    $env:SHAREACL_TEST_DIRECTORY = Join-Path $base 'directory.json'
    $resolver = Join-Path $repo 'Invoke-ShareAclResolver.ps1'
    $resDb = Join-Path $base 'resolver.db'
    Initialize-ShareAclDatabaseFile $resDb
    $group = 'S-1-5-21-100-200-300-1111'
    $nested = 'S-1-5-21-100-200-300-1112'
    $member = 'S-1-5-21-100-200-300-1113'
    $removed = 'S-1-5-21-100-200-300-1114'
    $unclassified = 'S-1-5-21-100-200-400-1120'
    $deleted = 'S-1-5-21-100-200-300-1121'
    $missing = 'S-1-5-21-100-200-300-1122'
    $outage = 'S-1-5-21-100-200-300-1123'
    Invoke-SqliteQuery -DataSource $resDb -Query @'
INSERT INTO scans(scan_id,started_utc,root_paths_json,status) VALUES (1,'now','[]','completed');
INSERT INTO folders(folder_id,scan_id,path,depth,inheritance_enabled,visited_utc) VALUES (1,1,'fixture',0,1,'now');
INSERT INTO principals(sid, name, principal_type, last_resolved_utc)
VALUES (@group,'Group','Group','cached'), (@member,'Member','User','cached'), (@removed,'Removed','User','cached'),
       (@missing,NULL,'Orphaned','legacy');
INSERT INTO aces(folder_id,trustee_sid,access_control_type,rights_text,rights_mask,inheritance_flags,propagation_flags,is_inherited)
VALUES (1,@group,'Allow','ReadData',1,'None','None',0), (1,@unknown,'Allow','ReadData',1,'None','None',0),
       (1,@deleted,'Allow','ReadData',1,'None','None',0), (1,@missing,'Allow','ReadData',1,'None','None',0);
INSERT INTO group_members(group_sid,member_sid,depth) VALUES (@group,@removed,1), (@group,@member,3);
'@ -SqlParameters @{ group = $group; member = $member; removed = $removed; unknown = $unclassified; deleted = $deleted; missing = $missing } | Out-Null

    $directory = @{
        Deleted = @($deleted); FailedGroups = @()
        Groups = @{
            $group = @(@{ Sid = $nested; Type = 'group' }, @{ Sid = $member; Type = 'user' })
            $nested = @(@{ Sid = $group; Type = 'group' }, @{ Sid = $member; Type = 'user' })
        }
    }
    $directory | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $env:SHAREACL_TEST_DIRECTORY
    $code = Invoke-TestScript $resolver @('-Database', $resDb)
    Assert-Test ($code -eq 0) 'Resolver failed on the valid directory fixture.'
    $members = @(Invoke-SqliteQuery -DataSource $resDb -Query 'SELECT member_sid,depth FROM group_members WHERE group_sid=@g ORDER BY member_sid' `
        -SqlParameters @{ g = $group })
    Assert-Test ($members.Count -eq 2 -and $members[1].member_sid -eq $member -and $members[1].depth -eq 1) 'Group refresh left stale or longer edges.'
    $principalRows = @(Invoke-SqliteQuery -DataSource $resDb -Query 'SELECT sid,principal_type,last_resolved_utc,orphan_confirmed FROM principals ORDER BY sid')
    $groupRow = $principalRows | Where-Object sid -eq $group
    $unclassifiedRow = $principalRows | Where-Object sid -eq $unclassified
    $deletedRow = $principalRows | Where-Object sid -eq $deleted
    $missingRow = $principalRows | Where-Object sid -eq $missing
    Assert-Test ($groupRow.last_resolved_utc -eq 'cached') 'Whole-database resolver reprocessed a cached principal.'
    Assert-Test ($unclassifiedRow.principal_type -eq 'Unknown' -and $unclassifiedRow.orphan_confirmed -eq 0) 'A missing foreign-domain SID was confirmed as orphaned.'
    Assert-Test ($deletedRow.principal_type -eq 'Orphaned' -and $deletedRow.orphan_confirmed -eq 1) 'Deleted-object evidence was lost.'
    Assert-Test ($missingRow.principal_type -eq 'Orphaned' -and $missingRow.orphan_confirmed -eq 1) 'An unmapped SID absent from its own domain was missed.'
    $findings = Get-Content -LiteralPath (Join-Path $repo 'ShareAcl.GUI/Pages/FindingsView.ps1') -Raw
    $orphanSql = [regex]::Match($findings, '(?s)Id\s*=\s*''orphaned''.*?@"\r?\n(.*?)\r?\n"@').Groups[1].Value
    $pendingSql = [regex]::Match($findings, '(?s)Id\s*=\s*''unclassified''.*?@"\r?\n(.*?)\r?\n"@').Groups[1].Value
    $orphans = @(Invoke-SqliteQuery -DataSource $resDb -Query $orphanSql -SqlParameters @{ scan = 1 })
    $pending = @(Invoke-SqliteQuery -DataSource $resDb -Query $pendingSql -SqlParameters @{ scan = 1 })
    Assert-Test ($orphans.Count -eq 2 -and $deleted -in $orphans.Sid -and $missing -in $orphans.Sid -and
        $pending.Count -eq 1 -and $pending[0].Sid -eq $unclassified) 'Findings confused confirmed and unresolved SIDs.'

    $directory.FailedGroups = @($nested)
    $directory.LookupError = $true
    $directory | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $env:SHAREACL_TEST_DIRECTORY
    Invoke-SqliteQuery -DataSource $resDb -Query @'
INSERT INTO aces(folder_id,trustee_sid,access_control_type,rights_text,rights_mask,inheritance_flags,propagation_flags,is_inherited)
VALUES (1,@sid,'Allow','ReadData',1,'None','None',0)
'@ -SqlParameters @{ sid = $outage } | Out-Null
    $code = Invoke-TestScript $resolver @('-Database', $resDb, '-ScanId', '1')
    Assert-Test ($code -eq 1) "A partial resolver refresh returned exit code $code."
    $outageRow = Invoke-SqliteQuery -DataSource $resDb -Query 'SELECT principal_type,orphan_confirmed FROM principals WHERE sid=@sid' -SqlParameters @{ sid = $outage }
    Assert-Test ($outageRow.principal_type -eq 'Unknown' -and $outageRow.orphan_confirmed -eq 0) 'A failed own-domain lookup was confirmed as orphaned.'
    $remaining = @(Invoke-SqliteQuery -DataSource $resDb -Query 'SELECT member_sid,depth FROM group_members WHERE group_sid=@g ORDER BY member_sid' `
        -SqlParameters @{ g = $group })
    Assert-Test (($remaining | ConvertTo-Json -Compress) -eq ($members | ConvertTo-Json -Compress)) 'Failed nested lookup replaced the last complete membership.'
    Write-Host 'PASS: Resolver cache, deleted versus unresolved identities, and atomic membership refresh with mocked AD'

    # Exercise the page's real callbacks with an in-process stand-in for the GUI shell.
    $pageFiles = Join-Path $base 'Gui/Pages'
    $null = [IO.Directory]::CreateDirectory($pageFiles)
    foreach ($name in 'SwapView.ps1', 'SwapView.xaml', 'SwapAcl.ps1') {
        Copy-Item -LiteralPath (Join-Path $repo "ShareAcl.GUI/Pages/$name") -Destination $pageFiles
    }
    $reader = [System.Xml.XmlReader]::Create((Join-Path $pageFiles 'SwapView.xaml'))
    try { $page = [System.Windows.Markup.XamlReader]::Load($reader) }
    finally { $reader.Dispose() }
    $page.Tag = [pscustomobject]@{ State = $null }
    $ui = [pscustomobject]@{
        CurrentScanId = 1; DbPath = $database; NavContext = $null; SwapExecuting = $false
        Window = [System.Windows.Window]::new(); BusyText = [pscustomobject]@{ Text = '' }; Status = ''; Progress = 0
    }
    $ui | Add-Member ScriptMethod GetControls {
        param($View, $Names)
        $map = @{}
        foreach ($name in $Names) { $map[$name] = $View.FindName($name) }
        $map
    }
    $ui | Add-Member ScriptMethod CancelAsync { }
    $ui | Add-Member ScriptMethod SetStatus { param($Message) $this.Status = $Message }
    $ui | Add-Member ScriptMethod ShowError { param($Title, $Message) throw "$Title - $Message" }
    $ui | Add-Member ScriptMethod Query {
        param($Sql, $Parameters)
        Invoke-SqliteQuery -DataSource $this.DbPath -Query $Sql -SqlParameters $Parameters
    }
    $ui | Add-Member ScriptMethod StartAsync {
        param($Owner, $Name, $Busy, $Context, $Work, $Complete, $Title, $Progress)
        $Context.DbPath = $this.DbPath
        $Context.ProgressQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
        $result = & $Work $Context
        $update = $null
        while ($Context.ProgressQueue.TryDequeue([ref]$update)) {
            $this.Progress++
            & $Progress $update $Owner
        }
        & $Complete $result $Owner
    }

    $btnClick = [System.Windows.Controls.Button]::ClickEvent
    & (Join-Path $pageFiles 'SwapView.ps1') -Page $page -App $ui
    $page.Tag.State.Source = @{ Sid = $source; Name = 'Source' }
    $page.Tag.State.Target = @{ Sid = $target; Name = 'Target'; Type = 'User'; Sam = 'target' }
    $page.FindName('TxtScope').Text = $scope
    $includeFiles = $page.FindName('ChkIncludeFiles')
    Assert-Test (-not $includeFiles.IsEnabled) 'Scan mode offered file ACL discovery.'
    Set-TestRule $scope $source ReadData
    Set-TestRule $sibling $source ReadData
    Invoke-SqliteQuery -DataSource $database -Query @'
INSERT INTO folders(scan_id,path,depth,inheritance_enabled,visited_utc) VALUES (1,@sibling,0,1,'now');
INSERT INTO aces(folder_id,trustee_sid,access_control_type,rights_text,rights_mask,inheritance_flags,propagation_flags,is_inherited)
SELECT folder_id,@source,'Allow','ReadData',1,'None','None',0 FROM folders WHERE scan_id=1 AND path IN (@scope,@sibling);
'@ -SqlParameters @{ source = $source; scope = $scope; sibling = $sibling } | Out-Null

    $page.FindName('BtnPreview').RaiseEvent([System.Windows.RoutedEventArgs]::new($btnClick))
    $previewGrid = $page.FindName('GrdPreview')
    Assert-Test ($previewGrid.ItemsSource.Count -eq 1 -and $previewGrid.ItemsSource[0].Path -eq $scope) 'Actual scan preview escaped its scope.'
    $ui.DbPath = $backupTest
    $page.FindName('TxtConfirm').Text = 'APPLY'
    Assert-Test (-not $page.FindName('BtnExecute').IsEnabled) 'A same-ID scan in another database enabled execution.'
    $ui.DbPath = $database
    $ui.CurrentScanId = 3
    & $page.Tag.State.RefreshForScan
    Assert-Test ($null -eq $page.Tag.State.Preview) 'Scan selection retained the previous preview.'

    $live = $page.FindName('RbModeLive')
    $live.IsChecked = $true
    $live.RaiseEvent([System.Windows.RoutedEventArgs]::new($btnClick))
    Assert-Test $includeFiles.IsEnabled 'Live mode did not enable file ACL discovery.'
    $includeFiles.IsChecked = $true
    $liveFile = Join-Path $sub 'source-only.txt'
    [IO.File]::WriteAllText($liveFile, 'fixture')
    Set-TestRule $liveFile $source ReadData
    for ($index = 0; $index -lt 24; $index++) { [IO.File]::WriteAllText((Join-Path $sub "$index.txt"), 'fixture') }
    $page.FindName('BtnPreview').RaiseEvent([System.Windows.RoutedEventArgs]::new($btnClick))
    Assert-Test ($ui.Progress -gt 0 -and $liveFile -in $previewGrid.ItemsSource.Path) 'Live file preview or progress was missing.'
    $page.FindName('TxtConfirm').Text = 'APPLY'
    Assert-Test $page.FindName('BtnExecute').IsEnabled 'A confirmed live preview did not enable execution.'
    $page.FindName('BtnExecute').RaiseEvent([System.Windows.RoutedEventArgs]::new($btnClick))
    $page.FindName('BtnVerify').RaiseEvent([System.Windows.RoutedEventArgs]::new($btnClick))
    Assert-Test ($page.FindName('GrdVerify').ItemsSource.Status -notcontains 'TARGET_MISMATCH' -and
        $page.FindName('GrdVerify').ItemsSource.Status -contains 'OK') 'Verification did not confirm the recorded rules.'
    $fileAcl = Get-Acl -LiteralPath $liveFile
    $fileAcl.PurgeAccessRules([System.Security.Principal.SecurityIdentifier]::new($target))
    Set-Acl -LiteralPath $liveFile -AclObject $fileAcl
    $page.FindName('BtnVerify').RaiseEvent([System.Windows.RoutedEventArgs]::new($btnClick))
    $fileResult = $page.FindName('GrdVerify').ItemsSource | Where-Object Path -eq $liveFile
    Assert-Test ($fileResult.Status -eq 'TARGET_MISMATCH') 'A missing target rule was counted as verified.'
    Write-Host 'PASS: WPF scan context, live file preview and execution, progress and verification'

    Invoke-SqliteQuery -DataSource $database -Query @'
INSERT INTO scans(scan_id,started_utc,root_paths_json,status) VALUES (20,'now','[]','completed');
INSERT INTO folders(scan_id,path,depth,inheritance_enabled,visited_utc)
VALUES (20,'Deny-only',0,1,'now'), (20,'Mixed',0,1,'now');
INSERT INTO aces(folder_id,trustee_sid,access_control_type,rights_text,rights_mask,inheritance_flags,propagation_flags,is_inherited)
SELECT folder_id,@sid,'Deny','ReadData',1,'None','None',0 FROM folders WHERE scan_id=20
UNION ALL SELECT folder_id,@sid,'Allow','ReadData',1,'None','None',0 FROM folders WHERE scan_id=20 AND path='Mixed';
'@ -SqlParameters @{ sid = $source } | Out-Null
    $accountDir = Join-Path $repo 'ShareAcl.GUI/Pages'
    $reader = [System.Xml.XmlReader]::Create((Join-Path $accountDir 'AccountView.xaml'))
    try { $accountPage = [System.Windows.Markup.XamlReader]::Load($reader) }
    finally { $reader.Dispose() }
    $accountPage.Tag = [pscustomobject]@{ State = $null }
    $ui.CurrentScanId = 20
    & (Join-Path $accountDir 'AccountView.ps1') -Page $accountPage -App $ui
    $accountView = $accountPage.Tag.State
    $accountView.PrincipalSid = $source
    $accountView.PrincipalName = 'Source'
    & $accountView.LoadReachable $accountView
    $accountRows = @($accountView.Controls.GrdReachable.ItemsSource)
    Assert-Test ($ui.Status -like '*3 matching ACEs*' -and $accountRows.Count -eq 3 -and
        ($accountRows | Where-Object Path -eq 'Deny-only').AceType -eq 'Deny') 'Account view treated historical Deny matches as access or omitted them.'
    $accountView.Controls.ChkAllowOnly.IsChecked = $true
    & $accountView.LoadReachable $accountView
    $accountRows = @($accountView.Controls.GrdReachable.ItemsSource)
    Assert-Test ($ui.Status -like '*1 matching ACEs*' -and $accountRows.Count -eq 1 -and
        $accountRows[0].AceType -eq 'Allow' -and $accountRows[0].Path -eq 'Mixed') 'The Allow ACEs filter did not filter the Deny-only and mixed folders.'
    Write-Host 'PASS: Account view labels Deny-only and mixed folders as historical ACE matches'

    $guiAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'ShareAcl.GUI/Start-ShareAclGui.ps1'), [ref]$null, [ref]$null)
    $queueAssignment = $guiAst.Find({
        param($Node)
        $Node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $Node.Left.Extent.Text -eq '$progressQueue' -and $Node.Right.Extent.Text -like '*ConcurrentQueue*'
    }, $true)
    $OnProgress = {}
    . ([scriptblock]::Create($queueAssignment.Extent.Text))
    Assert-Test ($progressQueue -is [System.Collections.Concurrent.ConcurrentQueue[object]]) 'The async runner lost the empty progress queue.'
    Write-Host 'PASS: GUI async runner preserves an empty progress queue'
} finally {
    $env:PSModulePath = $originalModulePath
    $env:SHAREACL_TEST_DIRECTORY = $originalDirectoryFixture
    if ($junction -and [IO.Directory]::Exists($junction)) { [IO.Directory]::Delete($junction) }
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if ([IO.Path]::GetFullPath($base).StartsWith("${tempRoot}shareacl-regression-", [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $base -Recurse -Force
    }
}
