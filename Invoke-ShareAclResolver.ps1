#Requires -Version 7.0
#Requires -Modules ActiveDirectory, PSSQLite

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Database,
    [int] $ScanId,
    [ValidateRange(1, [int]::MaxValue)] [int] $MaxNestingDepth = 16,
    [switch] $EmitProgress
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ShareAcl.Database.ps1')
if (-not (Test-Path -LiteralPath $Database -PathType Leaf)) { throw "Database not found: $Database" }
Update-ShareAclSchema -Database $Database

function Write-ResolverProgress {
    param(
        [Parameter(Mandatory)] [string] $Phase,
        [Parameter(Mandatory)] [int] $Current,
        [Parameter(Mandatory)] [int] $Total,
        [Parameter(Mandatory)] [string] $Activity
    )

    if (-not $EmitProgress) { return }

    # A compact, line-oriented protocol lets the GUI distinguish real resolver
    # progress from ordinary console output. Keep the activity on one line and
    # reserve pipe characters for field separators.
    $safeActivity = ($Activity -replace '[\r\n]+', ' ' -replace '\|', '/')
    $progressLine = 'SHAREACL_RESOLVER_PROGRESS|{0}|{1}|{2}|{3}' -f @(
        $Phase, $Current, $Total, $safeActivity)
    [Console]::Out.WriteLine($progressLine)
    [Console]::Out.Flush()
}

Write-ResolverProgress -Phase 'Starting' -Current 0 -Total 0 `
    -Activity 'Loading unresolved SIDs from the database…'

$folderJoin = if ($ScanId) { 'JOIN folders f ON f.folder_id = a.folder_id' } else { '' }
$sidFilter = if ($ScanId) { 'AND f.scan_id = @scan' } else { '' }
$scanParameters = if ($ScanId) { @{ scan = $ScanId } } else { @{} }

$sids = @(Invoke-SqliteQuery -DataSource $Database -Query @"
    SELECT DISTINCT a.trustee_sid AS sid
    FROM aces a
    LEFT JOIN principals p ON p.sid = a.trustee_sid
    $folderJoin
    WHERE (p.sid IS NULL OR (p.principal_type = 'Unknown' AND p.name IS NULL)
           OR (p.principal_type = 'Orphaned' AND p.orphan_confirmed = 0))
    $sidFilter
"@ -SqlParameters $scanParameters | ForEach-Object { $_.sid })

function Get-PrimaryGroupMembers {
    <#
        For domain-local groups whose membership is held in the primaryGroupID
        attribute on users/computers (RIDs 513-517), Get-ADGroupMember can
        silently under-report. This adds an LDAP-filter fallback.
    #>
    param([string]$GroupSid)

    if ($GroupSid -notmatch '^(S-1-5-21-\d+-\d+-\d+)-(51[3-7])$') { return }
    $domainSid = $Matches[1]
    $rid = $Matches[2]
    Get-ADObject -LDAPFilter "(primaryGroupID=$rid)" `
                 -Properties SamAccountName, objectClass, objectSID, Name -ErrorAction Stop |
        Where-Object { $_.objectSID.Value -like "$domainSid-*" } |
        ForEach-Object {
            [pscustomobject]@{
                Name = $_.Name; SamAccountName = $_.SamAccountName
                objectClass = $_.objectClass; SID = $_.objectSID
            }
        }
}

function Resolve-Sid {
    param([string]$Sid)
    $now = [DateTime]::UtcNow.ToString('o')

    # Well-known check
    try {
        $sidObj = [System.Security.Principal.SecurityIdentifier]::new($Sid)
        if ($sidObj.IsWellKnown([System.Security.Principal.WellKnownSidType]::WorldSid) -or
            $Sid -match '^S-1-5-(18|19|20|32-\d+)$' -or $Sid -match '^S-1-1-0$|^S-1-5-11$') {
            $nt = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
            return @{ name=$nt; domain='BUILTIN'; type='WellKnown'; wk=1; now=$now }
        }
    } catch { }

    $deleted = $false
    $lookupError = $null
    try {
        $objects = @(Get-ADObject -Filter { ObjectSID -eq $Sid } -IncludeDeletedObjects `
            -Properties sAMAccountName, objectClass, isDeleted -ErrorAction Stop)
        $obj = $objects | Where-Object { -not $_.isDeleted } | Select-Object -First 1
        if ($obj) {
            $type = switch ($obj.objectClass) {
                'user'     { 'User' }
                'group'    { 'Group' }
                'computer' { 'Computer' }
                'foreignSecurityPrincipal' { 'ForeignSecurityPrincipal' }
                default    { 'Unknown' }
            }
            return @{ name=$obj.Name; domain=$env:USERDOMAIN; sam=$obj.sAMAccountName; type=$type; wk=0; now=$now }
        }
        $deleted = $objects.Count -gt 0
    } catch { $lookupError = $_.Exception.Message }

    # Last attempt: LSA translate
    try {
        $nt = ([System.Security.Principal.SecurityIdentifier]::new($Sid)).Translate([System.Security.Principal.NTAccount]).Value
        return @{ name=$nt; type='Unknown'; wk=0; now=$now }
    } catch { }

    if ($deleted) { return @{ type='Orphaned'; wk=0; now=$now; orphan=1 } }
    @{ type='Unknown'; wk=0; now=$now; lookupError=$lookupError }
}

# Insert/update principals
$principalIndex = 0
$lookupFailures = 0
$unclassified = 0
Write-ResolverProgress -Phase 'Principals' -Current 0 -Total $sids.Count `
    -Activity ("Found {0:N0} unresolved SID(s)." -f $sids.Count)
foreach ($sid in $sids) {
    $principalIndex++
    Write-ResolverProgress -Phase 'Principals' -Current $principalIndex -Total $sids.Count `
        -Activity ("Resolving principal {0:N0} of {1:N0}: {2}" -f $principalIndex, $sids.Count, $sid)

    $r = Resolve-Sid -Sid $sid
    if ($r.lookupError) {
        $lookupFailures++
        if ($lookupFailures -eq 1) { Write-Warning "Directory lookup failed for ${sid}: $($r.lookupError)" }
    }
    if ($r.type -eq 'Unknown' -and -not $r.name) { $unclassified++ }
    Invoke-SqliteQuery -DataSource $Database -Query @"
        INSERT INTO principals(sid,name,domain,sam_account_name,principal_type,is_well_known,last_resolved_utc,orphan_confirmed)
        VALUES (@sid,@n,@d,@sam,@t,@wk,@now,@orphan)
        ON CONFLICT(sid) DO UPDATE SET
            name=excluded.name, domain=excluded.domain, sam_account_name=excluded.sam_account_name,
            principal_type=excluded.principal_type, is_well_known=excluded.is_well_known,
            last_resolved_utc=excluded.last_resolved_utc, orphan_confirmed=excluded.orphan_confirmed
"@ -SqlParameters @{
        sid=$sid; n=$r.name; d=$r.domain; sam=$r.sam; t=$r.type; wk=$r.wk; now=$r.now; orphan=[int]$r.orphan
    } | Out-Null
}
if ($unclassified -gt 0) { Write-Warning "$unclassified SID(s) remain unclassified. They will be retried on a later run." }

Write-ResolverProgress -Phase 'Groups' -Current 0 -Total 0 `
    -Activity 'Loading groups for membership expansion…'

# Expand from groups used by the selected scan, or all known groups for the database.
$groupFilter = if ($ScanId) {
    'AND EXISTS (SELECT 1 FROM aces a JOIN folders f ON f.folder_id = a.folder_id WHERE a.trustee_sid = p.sid AND f.scan_id = @scan)'
} else { '' }
$groups = @(Invoke-SqliteQuery -DataSource $Database -Query @"
    SELECT p.sid FROM principals p WHERE p.principal_type = 'Group' $groupFilter
"@ -SqlParameters $scanParameters | ForEach-Object { $_.sid })

$groupIndex = 0
$failedGroups = 0
Write-ResolverProgress -Phase 'Groups' -Current 0 -Total $groups.Count `
    -Activity ("Found {0:N0} group(s) to expand." -f $groups.Count)
foreach ($g in $groups) {
    $groupIndex++
    $visited = [System.Collections.Generic.HashSet[string]]::new()
    $queue   = [System.Collections.Generic.Queue[object]]::new()
    $queue.Enqueue(@{ sid=$g; depth=0 })
    $membersBySid = @{}

    Write-ResolverProgress -Phase 'Groups' -Current $groupIndex -Total $groups.Count `
        -Activity ("Expanding group {0:N0} of {1:N0}: {2}" -f $groupIndex, $groups.Count, $g)

    try {
        while ($queue.Count -gt 0) {
            $cur = $queue.Dequeue()
            if (-not $visited.Add($cur.sid) -or $cur.depth -ge $MaxNestingDepth) { continue }

            Write-ResolverProgress -Phase 'Groups' -Current $groupIndex -Total $groups.Count `
                -Activity ("Querying AD for {0} at nesting depth {1:N0}…" -f $cur.sid, $cur.depth)

            $members = @(Get-ADGroupMember -Identity $cur.sid -ErrorAction Stop)
            $members += Get-PrimaryGroupMembers -GroupSid $cur.sid
            $depth = $cur.depth + 1
            foreach ($member in $members) {
                if ($null -eq $member) { continue }
                $memberSid = $member.SID.Value
                if (-not $memberSid) { throw "AD returned a member without a SID for $($cur.sid)." }
                if ($memberSid -eq $g -or $membersBySid.ContainsKey($memberSid)) { continue }
                $membersBySid[$memberSid] = @{ Principal = $member; Depth = $depth }
                if ($member.objectClass -eq 'group') { $queue.Enqueue(@{ sid = $memberSid; depth = $depth }) }
            }
        }
    } catch {
        $failedGroups++
        Write-Warning "Membership refresh failed for ${g}. Kept the previous result. $($_.Exception.Message)"
        continue
    }

    Write-ResolverProgress -Phase 'Groups' -Current $groupIndex -Total $groups.Count `
        -Activity ("Recording {0:N0} member(s) for {1}." -f $membersBySid.Count, $g)
    $connection = New-SQLiteConnection -DataSource $Database
    try {
        $transaction = $connection.BeginTransaction()
        try {
            Invoke-SqliteQuery -SQLiteConnection $connection -Query 'DELETE FROM group_members WHERE group_sid = @sid' `
                -SqlParameters @{ sid = $g } | Out-Null
            foreach ($entry in $membersBySid.GetEnumerator()) {
                $m = $entry.Value.Principal
                $memberType = switch ($m.objectClass) {
                    'user'                     { 'User' }
                    'group'                    { 'Group' }
                    'computer'                 { 'Computer' }
                    'foreignSecurityPrincipal' { 'ForeignSecurityPrincipal' }
                    default                    { 'Unknown' }
                }
                Invoke-SqliteQuery -SQLiteConnection $connection -Query @'
                INSERT INTO principals(sid, name, domain, sam_account_name,
                                    principal_type, is_well_known, last_resolved_utc)
                VALUES (@sid, @name, @domain, @sam, @type, 0, @now)
                ON CONFLICT(sid) DO UPDATE SET name = excluded.name, domain = excluded.domain,
                    sam_account_name = excluded.sam_account_name, principal_type = excluded.principal_type,
                    last_resolved_utc = excluded.last_resolved_utc, orphan_confirmed = 0
                WHERE principals.principal_type IN ('Unknown', 'Orphaned')
'@ -SqlParameters @{
                    sid = $entry.Key; name = $m.Name; domain = $env:USERDOMAIN; sam = $m.SamAccountName
                    type = $memberType; now = [DateTime]::UtcNow.ToString('o')
                } | Out-Null
                Invoke-SqliteQuery -SQLiteConnection $connection -Query @'
                INSERT INTO group_members(group_sid, member_sid, depth) VALUES (@g, @m, @d)
'@ -SqlParameters @{ g = $g; m = $entry.Key; d = $entry.Value.Depth } | Out-Null
            }
            $transaction.Commit()
        } finally {
            $transaction.Dispose()
        }
    } finally {
        $connection.Dispose()
    }

    Write-ResolverProgress -Phase 'Groups' -Current $groupIndex -Total $groups.Count `
        -Activity ("Expanded group {0:N0} of {1:N0}." -f $groupIndex, $groups.Count)
}

if ($lookupFailures -gt 0 -or $failedGroups -gt 0) {
    throw "Resolution incomplete. $lookupFailures trustee lookup error(s), $failedGroups group refresh failure(s)."
}
Write-ResolverProgress -Phase 'Complete' -Current 1 -Total 1 -Activity 'Resolution complete.'
Write-Host "Resolution complete." -ForegroundColor Green
exit 0
