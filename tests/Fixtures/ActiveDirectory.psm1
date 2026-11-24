function Get-ADObject {
    [CmdletBinding()]
    param([scriptblock]$Filter, [string]$LDAPFilter, [switch]$IncludeDeletedObjects, [string[]]$Properties)

    $fixture = Get-Content -LiteralPath $env:SHAREACL_TEST_DIRECTORY -Raw | ConvertFrom-Json -AsHashtable
    if ($fixture.LookupError) { throw 'Simulated directory outage' }
    if ($LDAPFilter) { return }
    $sid = (Get-PSCallStack)[1].GetFrameVariables()['Sid'].Value
    if ($sid -in $fixture.Deleted) { [pscustomobject]@{ isDeleted = $true } }
}

function Get-ADGroupMember {
    [CmdletBinding()]
    param([string]$Identity)

    $fixture = Get-Content -LiteralPath $env:SHAREACL_TEST_DIRECTORY -Raw | ConvertFrom-Json -AsHashtable
    if ($Identity -in $fixture.FailedGroups) { throw 'Simulated group enumeration failure' }
    foreach ($member in $fixture.Groups[$Identity]) {
        [pscustomobject]@{
            SID = [System.Security.Principal.SecurityIdentifier]::new($member.Sid)
            Name = $member.Sid
            SamAccountName = $member.Sid
            objectClass = $member.Type
        }
    }
}

Export-ModuleMember -Function Get-ADObject, Get-ADGroupMember
