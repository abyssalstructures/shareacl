function Get-ADDomain {
    [CmdletBinding()]
    param()

    [pscustomobject]@{
        DNSRoot = 'fixture.example'
        DistinguishedName = 'DC=fixture,DC=example'
        DomainSID = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-100-200-300')
    }
}

function Get-ADObject {
    [CmdletBinding()]
    param([scriptblock]$Filter, [string]$LDAPFilter, [switch]$IncludeDeletedObjects, [string[]]$Properties,
          [string]$Server, [string]$SearchBase)

    $fixture = Get-Content -LiteralPath $env:SHAREACL_TEST_DIRECTORY -Raw | ConvertFrom-Json -AsHashtable
    if ($fixture.LookupError) { throw 'Simulated directory outage' }
    if ($LDAPFilter) { return }
    if ($Server -ne 'fixture.example' -or $SearchBase -ne 'DC=fixture,DC=example') { throw 'Lookup was outside the fixture domain' }
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

Export-ModuleMember -Function Get-ADDomain, Get-ADObject, Get-ADGroupMember
