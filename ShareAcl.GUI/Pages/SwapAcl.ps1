function ConvertTo-ShareAclPath {
    param([string]$Path)

    $Path = $Path.Trim().Replace('/', '\')
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or $Path -match '^\\\\[?.]\\') {
        throw "Use an absolute local or UNC path: $Path"
    }
    foreach ($segment in ($Path -split '\\')) {
        if ($segment -notin '.', '..' -and ($segment.EndsWith('.') -or $segment.EndsWith(' '))) {
            throw "Path components must not end in a dot or space: $Path"
        }
    }
    [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Path))
}

function Test-ShareAclPathInScope {
    param([string]$Path, [string]$Scope)

    $Path.Equals($Scope, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($Scope.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Test-ShareAclReparsePath {
    param([string]$Path)

    # A scan candidate can be below a junction even when its own attributes look ordinary.
    for ($item = $Path; $null -ne ($parent = [IO.Path]::GetDirectoryName($item)); $item = $parent) {
        if ([IO.File]::GetAttributes($item) -band [IO.FileAttributes]::ReparsePoint) { return $true }
    }
    $false
}

function Get-ShareAclExplicitRules {
    param([System.Security.AccessControl.RawAcl]$Dacl, [string]$Sid)

    foreach ($rule in $Dacl) {
        if ($rule -is [System.Security.AccessControl.KnownAce] -and
            $rule.SecurityIdentifier.Value -eq $Sid -and
            -not ($rule.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited)) {
            $rule
        }
    }
}

function Get-ShareAclRuleSignature {
    param([object[]]$Rules)

    [string[]]$entries = @(foreach ($rule in $Rules) {
        $bytes = [byte[]]::new($rule.BinaryLength)
        $rule.GetBinaryForm($bytes, 0)
        [Convert]::ToBase64String($bytes)
    })
    [Array]::Sort($entries, [StringComparer]::Ordinal)
    $entries -join ','
}

function Get-ShareAclDescriptor {
    param($Acl)

    [System.Security.AccessControl.RawSecurityDescriptor]::new($Acl.GetSecurityDescriptorBinaryForm(), 0)
}

function Set-ShareAclDacl {
    param([string]$Path, [System.Security.AccessControl.FileSystemSecurity]$Security)

    # These overloads persist only modified sections. Set-Acl can write every section.
    if ($Security -is [System.Security.AccessControl.DirectorySecurity]) {
        [IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($Path), $Security)
    } else {
        [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Path), $Security)
    }
}

function Invoke-ShareAclReplacement {
    param([string]$Path, [string]$SourceSid, [string]$TargetSid, [string]$ApprovedRules)

    if (Test-ShareAclReparsePath $Path) {
        return @{ Code = 'skip'; Detail = 'Reparse point in the path. No change made.' }
    }

    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $descriptor = Get-ShareAclDescriptor $acl
    $source = @(Get-ShareAclExplicitRules $descriptor.DiscretionaryAcl $SourceSid)
    if ((Get-ShareAclRuleSignature $source) -cne $ApprovedRules) {
        return @{ Code = 'noop'; Detail = 'Source rules changed since preview. Preview again.' }
    }

    $replacement = [System.Security.Principal.SecurityIdentifier]::new($TargetSid)
    foreach ($rule in $source) { $rule.SecurityIdentifier = $replacement }

    $bytes = [byte[]]::new($descriptor.BinaryLength)
    $descriptor.GetBinaryForm($bytes, 0)
    $writeSecurity = if ($acl -is [System.Security.AccessControl.DirectorySecurity]) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $writeSecurity.SetSecurityDescriptorBinaryForm($bytes, [System.Security.AccessControl.AccessControlSections]::Access)
    $staged = Get-ShareAclDescriptor $writeSecurity
    $expected = Get-ShareAclRuleSignature @(Get-ShareAclExplicitRules $staged.DiscretionaryAcl $TargetSid)

    Set-ShareAclDacl $Path $writeSecurity
    @{ Code = 'ok'; Detail = "Replaced $($source.Count) explicit rule(s)."; Expected = $expected }
}
