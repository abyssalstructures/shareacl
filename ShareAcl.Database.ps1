function Update-ShareAclSchema {
    param([string]$Database)

    $scanColumns = (Invoke-SqliteQuery -DataSource $Database -Query "PRAGMA table_info('scans')").name
    if ('total_folders' -notin $scanColumns) {
        Invoke-SqliteQuery -DataSource $Database -Query @'
BEGIN;
CREATE TABLE scans_new (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_utc TEXT NOT NULL,
    completed_utc TEXT,
    root_paths_json TEXT NOT NULL,
    host TEXT,
    operator TEXT,
    status TEXT NOT NULL CHECK (status IN ('counting','running','completed','failed','aborted')),
    folder_count INTEGER NOT NULL DEFAULT 0,
    ace_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    total_folders INTEGER,
    processed_folders INTEGER NOT NULL DEFAULT 0,
    folders_per_second REAL,
    estimated_completion_utc TEXT,
    last_updated_utc TEXT,
    max_depth INTEGER
);
INSERT INTO scans_new (scan_id, started_utc, completed_utc, root_paths_json,
                       host, operator, status, folder_count, ace_count, error_count, notes)
SELECT scan_id, started_utc, completed_utc, root_paths_json,
       host, operator, status, folder_count, ace_count, error_count, notes FROM scans;
DROP TABLE scans;
ALTER TABLE scans_new RENAME TO scans;
COMMIT;
'@ | Out-Null
    } elseif ('max_depth' -notin $scanColumns) {
        Invoke-SqliteQuery -DataSource $Database -Query 'ALTER TABLE scans ADD COLUMN max_depth INTEGER;' | Out-Null
    }

    $principalColumns = (Invoke-SqliteQuery -DataSource $Database -Query "PRAGMA table_info('principals')").name
    if ('orphan_confirmed' -notin $principalColumns) {
        Invoke-SqliteQuery -DataSource $Database -Query 'ALTER TABLE principals ADD COLUMN orphan_confirmed INTEGER NOT NULL DEFAULT 0;' | Out-Null
    }
}

function Initialize-ShareAclDatabaseFile {
    param([string]$Database)

    $schema = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'schema.sql') -Raw -ErrorAction Stop
    Invoke-SqliteQuery -DataSource $Database -Query $schema | Out-Null
    Update-ShareAclSchema -Database $Database
}

function Publish-ShareAclDatabaseFile {
    param([string]$StagedPath, [string]$Destination, [bool]$Overwrite)

    if ([IO.File]::Exists("$Destination-wal") -or [IO.File]::Exists("$Destination-shm") -or
        [IO.File]::Exists("$Destination-journal")) {
        throw 'The existing database has a SQLite journal. Close other connections and checkpoint it before overwriting.'
    }
    if ($Overwrite) {
        [IO.File]::Replace($StagedPath, $Destination, [NullString]::Value)
    } else {
        [IO.File]::Move($StagedPath, $Destination)
    }
}
