<#
.SYNOPSIS
    One-time setup for the Detection Feasibility & Rule Recommendation Engine.

.DESCRIPTION
    Creates the venv, installs dependencies, and pulls the local reference
    corpora into data/. This script is the ONLY part of the project that is
    allowed to touch the network (docs/BLUEPRINT.md Section 3). Once it has
    run, the engine works fully offline.

    Keep this file ASCII-only. Windows PowerShell 5.1 reads .ps1 as ANSI, so a
    UTF-8 em dash decodes into a stray smart quote and breaks parsing.

    Safe to re-run: an existing corpus is refreshed in place, not re-cloned.

.EXAMPLE
    scripts\setup.ps1
    scripts\setup.ps1 -SkipCorpora    # venv + deps only
    scripts\setup.ps1 -SkipVenv       # refresh corpora only
#>
[CmdletBinding()]
param(
    [switch]$SkipVenv,
    [switch]$SkipCorpora,
    [switch]$SkipDb
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is ~10x faster without it
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$DataDir    = Join-Path $RepoRoot 'data'
$VenvDir    = Join-Path $RepoRoot '.venv'
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'

$SigmaDir        = Join-Path $DataDir 'sigma-corpus'
$IntegrationsDir = Join-Path $DataDir 'elastic-integrations'
$MitreDir        = Join-Path $DataDir 'mitre-attack'
$MitreFile       = Join-Path $MitreDir 'enterprise-attack.json'

$SigmaRepo        = 'https://github.com/SigmaHQ/sigma.git'
$IntegrationsRepo = 'https://github.com/elastic/integrations.git'
$MitreStixUrl     = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'

# A full checkout of elastic/integrations is several GB. ECS gap analysis
# (BLUEPRINT 5.2) only needs the package manifests, field definitions, and
# ingest pipelines, so take a blobless + sparse checkout of just those paths.
$IntegrationsSparsePaths = @(
    '/packages/*/manifest.yml',
    '/packages/*/data_stream/*/manifest.yml',
    '/packages/*/data_stream/*/fields/*',
    '/packages/*/data_stream/*/elasticsearch/ingest_pipeline/*'
)

function Write-Step($Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok($Message)   { Write-Host "    ok   $Message" -ForegroundColor Green }
function Write-Note($Message) { Write-Host "    --   $Message" -ForegroundColor DarkGray }

function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]$Exe,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$What
    )
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed (exit $LASTEXITCODE): $Exe $($Arguments -join ' ')"
    }
}

function Assert-Prerequisites {
    Write-Step 'Checking prerequisites'

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw 'git not found on PATH. Install Git for Windows, then re-run this script.'
    }
    Write-Ok ((& git --version) -join ' ')

    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        throw 'python not found on PATH. Install Python 3.11+, then re-run this script.'
    }
    $pyVer = (& python -c "import sys; print('%d.%d' % sys.version_info[:2])").Trim()
    if ([version]$pyVer -lt [version]'3.11') {
        throw "Python 3.11+ required, found $pyVer."
    }
    Write-Ok "python $((& python --version) -replace '^Python ', '')"
}

function Initialize-Venv {
    Write-Step 'Python virtual environment'
    if (Test-Path $VenvPython) {
        Write-Note ".venv already exists, reusing it"
    } else {
        Invoke-Native 'python' @('-m', 'venv', $VenvDir) 'venv creation'
        Write-Ok "created $VenvDir"
    }

    Write-Step 'Installing dependencies (requirements.txt)'
    Invoke-Native $VenvPython @('-m', 'pip', 'install', '--upgrade', 'pip', '--quiet') 'pip upgrade'
    Invoke-Native $VenvPython @('-m', 'pip', 'install', '-r', (Join-Path $RepoRoot 'requirements.txt')) 'dependency install'
    Write-Ok 'dependencies installed'
}

function Sync-GitCorpus {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Dest,
        # Relative path that must exist for the corpus to count as complete. A
        # clone that died mid-checkout leaves .git behind, and refreshing that
        # would silently keep an empty corpus.
        [Parameter(Mandatory)][string]$ContentProbe,
        [string[]]$SparsePaths,
        [switch]$AllowNtfsReservedPaths
    )

    if ((Test-Path (Join-Path $Dest '.git')) -and (Test-Path (Join-Path $Dest $ContentProbe))) {
        Write-Step "Refreshing $Name"
        Invoke-Native 'git' @('-C', $Dest, 'fetch', '--depth', '1', 'origin') "$Name fetch"
        Invoke-Native 'git' @('-C', $Dest, 'reset', '--hard', 'FETCH_HEAD') "$Name reset"
        Write-Ok "$Name up to date"
        return
    }

    Write-Step "Cloning $Name (shallow)"
    if (Test-Path $Dest) {
        Write-Note 'existing copy is incomplete, re-cloning'
        Remove-Item -Recurse -Force $Dest
    }

    if ($SparsePaths) {
        Invoke-Native 'git' @('clone', '--depth', '1', '--single-branch', '--filter=blob:none', '--no-checkout', $Url, $Dest) "$Name clone"

        if ($AllowNtfsReservedPaths) {
            # Some packages ship test fixtures whose filenames contain ':'
            # (ISO timestamps), which NTFS cannot represent. Git validates every
            # tree entry while building the index, including entries the sparse
            # rules exclude, so the checkout below aborts with "invalid path"
            # unless this guard is off. Those files stay sparse-excluded and are
            # never written to disk, only tolerated as index entries.
            Invoke-Native 'git' @('-C', $Dest, 'config', 'core.protectNTFS', 'false') "$Name protectNTFS config"
        }

        Invoke-Native 'git' (@('-C', $Dest, 'sparse-checkout', 'set', '--no-cone') + $SparsePaths) "$Name sparse-checkout"
        Invoke-Native 'git' @('-C', $Dest, 'checkout') "$Name checkout"
    } else {
        Invoke-Native 'git' @('clone', '--depth', '1', '--single-branch', $Url, $Dest) "$Name clone"
    }
    Write-Ok "$Name cloned to $Dest"
}

function Get-MitreBundle {
    Write-Step 'MITRE ATT&CK STIX bundle (Enterprise)'
    New-Item -ItemType Directory -Force -Path $MitreDir | Out-Null
    Invoke-WebRequest -Uri $MitreStixUrl -OutFile $MitreFile -UseBasicParsing
    $sizeMb = [math]::Round((Get-Item $MitreFile).Length / 1MB, 1)
    Write-Ok "enterprise-attack.json ($sizeMb MB)"
}

function Initialize-Database {
    Write-Step 'Database + taxonomy seed'
    $python = if (Test-Path $VenvPython) { $VenvPython } else { 'python' }
    Invoke-Native $python @('-m', 'engine.storage.db', '--init') 'database init'
    Invoke-Native $python @((Join-Path $RepoRoot 'scripts\seed_taxonomy.py')) 'taxonomy seed'
}

function Write-Summary {
    Write-Step 'Summary'
    if (Test-Path (Join-Path $SigmaDir 'rules')) {
        $ruleCount = (Get-ChildItem -Path (Join-Path $SigmaDir 'rules') -Recurse -Filter '*.yml' -File).Count
        Write-Ok "sigma corpus:         $ruleCount rules  ->  $SigmaDir"
    } else {
        Write-Note "sigma corpus:         not present"
    }
    if (Test-Path (Join-Path $IntegrationsDir 'packages')) {
        $pkgCount = (Get-ChildItem -Path (Join-Path $IntegrationsDir 'packages') -Directory).Count
        Write-Ok "elastic integrations: $pkgCount packages  ->  $IntegrationsDir"
    } else {
        Write-Note "elastic integrations: not present"
    }
    if (Test-Path $MitreFile) {
        Write-Ok "mitre att&ck:         $([math]::Round((Get-Item $MitreFile).Length / 1MB, 1)) MB  ->  $MitreFile"
    } else {
        Write-Note "mitre att&ck:         not present"
    }
    $db = Join-Path $DataDir 'engine.db'
    if (Test-Path $db) { Write-Ok "database:             $db" } else { Write-Note "database:             not present" }

    Write-Host ''
    Write-Host 'Next:' -ForegroundColor Cyan
    Write-Host '    .\.venv\Scripts\Activate.ps1'
    Write-Host '    python scripts\cli.py tests\fixtures\<sample>.csv   (Phase 1 onward)'
    Write-Host ''
}

Push-Location $RepoRoot
try {
    Assert-Prerequisites
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

    if ($SkipVenv) { Write-Step 'Skipping venv + dependencies (-SkipVenv)' } else { Initialize-Venv }

    if ($SkipCorpora) {
        Write-Step 'Skipping reference corpora (-SkipCorpora)'
    } else {
        Sync-GitCorpus -Name 'SigmaHQ/sigma' -Url $SigmaRepo -Dest $SigmaDir -ContentProbe 'rules'
        Sync-GitCorpus -Name 'elastic/integrations' -Url $IntegrationsRepo -Dest $IntegrationsDir `
            -ContentProbe 'packages' -SparsePaths $IntegrationsSparsePaths -AllowNtfsReservedPaths
        Get-MitreBundle
    }

    if ($SkipDb) { Write-Step 'Skipping database init (-SkipDb)' } else { Initialize-Database }

    Write-Summary
}
finally {
    Pop-Location
}
