param(
    [string]$Remote = 'origin',
    [string]$Branch = 'main',
    [string]$CommitMessage = 'feat: prepare Vercel deployment',
    [switch]$SkipCommit,
    [switch]$SkipPush,
    [switch]$SkipDeploy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

Write-Step "Checking repository state"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoRoot

if (-not (Test-Path .git)) {
    throw 'This script must be run from the repository root.'
}

if (-not $SkipCommit) {
    $status = git status --porcelain
    if ($status) {
        Write-Step "Committing current changes"
        git add .
        git commit -m $CommitMessage
    }
    else {
        Write-Host 'No local changes to commit.' -ForegroundColor Yellow
    }
}

if (-not $SkipPush) {
    Write-Step "Pushing to GitHub"
    git push $Remote $Branch
}

if (-not $SkipDeploy) {
    if (-not (Get-Command vercel -ErrorAction SilentlyContinue)) {
        throw 'Vercel CLI is not installed. Install it with: npm install -g vercel'
    }

    Write-Step "Deploying to Vercel"
    vercel --prod
}

Write-Host "`nDone." -ForegroundColor Green
