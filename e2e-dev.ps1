#Requires -Version 7.0

$ErrorActionPreference = "Stop"

$configDir = Join-Path $PSScriptRoot "runtime/config"
$dataDir = Join-Path $PSScriptRoot "runtime/data"
$staticDir = Join-Path $PSScriptRoot "frontend/dist"
$backendExecutable = Join-Path $PSScriptRoot "backend/pwsafe-service.exe"

New-Item -ItemType Directory -Force -Path $configDir, $dataDir | Out-Null
$settingsPath = Join-Path $configDir "settings.json"
if (-not (Test-Path -LiteralPath $settingsPath)) {
    $serverPort = if ($env:PWSAFE_PORT) { $env:PWSAFE_PORT } else { "8080" }
    @{
        baseUrl = "http://localhost:$serverPort"
        providers = @{ mock = @{} }
    } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $settingsPath -Encoding utf8
}

# On first start, visit the user interface in your browser to choose an authentication mode.
# To skip setup for development, add "auth": { "mode": "disabled" } to settings.json.

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Command,
        [Parameter(Mandatory)]
        [string]$Description
    )

    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

Write-Host "Building frontend..."
Push-Location (Join-Path $PSScriptRoot "frontend")
try {
    Invoke-NativeCommand { npm.cmd ci } "Installing frontend dependencies"
    Invoke-NativeCommand { npm.cmd run build } "Building frontend"
} finally {
    Pop-Location
}

Write-Host "Building end-to-end tests..."
Push-Location (Join-Path $PSScriptRoot "e2e")
try {
    Invoke-NativeCommand { npm.cmd ci } "Installing end-to-end test dependencies"
} finally {
    Pop-Location
}

Write-Host "Building backend..."
Push-Location (Join-Path $PSScriptRoot "backend")
try {
    Invoke-NativeCommand { go mod download } "Downloading backend dependencies"
    Invoke-NativeCommand { go build -o $backendExecutable cmd/pwsafe-service/main.go } "Building backend"
} finally {
    Pop-Location
}

Write-Host "Stopping any running instance..."
Get-Process -Name "pwsafe-service" -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.Id -Force }

Write-Host "Starting pwsafe-service..."
$env:PWSAFE_CONFIG_DIR = $configDir
$env:PWSAFE_DATA_DIR = $dataDir
$env:PWSAFE_STATIC_DIR = $staticDir
Push-Location (Join-Path $PSScriptRoot "backend")
try {
    & $backendExecutable
    if ($LASTEXITCODE -ne 0) {
        throw "pwsafe-service exited with code $LASTEXITCODE."
    }
} finally {
    Pop-Location
}
