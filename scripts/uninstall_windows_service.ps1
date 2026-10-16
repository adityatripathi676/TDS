# AI-HIDS Sentinel - Windows Service Uninstaller Script
# Must be executed in an elevated PowerShell session (Run as Administrator)

param(
    [string]$ServiceName = "AIHIDSSentinel"
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "ERROR: This script must be run as Administrator! Please re-open PowerShell as Administrator."
    exit 1
}

Write-Host "Stopping and removing Windows Service '$ServiceName'..." -ForegroundColor Yellow

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $existingService) {
    Write-Host "Service '$ServiceName' is not installed." -ForegroundColor Yellow
    exit 0
}

sc.exe stop $ServiceName | Out-Null
Start-Sleep -Seconds 2
sc.exe delete $ServiceName | Out-Null

Write-Host "Service '$ServiceName' has been successfully uninstalled." -ForegroundColor Green
