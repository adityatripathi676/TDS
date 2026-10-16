# AI-HIDS Sentinel - Windows Service Installer Script
# Must be executed in an elevated PowerShell session (Run as Administrator)

param(
    [string]$ServiceName = "AIHIDSSentinel",
    [string]$DisplayName = "AI-HIDS Sentinel Host Protection Agent",
    [string]$Description = "AI-Driven Host Intrusion Detection & Threat Containment System"
)

# 1. Verify Administrative Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "ERROR: This script must be run as Administrator! Please re-open PowerShell as Administrator."
    exit 1
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " AI-HIDS Sentinel - Windows Background Service Installer" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 2. Determine Paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectDir = (Get-Item "$ScriptDir\..").FullName
$RunScript = "$ProjectDir\run.py"

$PythonPath = (Get-Command python.exe -ErrorAction SilentlyContinue).Path
if (-not $PythonPath) {
    Write-Error "ERROR: python.exe was not found in PATH! Please ensure Python is installed and added to PATH."
    exit 1
}

Write-Host "Project Root: $ProjectDir" -ForegroundColor Yellow
Write-Host "Python Executable: $PythonPath" -ForegroundColor Yellow
Write-Host "Service Name: $ServiceName" -ForegroundColor Yellow

# 3. Check if Service already exists
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Service '$ServiceName' already exists. Stopping and removing old instance..." -ForegroundColor Yellow
    sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# 4. Create Windows Service
# We launch python.exe run.py in the background
$BinPath = "`"$PythonPath`" `"$RunScript`""
Write-Host "Creating Windows Service via sc.exe..." -ForegroundColor Green

sc.exe create $ServiceName binPath= "cmd.exe /c `"$BinPath`"" start= auto displayName= "$DisplayName" | Out-Null
sc.exe description $ServiceName "$Description" | Out-Null

# 5. Set Recovery Options (Restart on failure)
sc.exe failure $ServiceName reset= 86400 actions= restart/6000/restart/10000/restart/30000 | Out-Null

# 6. Start Service
Write-Host "Starting '$ServiceName' service..." -ForegroundColor Green
sc.exe start $ServiceName | Out-Null

Start-Sleep -Seconds 2
$status = (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status

Write-Host "----------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Installation Complete! Service Status: $status" -ForegroundColor Green
Write-Host "AI-HIDS Sentinel is now running continuously in the background on boot." -ForegroundColor Green
Write-Host "----------------------------------------------------------------------" -ForegroundColor Cyan
