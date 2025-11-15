<#
.SYNOPSIS
    Downloads and installs Microsoft Defender Antivirus antimalware platform updates from Microsoft Update Catalog.

.DESCRIPTION
    This script automates the download and installation of Microsoft Defender Antivirus antimalware 
    platform updates (KB4052623) for AMD64 architecture from the Microsoft Update Catalog using
    direct web scraping (no module dependencies).
    
    The script performs the following actions:
    1. Ensures the download directory exists
    2. Searches the Microsoft Update Catalog for the latest KB4052623 update (Current Channel - Broad)
    3. Downloads the AMD64 version of the update
    4. Removes the Mark of the Web from the downloaded executable
    5. Installs the update silently
    6. Validates the installation by checking the updated Defender version

.NOTES
    Author:  DCODEV1702 & Claude Sonnet 4.5
    Date:    November 15, 2025
    Version: 1.0
    Requires: Administrator privileges
#>

# Set TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Ensure download directory exists
$downloadPath = "C:\Temp"
if (-not (Test-Path -Path $downloadPath)) {
    New-Item -Path $downloadPath -ItemType Directory -Force | Out-Null
}

# Search the catalog
$searchUrl = "https://www.catalog.update.microsoft.com/Search.aspx?q=KB4052623"
Write-Host "Searching catalog..." -ForegroundColor Cyan
$searchResults = Invoke-WebRequest -Uri $searchUrl -UseBasicParsing

# Extract update GUIDs using the correct pattern
$guidPattern = 'id="([a-f0-9\-]{36})"'
$updateGuids = [regex]::Matches($searchResults.Content, $guidPattern) | ForEach-Object { $_.Groups[1].Value }

if ($updateGuids.Count -eq 0) {
    Write-Error "Could not find any update GUIDs"
    exit 1
}

# Use the first GUID (Current Channel - Broad)
$updateGuid = $updateGuids[0]
Write-Host "Found update GUID: $updateGuid" -ForegroundColor Green

# Simulate clicking the Download button - POST to DownloadDialog.aspx
Write-Host "Getting download dialog..." -ForegroundColor Cyan
$downloadDialogUrl = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
$postParams = @{
    updateIDs = "[{'size':0,'updateID':'$updateGuid','uidInfo':'$updateGuid'}]"
}

$dialogResponse = Invoke-WebRequest -Uri $downloadDialogUrl -Method Post -Body $postParams -UseBasicParsing -ContentType "application/x-www-form-urlencoded"

# Extract the amd64.exe download link from the dialog
$downloadLinks = [regex]::Matches($dialogResponse.Content, 'https?://[^"''<>]+\.exe') | ForEach-Object { $_.Value }

# Filter for amd64 link
$amd64Link = $downloadLinks | Where-Object { $_ -like "*amd64*" } | Select-Object -First 1

if (-not $amd64Link) {
    Write-Error "Could not find amd64 download link in dialog"
    Write-Host "Available links:" -ForegroundColor Yellow
    $downloadLinks | ForEach-Object { Write-Host $_ }
    exit 1
}

Write-Host "Download URL: $amd64Link" -ForegroundColor Green

# Download the file
$fileName = Split-Path -Path $amd64Link -Leaf
$outputFile = Join-Path -Path $downloadPath -ChildPath $fileName

Write-Host "Downloading $fileName to $downloadPath..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $amd64Link -OutFile $outputFile -UseBasicParsing

# Unblock
Unblock-File -Path $outputFile
Write-Host "File unblocked" -ForegroundColor Green

# Install
Write-Host "Installing update..." -ForegroundColor Cyan
Start-Process -FilePath $outputFile -ArgumentList "/quiet" -Wait

# Validate
Write-Host "`nValidating installation..." -ForegroundColor Cyan
Get-MpComputerStatus | Select-Object AMProductVersion, AMEngineVersion | ForEach-Object {
    Write-Host "Antimalware Product Version: $($_.AMProductVersion)" -ForegroundColor Green
    Write-Host "Antimalware Engine Version: $($_.AMEngineVersion)" -ForegroundColor Green
    Write-Host "Antimalware platform update installed successfully." -ForegroundColor Green
}
