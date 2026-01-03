<#
.Author
    Aditya Sharma

.Purpose
    Automated Active Directory user provisioning with validation, logging,
    audit traceability, and enterprise-ready execution controls.

.Context
    Designed and tested in an enterprise-style lab environment to simulate
    real-world IAM and infrastructure operations.

.Features
    - Bulk user creation from CSV
    - Pre-validation and duplicate detection
    - Secure random password generation
    - Centralized logging and transcript capture
    - Optional group membership assignment
    - Safe execution using -WhatIf support
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [string]$CsvPath,

    [string]$LogFolder = "C:\Temp",

    [string]$UPNSuffix = "zy.va.atcsg.net"
)

# -----------------------------
# Pre-flight checks
# -----------------------------
Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path $CsvPath)) {
    throw "CSV file not found at path: $CsvPath"
}

if (-not (Test-Path $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
}

# -----------------------------
# Logging & Transcript
# -----------------------------
$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile   = Join-Path $LogFolder "ADUserCreation_$TimeStamp.log"
$TranscriptFile = Join-Path $LogFolder "ADUserCreation_$TimeStamp.transcript.txt"

Start-Transcript -Path $TranscriptFile -Append | Out-Null

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR")]
        [string]$Level = "INFO"
    )

    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    $line | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host $line
}

Write-Log "Starting AD bulk user provisioning"
Write-Log "CSV Source: $CsvPath"

# -----------------------------
# Import CSV
# -----------------------------
$users = Import-Csv -Path $CsvPath -ErrorAction Stop

foreach ($u in $users) {

    $sam     = ($u.samaccountname  -as [string]).Trim()
    $first   = ($u.firstname       -as [string]).Trim()
    $last    = ($u.lastname        -as [string]).Trim()
    $display = ($u.displayname     -as [string]).Trim()
    $ou      = ($u.ou              -as [string]).Trim()
    $group   = ($u.group           -as [string]).Trim()

    if ([string]::IsNullOrWhiteSpace($sam) -or
        [string]::IsNullOrWhiteSpace($display) -or
        [string]::IsNullOrWhiteSpace($ou)) {

        Write-Log "Missing mandatory attributes for SAM='$sam'. Skipping row." "WARN"
        continue
    }

    Write-Log "Processing user: $sam"

    # Duplicate check
    if (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
        Write-Log "User $sam already exists. Skipping creation." "WARN"
        continue
    }

    # Generate temporary password
    $tempPasswordPlain = -join ((33..126) | Get-Random -Count 14 | ForEach-Object {[char]$_})
    $securePassword = ConvertTo-SecureString $tempPasswordPlain -AsPlainText -Force

    try {
        if ($PSCmdlet.ShouldProcess($sam, "Create AD User")) {

            New-ADUser `
                -Name $display `
                -GivenName $first `
                -Surname $last `
                -SamAccountName $sam `
                -DisplayName $display `
                -UserPrincipalName "$sam@$UPNSuffix" `
                -Path $ou `
                -AccountPassword $securePassword `
                -ChangePasswordAtLogon $true `
                -Enabled $true `
                -ErrorAction Stop

            Write-Log "User $sam created successfully in OU $ou"

            # Tag user for cloud sync awareness
            Set-ADUser -Identity $sam -Replace @{ extensionAttribute14 = "EntraSYNC" } -ErrorAction Stop

            # Password export (controlled file)
            $PasswordExportFile = Join-Path $LogFolder "CreatedUserPasswords.csv"
            if (-not (Test-Path $PasswordExportFile)) {
                "samaccountname,temppassword" | Out-File $PasswordExportFile -Encoding UTF8
            }

            Add-Content -Path $PasswordExportFile -Value "`"$sam`",`"$tempPasswordPlain`"" -Encoding UTF8

            # Optional group membership
            if ($group) {
                Add-ADGroupMember -Identity $group -Members $sam -ErrorAction Stop
                Write-Log "Added $sam to group '$group'"
            }
        }
    }
    catch {
        Write-Log "Failed processing user $sam : $_" "ERROR"
    }
}

Write-Log "AD user provisioning completed"
Write-Log "Log file: $LogFile"
Write-Log "Transcript: $TranscriptFile"

Stop-Transcript | Out-Null
