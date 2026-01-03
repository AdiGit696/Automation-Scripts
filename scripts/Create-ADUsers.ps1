$CsvPath = "File Path where CSV is stored"
$users = Import-Csv -Path $CsvPath -ErrorAction Stop
$LogFolder = "C:\Temp"



# ensure log folder exists
if (-not (Test-Path -Path $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null }


$LogFile = Join-Path $LogFolder ("ADUserCreation_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    $line | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host $line
}

# Start
Write-Log "Starting AD bulk create. CSV: $CsvPath"

foreach ($u in $users) {
    # Normalize values (trim)
    $sam = ($u.samaccountname -as [string]).Trim()
    $first = ($u.firstname -as [string]).Trim()
    $last = ($u.lastname -as [string]).Trim()
    $display = ($u.displayname -as [string]).Trim()
    $ou = ($u.ou -as [string]).Trim()
    $group = ($u.group -as [string]).Trim()

    if ([string]::IsNullOrWhiteSpace($sam) -or [string]::IsNullOrWhiteSpace($display) -or [string]::IsNullOrWhiteSpace($ou)) {
        Write-Log "Missing required fields for SAM='$sam' - skipping row." "WARN"
        continue
    }

    Write-Log "Processing user: $sam"

    # Check if user already exists — robust form (no duplicate ErrorAction params)
    $exists = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue
    if ($exists) {
        Write-Log "User $sam already exists. Skipping creation." "WARN"
        continue
    }

    # Generate a strong random temporary password (you can change policy here)
    $tempPasswordPlain = -join ((33..126) | Get-Random -Count 14 | ForEach-Object {[char]$_})
    $securePassword = ConvertTo-SecureString -String $tempPasswordPlain -AsPlainText -Force

    try {
        # Create user
        $newUserParams = @{
            Name = $display
            GivenName = $first
            Surname = $last
            SamAccountName = $sam
            DisplayName = $display
            Path = $ou
            AccountPassword = $securePassword
            ChangePasswordAtLogon = $true
            Enabled = $true
            UserPrincipalName = "$sam@zy.va.atcsg.net"
        }

        New-ADUser @newUserParams -ErrorAction Stop
        Write-Log "Created user $sam in OU $ou."

        # Ensure mail attribute is cleared (explicitly blank)
        # Set-ADUser -Identity $sam -Clear mail -ErrorAction Stop

        # Set extensionAttribute14 = "EntraSYNC" for Syncing user on cloud
        # Use -Replace so it sets even if attribute exists
        Set-ADUser -Identity $sam -Replace @{extensionAttribute14='EntraSYNC'} -ErrorAction Stop

        # Export temp passwords to CSV
        $PasswordExportFile = "C:\Temp\CreatedUserPasswords.csv"
        if (-not (Test-Path $PasswordExportFile)) {
            "samaccountname,temppassword" | Out-File $PasswordExportFile -Encoding UTF8
        }

        # Append quoted line to avoid comma issues
        $escapedSam = $sam.Replace('"','""')
        $escapedPwd = $tempPasswordPlain.Replace('"','""')
        $line = '"' + $escapedSam + '","' + $escapedPwd + '"'
        Add-Content -Path $PasswordExportFile -Value $line -Encoding UTF8

        # Add to group if provided
        if (-not [string]::IsNullOrWhiteSpace($group)) {
            try {
                $g = Get-ADGroup -Identity $group -ErrorAction Stop
                Add-ADGroupMember -Identity $g -Members $sam -ErrorAction Stop
                Write-Log "Added $sam to group '$group'."
            } catch {
                # if group not found by identity, try searching by name
                try {
                    $g2 = Get-ADGroup -Filter { Name -eq $group } -ErrorAction Stop
                    Add-ADGroupMember -Identity $g2 -Members $sam -ErrorAction Stop
                    Write-Log "Added $sam to group (found by name) '$($g2.Name)'."
                } catch {
                    Write-Log "Could not add $sam to group '$group' : $_" "ERROR"
                }
            }
        }

    } catch {
        Write-Log "Failed to create user $sam : $_" "ERROR"
        continue
    }
}

Write-Log "Processing completed. Log saved to $LogFile"
Write-Log "Passwords exported to C:\Temp\CreatedUserPasswords.csv (protect this file!)."
