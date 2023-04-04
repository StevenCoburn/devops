# RUN ME WITH THIS COMMAND:
# powershell -ExecutionPolicy Bypass -File ".\Win-Setup.ps1"

<# Manual Customizations (Mainly Windows 11)
- Set apps to not auto start
- Sign into apps and customize individual app settings
- Touchpad - Change direction
- Personalization - Lock Screen - Status - Weather
- Personalization - Start - Turn off Recently Added Apps
- Personalization - Start - Turn off Recently Opened Items
- Personalization - Start - Folders - Settings/File Explorer/Downloads/Network
- Privacy - For Developers - Terminal - Terminal
- Privacy - General - turn off all spying
- Privacy - Diagnostics - Feedback - Never
- Privacy - Activity History - Off
- Privacy - Search - turn off everything
- Privacy - Search Windows - Respect Power
- Privacy - Search Windows - Enhanced
- Associate File Types
- Set Default Browser
- Pin items to Quick Access (Recycle Bin, user account, samba shares)
- Pin items to Start and Taskbar
- Uninstall Windows bloatware
- Add a PIN or biometrics
- Change font/theme/colors in Terminal, VS Code, and PowerShell
- Install RSAT Tools from Settings > Apps > Optional features
- Install Jetbrains Apps
- Install Device-specific drivers and firmware (including Thunderbolt and Thunderbolt Control Center)
- Configure Multi-Monitor Positioning
- Remove Pen taskbar icon
- Restore files (powershell profile and etc.)
#>

#Requires -RunAsAdministrator

Start-Transcript -Path C:\SETUP.log

# Detect Win 10 or Win 11
$WindowsVersion = (Get-WMIObject win32_operatingsystem).Caption
if ($WindowsVersion -match "Windows 10") {
    Write-Output "Windows 10 detected"
}
if ($WindowsVersion -match "Windows 11") {
    Write-Output "Windows 11 detected"
}

$NewName = Read-Host -Prompt "Enter new PC name or press enter to skip"
if ($NewName -ne "") {
    Rename-Computer -NewName $NewName -Force
} else {
    Write-Output "Skipping PC rename"
}

$ChangePW = Read-Host -Prompt "Change password? [y/N]"
if ($ChangePW.ToLower() -eq "y") {
    $NewPassword = Read-Host -Prompt "Enter new password" -AsSecureString
    Set-LocalUser -Name $env:USERNAME -Password $NewPassword -PasswordNeverExpires $true -AccountNeverExpires
} else {
    Write-Output "Skipping password change"
}

# Set time zone
Set-TimeZone -Name "Mountain Standard Time"

#region Install OpenSSH Beta (yubikey and devcontainer support)
# Get the latest download URL
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
$request = [System.Net.WebRequest]::Create($url)
$request.AllowAutoRedirect=$false
$response=$request.GetResponse()
$DLBaseURL = $([String]$response.GetResponseHeader("Location")).Replace('tag','download')

# Extract version number from download URL
$DLBaseURL -match "(?s)download/(?<content>.*)p" | Out-Null
$SSHVersion = $matches['content']

# Download OpenSSH MSI
$MSIPath = "$env:USERPROFILE/Downloads/openssh.msi"
Invoke-WebRequest -Uri "$DLBaseURL/OpenSSH-Win64-$SSHVersion.msi" -OutFile $MSIPath

# Install the OpenSSH MSI
Start-Process $MSIPath -ArgumentList "/qn" -Wait

# Remove the installer after we're done
Remove-Item -Path $MSIPath -Force

$DisableSSHD = Read-Host -Prompt "Disable the SSH server service? [Y/n]"
if ($DisableSSHD.ToLower() -eq "y" -or $DisableSSHD -eq "") {
    Stop-Service sshd
    Set-Service -StartupType Disabled sshd
}
#endregion

#region Windows Updates
$hasNuget = Test-Path -Path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget"
$hasPSWinUpdate = Test-Path -Path "C:\Program Files\WindowsPowerShell\Modules\PSWindowsUpdate"
if (!($hasNuget)) {
    Install-PackageProvider -Name NuGet -Force
} else {
    Write-Output "$(Get-Date -Format HH:mm:ss) - NuGet is already installed."
}
if (!($hasPSWinUpdate)) {
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
    # PSWindowsUpdate 1.6.1.1 was the last version we can audit. New versions are compiled.
    # https://www.powershellgallery.com/packages/PSWindowsUpdate/1.6.1.1
    Install-Module -Name PSWindowsUpdate -RequiredVersion 1.6.1.1 -Force
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Untrusted
} else {
    Write-Output "$(Get-Date -Format HH:mm:ss) - PSWindowsUpdate is already installed."
}
# Install updates - Scope down updates with this: -Category:@('Critical Updates', 'Security Updates', 'Update Rollup', 'Service Stack Updates')
Get-WUInstall -AcceptAll -IgnoreUserInput -IgnoreReboot -Confirm:$false
#endregion

# Customize sleep and disable hibernate
PowerCFG /H off
PowerCFG /X monitor-timeout-dc 5
PowerCFG /X monitor-timeout-ac 30
PowerCFG /X disk-timeout-dc 10
PowerCFG /X disk-timeout-ac 60
PowerCFG /X standby-timeout-dc 15
PowerCFG /X standby-timeout-ac 0

# Change networks to private
Write-Output "Setting network interfaces to Private"
Get-NetConnectionProfile -NetworkCategory "Public" -ea SilentlyContinue | Set-NetConnectionProfile -NetworkCategory "Private"

# Rename C drive to Windows SSD
Set-Volume -DriveLetter C -NewFileSystemLabel "Windows SSD"

# Developer Options - Set PowerShell ExecutionPolicy
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force

# Add some sites to trusted intranet sites
# This does not handle subdomains
$sites = Read-Host "Enter a list of sites to add to the trusted intranet sites (comma separated)"
$sites = $sites.Split(',')
ForEach ($site in $sites) {
    Get-Location | Push-Location 
    Set-Location "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains" 
    New-Item $site -ErrorAction SilentlyContinue
    New-ItemProperty $site -Name * -Value 1 -Type DWORD -ErrorAction SilentlyContinue
    Pop-Location
}

# Windows 11-Specific Customizations
if ($WindowsVersion -match "Windows 11") {
    # Install Explorer Patcher
    Write-Output "Using Windows 11, we need ExplorerPatcher..."
    $PatcherURL = "https://github.com/valinet/ExplorerPatcher/releases/latest/download/ep_setup.exe"
    $LocalPatcher = "$env:USERPROFILE\Downloads\explorerpatcher.exe"
    Invoke-WebRequest -Uri $PatcherURL -OutFile $LocalPatcher
    Start-Process -FilePath $LocalPatcher -Wait
    Remove-Item -Path $LocalPatcher -Force
    reg import $PSScriptRoot\ExplorerPatcher.reg

    # Enable Dark Mode / Dark Theme
    # Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0 -Type Dword -Force
    # Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme -Value 0 -Type Dword -Force
    Start-Process -FilePath "C:\Windows\Resources\Themes\dark.theme" -Wait
}

# Windows 10-Specific Customizations
if ($WindowsVersion -match "Windows 10") {
    # Hide warning about not using a Microsoft Account
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Type DWord -Value 1
    # Disable the News and Interests toolbar (June 2021 cumulative update)
    REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /f /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d "2"
    REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /f /v "EnableFeeds " /t REG_DWORD /d "0"
    #REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "ShowCortanaButton" /t REG_DWORD /d "0" # Hide Cortana button
}

# Change registry keys (mainly Explorer settings)
Write-Output "Setting custom Explorer settings"
# Windows 11 needs Explorer Patcher to make these work! https://github.com/valinet/ExplorerPatcher
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "ShowSecondsInSystemClock" /t REG_DWORD /d "1" # Show seconds on system clock
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /f /v "TraySearchBoxVisible" /t REG_DWORD /d "0" # Hide search box on taskbar - win 11 only needs one key for this - win 10 needs two
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /f /v "EnableAutoTray" /t REG_DWORD /d "0" # Always show all taskbar icons - Win11 has to be done manually with "explorer shell:::{05d7b0f4-2121-4eff-bf6b-ed3f69b894d9}"
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "MMTaskbarGlomLevel" /t REG_DWORD /d "2" # Never combine taskbar buttons on secondary displays
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "TaskbarGlomLevel" /t REG_DWORD /d "2" # Never combine taskbar buttons on primary displays

# These should work in Win10 and Win11 the same
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "HideDrivesWithNoMedia" /t REG_DWORD /d "0" # Do not hide drives with no media
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "LaunchTo" /t REG_DWORD /d "1" # Open Explorer in This PC instead of Quick Access
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /f /v "ShowFrequent" /t REG_DWORD /d "0" # Turn off frequent files in Quick Access
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /f /v "ShowRecent" /t REG_DWORD /d "0" # Turn off recent files in Quick Access
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /f /v "{645FF040-5081-101B-9F08-00AA002F954E}" /t REG_DWORD /d "1" # Remove Recycle Bin from Desktop
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /f /v "EnthusiastMode" /t REG_DWORD /d "1" # Show more info in the File Transfer dialog box
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /f /v "ConfirmationCheckBoxDoForAll" /t REG_DWORD /d "1" # Auto check the "do for all" for file transfers
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f /v "NoDriveTypeAutoRun" /t REG_DWORD /d "0xFF" # Do not autorun USB or SD Cards
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock" /f /v "AllowDevelopmentWithoutDevLicense" /t REG_DWORD /d "1" # Developer Mode
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock" /f /v "AllowAllTrustedApps" /t REG_DWORD /d "1" # Developer Mode
REG ADD "HKCU\Control Panel\International" /f /v "sShortTime" /t REG_SZ /d "H:mm" # 24 hour clock format
REG ADD "HKCU\Control Panel\International" /f /v "sTimeFormat" /t REG_SZ /d "H:mm:ss" # 24 hour clock format

# Windows 11 - These two only worked after enabling Developer Mode
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "Hidden" /t REG_DWORD /d "1" # Show hidden files
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "HideFileExt" /t REG_DWORD /d "0" # Show file extensions
REG ADD "HKCU\Software\Policies\Microsoft\Windows\Explorer" /f /v "ShowRunAsDifferentUserInStart" /t REG_DWORD /d "1" # Show Run as Different User in Start
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /f /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" # Hide search box on taskbar
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "ShowTaskViewButton" /t REG_DWORD /d "0" # Hide task view on taskbar
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "MMTaskbarMode" /t REG_DWORD /d "2" # Show taskbar buttons on taskbar where window is open

# Sets BIOS Time to UTC (useful for dual-booting)
# Can also set "localtime" in Linux but I prefer to set it in Windows
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1

# Hide Bluetooth tray icon
Set-Itemproperty 'HKCU:\Control Panel\Bluetooth' -Name 'Notification Area Icon' -Value '0' -Type DWord

# Do not append "- shortcut" to new shortcuts
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0, 0, 0, 0))

# Empty the Start Tiles
$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
$data = $key.Data[0..25] + ([byte[]](202, 50, 0, 226, 44, 1, 1, 0, 0))
Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $data
Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue

# Disable AutoPlay
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
# Enable file paths longer than 260 char
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 1
# Disable Fast Startup
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
# Disable IPV6
Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"

# Disable telemetry in PowerShell
[System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', [System.EnvironmentVariableTarget]::Machine)
# Disable Error Reporting
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
# Disable Connected User Experiences
Stop-Service "DiagTrack" -WarningAction SilentlyContinue
Set-Service "DiagTrack" -StartupType Disabled
# Stop and disable Diagnostics Hub Standard Collector Service
Stop-Service "diagnosticshub.standardcollector.service" -WarningAction SilentlyContinue
Set-Service "diagnosticshub.standardcollector.service" -StartupType Disabled

# Customize PowerShell
Write-Output "Customizing PowerShell"
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
Install-Module posh-git -Force
Set-PSRepository -Name "PSGallery" -InstallationPolicy Untrusted
Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://ohmyposh.dev/install.ps1'))

# Refresh the environment variables
$Env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

oh-my-posh font install JetBrainsMono
oh-my-posh font install CascadiaCode

# Install Chocolatey
Write-Output "Install Chocolatey"
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install software bundles and Windows features
Write-Output "Starting install of choco stuff"
choco install -y "$PSScriptRoot/choco-packages.config"

# Install WSL2 and Ubuntu by default (new way)
# wsl --install

#region WSL install the old and buggy way
<#
# Download WSL 2 kernel update
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi" -Outfile "$env:USERPROFILE\Downloads\wsl_update.msi"
Start-Process msiexec -ArgumentList "/i $env:USERPROFILE\Downloads\wsl_update.msi /quiet" -Wait
Remove-Item "$env:USERPROFILE\Downloads\wsl_update.msi" -Force
# Set WSL to WSL 2
wsl --set-default-version 2
# Install Ubuntu WSL2
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri https://aka.ms/wslubuntu -OutFile "$env:USERPROFILE\Downloads\Ubuntu.appx" -UseBasicParsing
Add-AppxPackage "$env:USERPROFILE\Downloads\Ubuntu.appx"
Remove-Item "$env:USERPROFILE\Downloads\Ubuntu.appx" -Force
#>
#endregion

# Remove VLC from context menu
Get-Item Registry::HKEY_CLASSES_ROOT\Directory\shell\AddToPlaylistVLC | Remove-Item -Force -Recurse -Verbose
Get-Item Registry::HKEY_CLASSES_ROOT\Directory\shell\PlayWithVLC | Remove-Item -Force -Recurse -Verbose

# Run Disk Cleanup with all options selected
Write-Output "---------------------------------------------------------"
Write-Output "$(Get-Date -Format HH:mm:ss) - Running Disk Cleanup"
Write-Output "---------------------------------------------------------"
$strKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
$strValueName = "StateFlags0065"
$subkeys = Get-ChildItem -Path $strKeyPath -Name
ForEach ($subkey in $subkeys) {
    $null = New-ItemProperty  -Path $strKeyPath\$subkey -Name $strValueName -PropertyType DWord -Value 2 -ea SilentlyContinue -wa SilentlyContinue
}
Start-Process cleanmgr -ArgumentList "/sagerun:65" -Wait -NoNewWindow -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
ForEach ($subkey in $subkeys) {
    $null = Remove-ItemProperty -Path $strKeyPath\$subkey -Name $strValueName -ea SilentlyContinue -wa SilentlyContinue
}

# Defrag the main drive
Write-Output "---------------------------------------------------------"
Write-Output "$(Get-Date -Format HH:mm:ss) - Running disk defrag"
Write-Output "---------------------------------------------------------"
Optimize-Volume -DriveLetter C -Defrag
Optimize-Volume -DriveLetter C -ReTrim

#Delete powershell history 
Remove-Item (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue

Stop-Transcript
