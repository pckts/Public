$DevLogOutput = "$home\VerboseDevLog-NOTEPDVUL.log"
Start-Transcript -Path $DevLogOutput -Append

#Minor shell setup
$ProgressPreference = "SilentlyContinue"
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

#Verifies that the script is being run as admin
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false)
{
  Clear-Host
  write-host "Please run as admin..."
  sleep 1
  break
}

#Verifies that the deployment is run on a domain controller
$IsDC = Get-WmiObject -Class Win32_OperatingSystem | Select-Object ProductType
if ($IsDC.ProductType -ne "2")
{
  Clear-Host
  write-host "This server is not a Domain Controller"
  write-host "Please retry on a server that has the Domain Controller role"
  write-host ""
  sleep 1
  break
}
Stop-Transcript

#Defines the source script file
$DetectScript = @'
#Check if Notepad++ is installed and report accordingly

#Makes sure script is only run once per device
$HasReported = Test-Path -Path C:\NOTEPDVUL\hasReported.log
if ($HasReported -eq $true)
{
    exit
}

#Minor shell setup
$ProgressPreference = "SilentlyContinue"
$hostname = hostname

#Require script to be run as admin
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false)
{
  Clear-Host
  write-host "Please run as admin..."
  sleep 1
  break
}

#Create folder structure to be used
$FolderExist = Test-Path -Path C:\NOTEPDVUL
if ($FolderExist -ne $true)
{
    New-Item -ItemType "directory" -Path C:\NOTEPDVUL | Out-Null
    sleep 1
}

if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 1) {
    $HostVer = "Client"
} else {
    $HostVer = "Server"
}

$ShareHostname = "QZQZQPLACEHOLDERQZQZQ2"
$OutputFileReportYes = "\\$ShareHostname\NOTEPDVUL\Detected\$HostVer_" + "$hostname" + ".txt"
$OutputFileReportNo = "\\$ShareHostname\NOTEPDVUL\Not_Detected\$HostVer_" + "$hostname" + ".txt"

$NotepadPlusPlusPath64 = "C:\Program Files\Notepad++"
$NotepadPlusPlusPath32 = "C:\Program Files (x86)\Notepad++"

if ((Test-Path $NotepadPlusPlusPath64) -or (Test-Path $NotepadPlusPlusPath32)) {
    # Notepad++ is installed, get version
    $NppPath = if (Test-Path $NotepadPlusPlusPath64) { $NotepadPlusPlusPath64 } else { $NotepadPlusPlusPath32 }
    $NppExe = Join-Path $NppPath "notepad++.exe"
    
    if (Test-Path $NppExe) {
        $Version = (Get-Item $NppExe).VersionInfo.FileVersion
        "Notepad++ version $Version" | Out-File -FilePath $OutputFileReportYes -Append
    } else {
        "Notepad++ folder found but executable missing" | Out-File -FilePath $OutputFileReportYes -Append
    }
} else {
    "Notepad++ installation not detected" | Out-File -FilePath $OutputFileReportNo -Append
}
break
'@

 
#Create folder structure to be used
$NOTEPDVULFolderExist = Test-Path -Path C:\itm8\NOTEPDVUL
if ($NOTEPDVULFolderExist -ne $true)
{
    $itm8FolderExist = Test-Path -Path C:\itm8
    if ($itm8FolderExist -ne $true)
    {
        New-Item -ItemType "directory" -Path C:\itm8 -Erroraction Stop
        sleep 1
    }
    New-Item -ItemType "directory" -Path C:\itm8\NOTEPDVUL -Erroraction Stop
    sleep 1
}

#Shares the folder
sleep 1
New-SmbShare -Name "NOTEPDVUL" -Path "C:\itm8\NOTEPDVUL" -ReadAccess "Everyone" -Erroraction Stop
$hostname = hostname
$ShareLocalPath = "C:\itm8\NOTEPDVUL"
$DetectScript  | out-file "$ShareLocalPath\NOTEPDVUL.ps1"
#Replaces the placerholder sharepath in the active script
$PlaceholderToReplace2 = "QZQZQPLACEHOLDERQZQZQ2"
$ScriptPath = "$ShareLocalPath\NOTEPDVUL.ps1"
(Get-Content -path $ScriptPath -Raw) -replace $PlaceholderToReplace2,$hostname | Set-Content -Path $ScriptPath -Erroraction Stop
