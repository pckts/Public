

# PLEASE SEE README.TXT

Clear-Host

write-host "Example tenant name: contoso"
write-host "Present in the URL: https://contoso.sharepoint.com/"
write-host ""
$tenantName = read-host "Please input the tenant name"

#Verifies that the script is being run as admin
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false)
{
  Clear-Host
  write-host "Please run as admin..."
  sleep 1
  break
}

# Set minor shell options
$ProgressPreference = "SilentlyContinue"
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# installs the required module
Install-Module -Name "PnP.PowerShell" -AllowClobber -Force
try
{
    Import-module -name "PnP.PowerShell" -ErrorAction Stop
}
catch
{
    clear-host
    write-host "You have to install Powershell 7.2 to use this script." -ForegroundColor Red
}

# Define the SharePoint Permissions folder path and create if it doesn't exist
$SPPermsFolderPath = "$HOME\SharepointPerms\$tenantName"
if (-not (Test-Path -Path $SPPermsFolderPath)) {
    New-Item -ItemType "directory" -Path $SPPermsFolderPath | Out-Null
}

$DevLogOutput = "$SPPermsFolderPath\IndexSPPermsScript.log"
Start-Transcript -Path $DevLogOutput -Append

$TenantAdminUrl = "https://$tenantName-admin.sharepoint.com"

#Register Entra ID App
Register-PnPEntraIDAppForInteractiveLogin -ApplicationName "PnP Powershell" -Tenant "$tenantName.onmicrosoft.com" -Interactive

write-host ""
Write-host "Please copy the above Client ID"
$ClientID = Read-host "and paste it here"

# Authenticate to the SharePoint Admin Center
$AdminConnection = Connect-PnPOnline -Url $TenantAdminUrl -Interactive -ClientId $ClientID -ReturnConnection

# Get all sites in the tenant
$sites = Get-PnPTenantSite -IncludeOneDriveSites:$false -Filter "Url -like 'https://$tenantName.sharepoint.com/sites/'"

# Loop through each site to gather and export permissions
foreach ($site in $sites) {
    $siteName = ($site.Url -split "/")[-1]  # Get the site name from the URL
    $siteFolder = "$SPPermsFolderPath\$siteName"

    # Create a folder for each site
    if (-not (Test-Path -Path $siteFolder)) {
        New-Item -ItemType "directory" -Path $siteFolder | Out-Null
    }

    $SiteConnection = Connect-PnPOnline -Url $site.Url -Interactive -ClientId $ClientID -ReturnConnection

    # Export Site members
    $rootSitePerms = Get-PnPUser -Connection $SiteConnection | ForEach-Object {
        $user = $_
        $UserUPN = $user.LoginName -replace "^i:0#\.f\|membership\|", ""
        [PSCustomObject]@{
            Name = $user.Title
            UPN = $UserUPN 
            Type = $user.PrincipalType
        }
    }
    $rootSitePerms | Export-Csv -Path "$siteFolder\RootSitePerms.csv" -NoTypeInformation -Encoding UTF8
}

Disconnect-PnPOnline
Stop-Transcript