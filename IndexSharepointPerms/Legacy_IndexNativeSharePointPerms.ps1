


#THIS CODE IS PSEUDO AND IS SOLELY FOR REFERENCE PURPOSES






#Required values set by operator before executing script
$tenantName = "PUT_TENANT_SP_NAME_HERE"
$AdminUser = "PUT_ADMIN_USERNAME_HERE"

#-----------------------------------------------------------

#Minor shell setup
$ProgressPreference = "SilentlyContinue"
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

#Create folder structure to be used
$FolderPath = $HOME+"\IndexNativeSharepointPerms\"+$tenantName
$FolderExist = Test-Path -Path $FolderPath
if ($FolderExist -ne $true)
{
    New-Item -ItemType "directory" -Path $FolderPath | Out-Null
    sleep 1
}

#Connects to SharePoint Online
$SPOAdminURL = "https://"+$tenantName+"-admin.sharepoint.com"
Connect-SPOService -Url $SPOAdminURL

#Indexes all SharePoint Online sites
$AllSites = Get-SPOSite -Limit All
foreach ($AllSite in $Allsites)
{
    #Each site gets put into a corresponding CSV file detailing which groups and users have any level of permission on the site root
    $SiteURL = $AllSite.Url
    $SiteName = ($SiteURL -split '/')[ -1 ]
    Set-SPOUser -Site $SiteURL -LoginName $AdminUser -IsSiteCollectionAdmin $true
    Get-SPOSite -Identity $SiteURL | ForEach {Get-SPOUser -Site $_.Url} | Select-Object  DisplayName,LoginName,IsSiteAdmin,IsGroup,Groups | Export-CSV -Path $FolderPath\$SiteName.csv -Encoding utf8 -NoTypeInformation
}
