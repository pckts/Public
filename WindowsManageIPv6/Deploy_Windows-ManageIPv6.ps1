$ErrorActionPreference= "SilentlyContinue"
﻿$ProgressPreference = "SilentlyContinue"
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false)
{
  Clear-Host
  write-host "Please run as admin..."
  sleep 1
  break
}

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

Function Windows-DisableIPv6
{
    #Removes installs of Windows-RestoreIPv6 to avoid conflicts
    $ConflictFolderExist = Test-Path -Path "C:\Windows-RestoreIPv6"
    $ConflictGPOExist = Get-GPO -All | Where-Object {$_.displayname -like "Windows-RestoreIPv6"}
    if ($ConflixtFolderExist -eq $true -or $null -ne $ConflictGPOExist)
    {
        Remove-Item -LiteralPath "C:\Windows-RestoreIPv6" -Force -Recurse
        Remove-GPO -Name "Windows-RestoreIPv6"
        Unregister-ScheduledTask -TaskName "Cleanup_Windows-RestoreIPv6" -Confirm:$false
    }
    
    #Create folder structure to be used
    $FolderExist = Test-Path -Path C:\Windows-DisableIPv6
    if ($FolderExist -ne $true)
    {
        New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6 | Out-Null
        sleep 1
    }
    else
    {
        clear-host
        write-host "The main script folder exists already"
        write-host "This folder will be deleted and recreated to ensure integrity"
        write-host ""
        sleep 1
        Remove-SmbShare -Name "Windows-DisableIPv6" -Force
        Remove-Item -LiteralPath "C:\Windows-DisableIPv6" -Force -Recurse
        New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6 | Out-Null
        clear-host
    }

    $ReportFolderExist = Test-Path -Path C:\Windows-DisableIPv6_Reports
    if ($FolderExist -ne $true)
    {
        New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6_Reports | Out-Null
        sleep 1
    }
    else
    {
        clear-host
        write-host "The Reports folder exists already"
        write-host "This folder will be deleted and recreated to ensure integrity"
        write-host ""
        sleep 1
        Remove-SmbShare -Name "Windows-DisableIPv6_Reports" -Force
        Remove-Item -LiteralPath "C:\Windows-DisableIPv6_Reports" -Force -Recurse
        New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6_Reports | Out-Null
        clear-host
    }

    #Shares the folder
    New-SmbShare -Name "Windows-DisableIPv6" -Path "C:\Windows-DisableIPv6" -ReadAccess "Everyone"
    New-SmbShare -Name "Windows-DisableIPv6_Reports" -Path "C:\Windows-DisableIPv6_Reports" -ChangeAccess "Everyone"
    $hostname = hostname
    $ShareRemotePath = "\\"+$hostname+"\Windows-DisableIPv6"
    $ShareLocalPath = "C:\Windows-DisableIPv6"

    #Downloads script and source files for GPO
    $URLSource = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cHM6Ly9naXRodWIuY29tL3Bja3RzL1dpbmRvd3MtTWFuYWdlSVB2Ni9yYXcvbWFpbi9Tb3VyY2VfV2luZG93cy1EaXNhYmxlSVB2Ni56aXA="))
    Invoke-WebRequest -Uri $URLSource -OutFile $ShareLocalPath\Source_Windows-DisableIPv6.zip

    Try
    {
        Expand-Archive -LiteralPath $ShareLocalPath\Source_Windows-DisableIPv6.zip -DestinationPath $ShareLocalPath
    }
    catch
    {
        cls
        write-host "The .zip file failed to extract, please verify that the .zip file is indeed present"
        write-host "If it is, it's most likely that the Powershell version is outdated and does not contain required functionality."
        write-host "Please download and install Windows Management Framework 5.1"
        write-host "You can not continue until this is installed."
        write-host ""
        pause
        break
    }


    #Replaces the placeholder in the XML for the scheduled cleanup task with runtime 2 weeks in the future
    $DatePlaceholderToReplace = "QQQQ-QQ-QQ"
    $DateThen = (Get-Date).AddDays(14)
    $FormattedDateThen = Get-Date $DateThen -Format "yyyy-MM-dd"
    $TaskXMLPath = "$ShareLocalPath\GPOSourceFilesDisable\Cleanup_Windows-DisableIPv6.xml"
    (Get-Content -path $TaskXMLPath -Raw) -replace $DatePlaceholderToReplace,$FormattedDateThen | Set-Content -Path $TaskXMLPath

    #Replaces the placeholder in the XML for the scheduled task, with the real hostname
    $PlaceholderToReplace = "QZQZQPLACEHOLDERQZQZQ"
    $XMLPath = "$ShareLocalPath\GPOSourceFilesDisable\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
    (Get-Content -path $XMLPath -Raw) -replace $PlaceholderToReplace,$hostname | Set-Content -Path $XMLPath

    #Replaces the placerholder sharepath in the active script
    $PlaceholderToReplace2 = "QZQZQPLACEHOLDERQZQZQ2"
    $ScriptPath = "$ShareLocalPath\Windows-DisableIPv6.ps1"
    (Get-Content -path $ScriptPath -Raw) -replace $PlaceholderToReplace2,$hostname | Set-Content -Path $ScriptPath

    #Replaces the generic domain in the MOF for the WMI filter, with the real domain
    $GenericDomainToReplace = "domain.local"
    $MOFPath = "$ShareLocalPath\GPOSourceFilesDisable\IPv6WMIFilter.mof"
    $RealDomain = [System.Net.NetworkInformation.IpGlobalProperties]::GetIPGlobalProperties().DomainName
    (Get-Content -path $MOFPath -Raw) -replace $GenericDomainToReplace,$RealDomain | Set-Content -Path $MOFPath

    #Imports the WMI filter
    mofcomp -N:root\Policy "$ShareLocalPath\GPOSourceFilesDisable\IPv6WMIFilter.mof"

    #Deploys the GPO, enforces it, and links it to any OU with inheritance disabled
    $GPOName = "Windows-DisableIPv6"
    $DoesGPOExist = Get-GPO -All | Where-Object {$_.displayname -like "Windows-DisableIPv6"}
    if ($null -ne $DoesGPOExist)
    {
        Remove-GPO -Name $GPOName
    }

    $Partition = Get-ADDomainController | Select-Object DefaultPartition
    $GPOSource = "C:\Windows-DisableIPv6\GPOSourceFilesDisable"
    import-gpo -BackupId B4BA155A-AB98-4943-9610-328DD1EA1C37 -TargetName $GPOName -path $GPOSource -CreateIfNeeded
    Get-GPO -Name $GPOName | New-GPLink -Target $Partition.DefaultPartition
    Set-GPLink -Name $GPOName -Enforced Yes -Target $Partition.DefaultPartition
    $DisabledInheritances = Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where-Object {$_.GPOInheritanceBlocked} | select-object Path 
    Foreach ($DisabledInheritance in $DisabledInheritances) 
    {
        New-GPLink -Name $GPOName -Target $DisabledInheritance.Path
        Set-GPLink -Name $GPOName -Enforced Yes -Target $DisabledInheritance.Path
    }

    #Links the WMI filter to the GPO
    $DomainDn = "DC=" + [String]::Join(",DC=", $RealDomain.Split("."))
    $SystemContainer = "CN=System," + $DomainDn
    $GPOContainer = "CN=Policies," + $SystemContainer
    $WMIFilterContainer = "CN=SOM,CN=WMIPolicy," + $SystemContainer
    $GPReportPath = "$ShareLocalPath\GPOSourceFilesDisable\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\gpreport.xml"
    [xml]$GPReport = get-content $GPReportPath
    $WMIFilterDisplayName = $GPReport.GPO.FilterName
    $GPOAttributes = Get-GPO $GPOName
    $WMIFilter = Get-ADObject -Filter 'msWMI-Name -eq $WMIFilterDisplayName'
    $GPODN = "CN={" + $GPOAttributes.Id + "}," + $GPOContainer
    $WMIFilterLinkValue = "[$RealDomain;" + $WMIFilter.Name + ";0]"
    Set-ADObject $GPODN -Add @{gPCWQLFilter=$WMIFilterLinkValue}

    #Creates cleanup task that will automatically remove the GPO in 2 weeks from date of implementation
    $taskExists = schtasks /Query /tn "Cleanup_Windows-DisableIPv6"
    if ($taskExists -eq $null)
    {
        schtasks /Create /XML "$ShareLocalPath\GPOSourceFilesDisable\Cleanup_Windows-DisableIPv6.xml" /tn "Cleanup_Windows-DisableIPv6"
    }

    #Cleans up
    Remove-Item -LiteralPath $ShareLocalPath\Source_Windows-DisableIPv6.zip -Force
    Remove-Item -LiteralPath $ShareLocalPath\GPOSourceFilesDisable -Force -Recurse

    clear-host
    write-host "The group policy 'Windows-DisableIPv6' has now been deployed"
    write-host ""
    write-host "It will automatically be deleted in 2 weeks to allow for re-use of IPv6."
    write-host "The 'Windows-DisableIPv6_Reports' folder will be kept intact"
    write-host ""
    write-host "Goodbye"
    write-host ""
    sleep 1
    break
}

Function Windows-RestoreIPv6
{
    #Removes installs of Windows-RestoreIPv6 to avoid conflicts
    $ConflictFolderExist = Test-Path -Path "C:\Windows-DisableIPv6"
    $ConflictGPOExist = Get-GPO -All | Where-Object {$_.displayname -like "Windows-DisableIPv6"}
    if ($ConflixtFolderExist -eq $true -or $null -ne $ConflictGPOExist)
    {
        Remove-Item -LiteralPath "C:\Windows-DisableIPv6" -Force -Recurse
        Remove-GPO -Name "Windows-DisableIPv6"
        Unregister-ScheduledTask -TaskName "Cleanup_Windows-DisableIPv6" -Confirm:$false
    }

    #Create folder structure to be used
    $FolderExist = Test-Path -Path C:\Windows-RestoreIPv6
    if ($FolderExist -ne $true)
    {
        New-Item -ItemType "directory" -Path C:\Windows-RestoreIPv6 | Out-Null
        sleep 1
    }
    else
    {
        clear-host
        write-host "The main script folder exists already"
        write-host "This folder will be deleted and recreated to ensure integrity"
        write-host ""
        sleep 1
        Remove-SmbShare -Name "Windows-RestoreIPv6" -Force
        Remove-Item -LiteralPath "C:\Windows-RestoreIPv6" -Force -Recurse
        New-Item -ItemType "directory" -Path C:\Windows-RestoreIPv6 | Out-Null
        clear-host
    }

    $ReportFolderExist = Test-Path -Path C:\Windows-RestoreIPv6_Reports
    if ($FolderExist -ne $true)
    {
        New-Item -ItemType "directory" -Path C:\Windows-RestoreIPv6_Reports | Out-Null
        sleep 1
    }
    else
    {
        clear-host
        write-host "The Reports folder exists already"
        write-host "This folder will be deleted and recreated to ensure integrity"
        write-host ""
        sleep 1
        Remove-SmbShare -Name "Windows-RestoreIPv6_Reports" -Force
        Remove-Item -LiteralPath "C:\Windows-RestoreIPv6_Reports" -Force -Recurse
        New-Item -ItemType "directory" -Path C:\Windows-RestoreIPv6_Reports | Out-Null
        clear-host
    }

    #Shares the folder
    New-SmbShare -Name "Windows-RestoreIPv6" -Path "C:\Windows-RestoreIPv6" -ReadAccess "Everyone"
    New-SmbShare -Name "Windows-RestoreIPv6_Reports" -Path "C:\Windows-RestoreIPv6_Reports" -ChangeAccess "Everyone"
    $hostname = hostname
    $ShareRemotePath = "\\"+$hostname+"\Windows-RestoreIPv6"
    $ShareLocalPath = "C:\Windows-RestoreIPv6"

    #Downloads script and source files for GPO
    $URLSource = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cHM6Ly9naXRodWIuY29tL3Bja3RzL1dpbmRvd3MtTWFuYWdlSVB2Ni9yYXcvbWFpbi9Tb3VyY2VfV2luZG93cy1SZXN0b3JlSVB2Ni56aXA="))
    Invoke-WebRequest -Uri $URLSource -OutFile $ShareLocalPath\Source_Windows-RestoreIPv6.zip

    Try
    {
        Expand-Archive -LiteralPath $ShareLocalPath\Source_Windows-RestoreIPv6.zip -DestinationPath $ShareLocalPath
    }
    catch
    {
        cls
        write-host "The .zip file failed to extract, please verify that the .zip file is indeed present"
        write-host "If it is, it's most likely that the Powershell version is outdated and does not contain required functionality."
        write-host "Please download and install Windows Management Framework 5.1"
        write-host "You can not continue until this is installed."
        write-host ""
        pause
        break
    }


    #Replaces the placeholder in the XML for the scheduled cleanup task with runtime 2 weeks in the future
    $DatePlaceholderToReplace = "QQQQ-QQ-QQ"
    $DateThen = (Get-Date).AddDays(56)
    $FormattedDateThen = Get-Date $DateThen -Format "yyyy-MM-dd"
    $TaskXMLPath = "$ShareLocalPath\GPOSourceFilesRestore\Cleanup_Windows-RestoreIPv6.xml"
    (Get-Content -path $TaskXMLPath -Raw) -replace $DatePlaceholderToReplace,$FormattedDateThen | Set-Content -Path $TaskXMLPath

    #Replaces the placeholder in the XML for the scheduled task, with the real hostname
    $PlaceholderToReplace = "QZQZQPLACEHOLDERQZQZQ"
    $XMLPath = "$ShareLocalPath\GPOSourceFilesRestore\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
    (Get-Content -path $XMLPath -Raw) -replace $PlaceholderToReplace,$hostname | Set-Content -Path $XMLPath

    #Replaces the placerholder sharepath in the active script
    $PlaceholderToReplace2 = "QZQZQPLACEHOLDERQZQZQ2"
    $ScriptPath = "$ShareLocalPath\Windows-RestoreIPv6.ps1"
    (Get-Content -path $ScriptPath -Raw) -replace $PlaceholderToReplace2,$hostname | Set-Content -Path $ScriptPath

    #Replaces the generic domain in the MOF for the WMI filter, with the real domain
    $GenericDomainToReplace = "domain.local"
    $MOFPath = "$ShareLocalPath\GPOSourceFilesRestore\IPv6WMIFilter.mof"
    $RealDomain = [System.Net.NetworkInformation.IpGlobalProperties]::GetIPGlobalProperties().DomainName
    (Get-Content -path $MOFPath -Raw) -replace $GenericDomainToReplace,$RealDomain | Set-Content -Path $MOFPath

    #Imports the WMI filter
    mofcomp -N:root\Policy "$ShareLocalPath\GPOSourceFilesRestore\IPv6WMIFilter.mof"

    #Deploys the GPO, enforces it, and links it to any OU with inheritance disabled
    $GPOName = "Windows-RestoreIPv6"
    $DoesGPOExist = Get-GPO -All | Where-Object {$_.displayname -like "Windows-RestoreIPv6"}
    if ($null -ne $DoesGPOExist)
    {
        Remove-GPO -Name $GPOName
    }

    $Partition = Get-ADDomainController | Select-Object DefaultPartition
    $GPOSource = "C:\Windows-RestoreIPv6\GPOSourceFilesRestore"
    import-gpo -BackupId B4BA155A-AB98-4943-9610-328DD1EA1C37 -TargetName $GPOName -path $GPOSource -CreateIfNeeded
    Get-GPO -Name $GPOName | New-GPLink -Target $Partition.DefaultPartition
    Set-GPLink -Name $GPOName -Enforced Yes -Target $Partition.DefaultPartition
    $DisabledInheritances = Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where-Object {$_.GPOInheritanceBlocked} | select-object Path 
    Foreach ($DisabledInheritance in $DisabledInheritances) 
    {
        New-GPLink -Name $GPOName -Target $DisabledInheritance.Path
        Set-GPLink -Name $GPOName -Enforced Yes -Target $DisabledInheritance.Path
    }

    #Links the WMI filter to the GPO
    $DomainDn = "DC=" + [String]::Join(",DC=", $RealDomain.Split("."))
    $SystemContainer = "CN=System," + $DomainDn
    $GPOContainer = "CN=Policies," + $SystemContainer
    $WMIFilterContainer = "CN=SOM,CN=WMIPolicy," + $SystemContainer
    $GPReportPath = "$ShareLocalPath\GPOSourceFilesRestore\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\gpreport.xml"
    [xml]$GPReport = get-content $GPReportPath
    $WMIFilterDisplayName = $GPReport.GPO.FilterName
    $GPOAttributes = Get-GPO $GPOName
    $WMIFilter = Get-ADObject -Filter 'msWMI-Name -eq $WMIFilterDisplayName'
    $GPODN = "CN={" + $GPOAttributes.Id + "}," + $GPOContainer
    $WMIFilterLinkValue = "[$RealDomain;" + $WMIFilter.Name + ";0]"
    Set-ADObject $GPODN -Add @{gPCWQLFilter=$WMIFilterLinkValue}

    #Creates cleanup task that will automatically remove the GPO in 2 weeks from date of implementation
    $taskExists = schtasks /Query /tn "Cleanup_Windows-RestoreIPv6"
    if ($taskExists -eq $null)
    {
        schtasks /Create /XML "$ShareLocalPath\GPOSourceFilesRestore\Cleanup_Windows-RestoreIPv6.xml" /tn "Cleanup_Windows-RestoreIPv6"
    }

    #Cleans up
    Remove-Item -LiteralPath $ShareLocalPath\Source_Windows-RestoreIPv6.zip -Force
    Remove-Item -LiteralPath $ShareLocalPath\GPOSourceFilesRestore -Force -Recurse

    clear-host
    write-host "The group policy 'Windows-RestoreIPv6' has now been deployed"
    write-host ""
    write-host "It will automatically be deleted in 8 weeks to minimise group policy clutter"
    write-host "The 'Windows-RestoreIPv6_Reports' folder will be kept intact"
    write-host ""
    write-host "Goodbye"
    write-host ""
    sleep 1
    break
}

Function Windows-HousekeepingIPv6
{
    Remove-SmbShare -Name "Windows-DisableIPv6" -Force
    Remove-SmbShare -Name "Windows-RestoreIPv6" -Force
    Remove-SmbShare -Name "Windows-DisableIPv6_Reports" -Force
    Remove-SmbShare -Name "Windows-RestoreIPv6_Reports" -Force
    Remove-Item -LiteralPath "C:\Windows-DisableIPv6" -Force -Recurse
    Remove-Item -LiteralPath "C:\Windows-RestoreIPv6" -Force -Recurse
    Remove-Item -LiteralPath "C:\Windows-DisableIPv6_Reports" -Force -Recurse
    Remove-Item -LiteralPath "C:\Windows-RestoreIPv6_Reports" -Force -Recurse
    Remove-GPO -Name "Windows-DisableIPv6"
    Remove-GPO -Name "Windows-RestoreIPv6"
    Unregister-ScheduledTask -TaskName "Cleanup_Windows-DisableIPv6" -Confirm:$false
    Unregister-ScheduledTask -TaskName "Cleanup_Windows-RestoreIPv6" -Confirm:$false
    clear-host
    write-host "All parts of both Windows-DisableIPv6 and Windows-RestoreIPv6 is now removed from this environment"
    write-host ""
    write-host "Goodbye"
    write-host ""
    sleep 1
    break
}

$FunctionMenu = 
{
    sleep 1
    cls
    write-host ""
    write-host "                                        " -BackGroundColor Black -NoNewLine; write-host "Windows-ManageIPv6" -ForeGroundColor Red -BackGroundColor Black -NoNewLine; write-host "                                         " -BackGroundColor Black
    write-host "                                                                                                   " -BackGroundColor Black
    write-host "+---FUNCTIONS----------------+" -BackGroundColor Black -NoNewLine; write-host "---INFO-------------------------------------------------------------+" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|" -BackGroundColor Black -NoNewLine; write-host "Option 1." -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "                  |" -BackGroundColor Black -NoNewLine; write-host " This will disable IPv6 on all interfaces on all domain devices      |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|" -BackGroundColor Black -NoNewLine; write-host "Deploy Windows-DisableIPv6" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host " |" -BackGroundColor Black -NoNewLine; write-host " (Domain Controllers and Exchange servers are automatically excempt) |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|---------------------------|" -BackGroundColor Black -NoNewLine; write-host "---------------------------------------------------------------------|" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|" -BackGroundColor Black -NoNewLine; write-host "Option 2." -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "                  |" -BackGroundColor Black -NoNewLine; write-host " This will restore the original IPv6 setup on all domain devices     |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|" -BackGroundColor Black -NoNewLine; write-host "Deploy Windows-RestoreIPv6" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host " |" -BackGroundColor Black -NoNewLine; write-host " (This will have no effect if Windows-DisableIPv6 was never used)    |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "+---------------------------+" -BackGroundColor Black -NoNewLine; write-host "---------------------------------------------------------------------+" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|" -BackGroundColor Black -NoNewLine; write-host "Option 3." -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "                  |" -BackGroundColor Black -NoNewLine; write-host " This will ensure that all traces of either function will be fully   |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|" -BackGroundColor Black -NoNewLine; write-host "Ensure both are removed" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "    |" -BackGroundColor Black -NoNewLine; write-host " removed from the environment (Local device files are unaffected)    |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "+---------------------------+" -BackGroundColor Black -NoNewLine; write-host "---------------------------------------------------------------------+" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host ""
    $SelectedFunction = read-host "Select function (1/2/3)"
    

    if ($SelectedFunction -ne "1" -and $SelectedFunction -ne "2" -and $SelectedFunction -ne "3")
    {
        &@FunctionMenu
    }

    if ($SelectedFunction -eq "1")
    {
        Windows-DisableIPv6
    }

    if ($SelectedFunction -eq "2")
    {
        Windows-RestoreIPv6
    }

    if ($SelectedFunction -eq "3")
    {
        Windows-HousekeepingIPv6
    }
}
&@FunctionMenu
$FunctionMenuexit
