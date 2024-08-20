$DevLogOutput = "$home\VerboseDevLog_Windows-ManageIPv6.log"
Start-Transcript -Path $DevLogOutput -Append

$ProgressPreference = "SilentlyContinue"
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
Stop-Transcript

Function Windows-DisableIPv6
{
    Start-Transcript -Path $DevLogOutput -Append

    #Removes installs of Windows-RestoreIPv6 to avoid conflicts
    $ConflictFolderExist = Test-Path -Path "C:\Windows-RestoreIPv6"
    $ConflictGPOExist = Get-GPO -All | Where-Object {$_.displayname -like "Windows-RestoreIPv6"}
    if ($ConflixtFolderExist -eq $true -or $null -ne $ConflictGPOExist)
    {
        Remove-Item -LiteralPath "C:\Windows-RestoreIPv6" -Force -Recurse -Erroraction SilentlyContinue
        Remove-GPO -Name "Windows-RestoreIPv6" -Erroraction SilentlyContinue
        Unregister-ScheduledTask -TaskName "Cleanup_Windows-RestoreIPv6" -Confirm:$false -Erroraction SilentlyContinue
    }
    
    #Create folder structure to be used
    $FolderExist = Test-Path -Path C:\Windows-DisableIPv6
    if ($FolderExist -ne $true)
    {
        New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6 -Erroraction Stop
        sleep 1
    }
    else
    {
        clear-host
        write-host "The main script folder exists already"
        write-host "This folder will be deleted and recreated to ensure integrity"
        write-host ""
        sleep 1
        Remove-SmbShare -Name "Windows-DisableIPv6" -Force -Erroraction SilentlyContinue
        Remove-Item -LiteralPath "C:\Windows-DisableIPv6" -Force -Recurse -Erroraction SilentlyContinue
        New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6 -Erroraction Stop
        clear-host
    }

    $ReportFolderExist = Test-Path -Path C:\Windows-DisableIPv6_Reports
    if ($FolderExist -ne $true)
    {
        New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6_Reports -Erroraction Stop
        sleep 1
    }
    else
    {
        clear-host
        write-host "The Reports folder exists already"
        write-host "This folder will be deleted and recreated to ensure integrity"
        write-host ""
        sleep 1
        Remove-SmbShare -Name "Windows-DisableIPv6_Reports" -Force -Erroraction SilentlyContinue
        Copy-Item -Path "C:\Windows-DisableIPv6_Reports" -Destination "C:\Windows-DisableIPv6_Reports2" -Recurse
        Remove-Item -LiteralPath "C:\Windows-DisableIPv6_Reports" -Force -Recurse -Erroraction SilentlyContinue
        New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6_Reports -Erroraction Stop
        Copy-Item -Path "C:\Windows-DisableIPv6_Reports2\*" -Destination "C:\Windows-DisableIPv6_Reports" -Recurse -Erroraction SilentlyContinue
        Remove-Item -LiteralPath "C:\Windows-DisableIPv6_Reports2" -Force -Recurse -Erroraction SilentlyContinue
        clear-host
    }

    #Shares the folder
    New-SmbShare -Name "Windows-DisableIPv6" -Path "C:\Windows-DisableIPv6" -ReadAccess "Everyone" -Erroraction Stop
    New-SmbShare -Name "Windows-DisableIPv6_Reports" -Path "C:\Windows-DisableIPv6_Reports" -ChangeAccess "Everyone" -Erroraction Stop
    $hostname = hostname
    $ShareRemotePath = "\\"+$hostname+"\Windows-DisableIPv6"
    $ShareLocalPath = "C:\Windows-DisableIPv6"

    #Downloads script and source files for GPO
    $URLSource = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cHM6Ly9naXRodWIuY29tL3Bja3RzL1dpbmRvd3MtTWFuYWdlSVB2Ni9yYXcvbWFpbi9Tb3VyY2VfV2luZG93cy1EaXNhYmxlSVB2Ni56aXA="))
    Invoke-WebRequest -Uri $URLSource -OutFile $ShareLocalPath\Source_Windows-DisableIPv6.zip -Erroraction Stop

    Expand-Archive -LiteralPath $ShareLocalPath\Source_Windows-DisableIPv6.zip -DestinationPath $ShareLocalPath -Erroraction Stop

    #Replaces the placeholder in the XML for the scheduled cleanup task with runtime 2 weeks in the future
    $DatePlaceholderToReplace = "QQQQ-QQ-QQ"
    $DateThen = (Get-Date).AddDays(14)
    $FormattedDateThen = Get-Date $DateThen -Format "yyyy-MM-dd"
    $TaskXMLPath = "$ShareLocalPath\GPOSourceFilesDisable\Cleanup_Windows-DisableIPv6.xml"
    (Get-Content -path $TaskXMLPath -Raw) -replace $DatePlaceholderToReplace,$FormattedDateThen | Set-Content -Path $TaskXMLPath -Erroraction Stop

    #Replaces the placeholder in the XML for the scheduled task, with the real hostname
    $PlaceholderToReplace = "QZQZQPLACEHOLDERQZQZQ"
    $XMLPath = "$ShareLocalPath\GPOSourceFilesDisable\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
    (Get-Content -path $XMLPath -Raw) -replace $PlaceholderToReplace,$hostname | Set-Content -Path $XMLPath -Erroraction Stop

    #Replaces the placerholder sharepath in the active script
    $PlaceholderToReplace2 = "QZQZQPLACEHOLDERQZQZQ2"
    $ScriptPath = "$ShareLocalPath\Windows-DisableIPv6.ps1"
    (Get-Content -path $ScriptPath -Raw) -replace $PlaceholderToReplace2,$hostname | Set-Content -Path $ScriptPath -Erroraction Stop

    #Replaces the generic domain in the MOF for the WMI filter, with the real domain
    $GenericDomainToReplace = "domain.local"
    $MOFPath = "$ShareLocalPath\GPOSourceFilesDisable\IPv6WMIFilter.mof"
    $RealDomain = [System.Net.NetworkInformation.IpGlobalProperties]::GetIPGlobalProperties().DomainName
    (Get-Content -path $MOFPath -Raw) -replace $GenericDomainToReplace,$RealDomain | Set-Content -Path $MOFPath -Erroraction Stop

    #Imports the WMI filter
    mofcomp -N:root\Policy "$ShareLocalPath\GPOSourceFilesDisable\IPv6WMIFilter.mof"

    #Deploys the GPO, enforces it, and links it to any OU with inheritance disabled
    $GPOName = "Windows-DisableIPv6"
    $DoesGPOExist = Get-GPO -All | Where-Object {$_.displayname -like "Windows-DisableIPv6"}
    if ($null -ne $DoesGPOExist)
    {
        Remove-GPO -Name $GPOName -Erroraction SilentlyContinue
    }

    $Partition = Get-ADDomainController | Select-Object DefaultPartition
    $GPOSource = "C:\Windows-DisableIPv6\GPOSourceFilesDisable"
    import-gpo -BackupId B4BA155A-AB98-4943-9610-328DD1EA1C37 -TargetName $GPOName -path $GPOSource -CreateIfNeeded -Erroraction Stop
    Get-GPO -Name $GPOName | New-GPLink -Target $Partition.DefaultPartition -Erroraction Stop
    Set-GPLink -Name $GPOName -Enforced Yes -Target $Partition.DefaultPartition -Erroraction Stop
    $DisabledInheritances = Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where-Object {$_.GPOInheritanceBlocked} | select-object Path 
    Foreach ($DisabledInheritance in $DisabledInheritances) 
    {
        New-GPLink -Name $GPOName -Target $DisabledInheritance.Path -Erroraction SilentlyContinue
        Set-GPLink -Name $GPOName -Enforced Yes -Target $DisabledInheritance.Path -Erroraction SilentlyContinue
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
    Set-ADObject $GPODN -Add @{gPCWQLFilter=$WMIFilterLinkValue} -Erroraction Stop

    #Verifies that the WMI filter was actually applied to the GPO
    if ($null -eq $GPOAttributes.WmiFilter.Name)
    {
        throw "The WMI Filter was not properly applied to the Group Policy Object"
    }

    #Creates cleanup task that will automatically remove the GPO in 2 weeks from date of implementation
    $taskExists = $taskExists = Get-ScheduledTask -TaskName "Cleanup_Windows-DisableIPv6" -ErrorAction SilentlyContinue
    if ($taskExists -eq $null)
    {
        Register-ScheduledTask -TaskName "Cleanup_Windows-DisableIPv6" -Xml (Get-Content "$ShareLocalPath\GPOSourceFilesDisable\Cleanup_Windows-DisableIPv6.xml" | Out-String) -Force -Erroraction Stop
    }

    #Cleans up
    Remove-Item -LiteralPath $ShareLocalPath\Source_Windows-DisableIPv6.zip -Force -Erroraction SilentlyContinue
    Remove-Item -LiteralPath $ShareLocalPath\GPOSourceFilesDisable -Force -Recurse -Erroraction SilentlyContinue
    Stop-Transcript
    $psISE.CurrentFile.SaveAS("$home\Temp_Windows-ManageIPv6")
    Remove-Item -LiteralPath "$home\Temp_Windows-ManageIPv6" -Force -Recurse -Erroraction SilentlyContinue
    sleep 1
    clear-host
    write-host "The group policy 'Windows-DisableIPv6' has now been deployed"
    write-host ""
    write-host "It will automatically be deleted in 2 weeks to allow for re-use of IPv6."
    write-host "The 'Windows-DisableIPv6_Reports' folder will be kept intact"
    write-host ""
    write-host ""
    write-host "Developer Log: $DevLogOutput" -ForegroundColor DarkGray
    write-host ""
    write-host ""
    write-host "This ISE will forcefully close itself in 10 seconds"
    write-host ""
    sleep 10
    exit
}

Function Windows-RestoreIPv6
{
    Start-Transcript -Path $DevLogOutput -Append

    #Removes installs of Windows-RestoreIPv6 to avoid conflicts
    $ConflictFolderExist = Test-Path -Path "C:\Windows-DisableIPv6"
    $ConflictGPOExist = Get-GPO -All | Where-Object {$_.displayname -like "Windows-DisableIPv6"}
    if ($ConflixtFolderExist -eq $true -or $null -ne $ConflictGPOExist)
    {
        Remove-Item -LiteralPath "C:\Windows-DisableIPv6" -Force -Recurse -Erroraction SilentlyContinue
        Remove-GPO -Name "Windows-DisableIPv6" -Erroraction SilentlyContinue
        Unregister-ScheduledTask -TaskName "Cleanup_Windows-DisableIPv6" -Confirm:$false -Erroraction SilentlyContinue
    }

    #Create folder structure to be used
    $FolderExist = Test-Path -Path C:\Windows-RestoreIPv6
    if ($FolderExist -ne $true)
    {
        New-Item -ItemType "directory" -Path C:\Windows-RestoreIPv6 -Erroraction Stop
        sleep 1
    }
    else
    {
        clear-host
        write-host "The main script folder exists already"
        write-host "This folder will be deleted and recreated to ensure integrity"
        write-host ""
        sleep 1
        Remove-SmbShare -Name "Windows-RestoreIPv6_Reports" -Force -Erroraction SilentlyContinue
        Copy-Item -Path "C:\Windows-RestoreIPv6_Reports" -Destination "C:\Windows-RestoreIPv6_Reports2" -Recurse
        Remove-Item -LiteralPath "C:\Windows-RestoreIPv6_Reports" -Force -Recurse -Erroraction SilentlyContinue
        New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6_Reports -Erroraction Stop
        Copy-Item -Path "C:\Windows-RestoreIPv6_Reports2\*" -Destination "C:\Windows-RestoreIPv6_Reports" -Recurse -Erroraction SilentlyContinue
        Remove-Item -LiteralPath "C:\Windows-RestoreIPv6_Reports2" -Force -Recurse -Erroraction SilentlyContinue
        clear-host
    }

    $ReportFolderExist = Test-Path -Path C:\Windows-RestoreIPv6_Reports
    if ($FolderExist -ne $true)
    {
        New-Item -ItemType "directory" -Path C:\Windows-RestoreIPv6_Reports -Erroraction Stop
        sleep 1
    }
    else
    {
        clear-host
        write-host "The Reports folder exists already"
        write-host "This folder will be deleted and recreated to ensure integrity"
        write-host ""
        sleep 1
        Remove-SmbShare -Name "Windows-RestoreIPv6_Reports" -Force -Erroraction SilentlyContinue
        Remove-Item -LiteralPath "C:\Windows-RestoreIPv6_Reports" -Force -Recurse -Erroraction SilentlyContinue
        New-Item -ItemType "directory" -Path C:\Windows-RestoreIPv6_Reports -Erroraction Stop
        clear-host
    }

    #Shares the folder
    New-SmbShare -Name "Windows-RestoreIPv6" -Path "C:\Windows-RestoreIPv6" -ReadAccess "Everyone" -ErrorAction Stop
    New-SmbShare -Name "Windows-RestoreIPv6_Reports" -Path "C:\Windows-RestoreIPv6_Reports" -ChangeAccess "Everyone" -Erroraction Stop
    $hostname = hostname
    $ShareRemotePath = "\\"+$hostname+"\Windows-RestoreIPv6"
    $ShareLocalPath = "C:\Windows-RestoreIPv6"

    #Downloads script and source files for GPO
    $URLSource = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cHM6Ly9naXRodWIuY29tL3Bja3RzL1dpbmRvd3MtTWFuYWdlSVB2Ni9yYXcvbWFpbi9Tb3VyY2VfV2luZG93cy1SZXN0b3JlSVB2Ni56aXA="))
    Invoke-WebRequest -Uri $URLSource -OutFile $ShareLocalPath\Source_Windows-RestoreIPv6.zip -ErrorAction Stop

    Expand-Archive -LiteralPath $ShareLocalPath\Source_Windows-RestoreIPv6.zip -DestinationPath $ShareLocalPath -Erroraction Stop

    #Replaces the placeholder in the XML for the scheduled cleanup task with runtime 2 weeks in the future
    $DatePlaceholderToReplace = "QQQQ-QQ-QQ"
    $DateThen = (Get-Date).AddDays(56)
    $FormattedDateThen = Get-Date $DateThen -Format "yyyy-MM-dd"
    $TaskXMLPath = "$ShareLocalPath\GPOSourceFilesRestore\Cleanup_Windows-RestoreIPv6.xml"
    (Get-Content -path $TaskXMLPath -Raw) -replace $DatePlaceholderToReplace,$FormattedDateThen | Set-Content -Path $TaskXMLPath -Erroraction Stop

    #Replaces the placeholder in the XML for the scheduled task, with the real hostname
    $PlaceholderToReplace = "QZQZQPLACEHOLDERQZQZQ"
    $XMLPath = "$ShareLocalPath\GPOSourceFilesRestore\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
    (Get-Content -path $XMLPath -Raw) -replace $PlaceholderToReplace,$hostname | Set-Content -Path $XMLPath -Erroraction Stop

    #Replaces the placerholder sharepath in the active script
    $PlaceholderToReplace2 = "QZQZQPLACEHOLDERQZQZQ2"
    $ScriptPath = "$ShareLocalPath\Windows-RestoreIPv6.ps1"
    (Get-Content -path $ScriptPath -Raw) -replace $PlaceholderToReplace2,$hostname | Set-Content -Path $ScriptPath -Erroraction Stop

    #Replaces the generic domain in the MOF for the WMI filter, with the real domain
    $GenericDomainToReplace = "domain.local"
    $MOFPath = "$ShareLocalPath\GPOSourceFilesRestore\IPv6WMIFilter.mof"
    $RealDomain = [System.Net.NetworkInformation.IpGlobalProperties]::GetIPGlobalProperties().DomainName
    (Get-Content -path $MOFPath -Raw) -replace $GenericDomainToReplace,$RealDomain | Set-Content -Path $MOFPath -Erroraction Stop

    #Imports the WMI filter
    mofcomp -N:root\Policy "$ShareLocalPath\GPOSourceFilesRestore\IPv6WMIFilter.mof" -Erroraction Stop

    #Deploys the GPO, enforces it, and links it to any OU with inheritance disabled
    $GPOName = "Windows-RestoreIPv6"
    $DoesGPOExist = Get-GPO -All | Where-Object {$_.displayname -like "Windows-RestoreIPv6"}
    if ($null -ne $DoesGPOExist)
    {
        Remove-GPO -Name $GPOName -Erroraction SilentlyContinue
    }

    $Partition = Get-ADDomainController | Select-Object DefaultPartition
    $GPOSource = "C:\Windows-RestoreIPv6\GPOSourceFilesRestore"
    import-gpo -BackupId B4BA155A-AB98-4943-9610-328DD1EA1C37 -TargetName $GPOName -path $GPOSource -CreateIfNeeded -Erroraction Stop
    Get-GPO -Name $GPOName | New-GPLink -Target $Partition.DefaultPartition -Erroraction Stop
    Set-GPLink -Name $GPOName -Enforced Yes -Target $Partition.DefaultPartition -Erroraction Stop
    $DisabledInheritances = Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where-Object {$_.GPOInheritanceBlocked} | select-object Path 
    Foreach ($DisabledInheritance in $DisabledInheritances) 
    {
        New-GPLink -Name $GPOName -Target $DisabledInheritance.Path -Erroraction SilentlyContinue
        Set-GPLink -Name $GPOName -Enforced Yes -Target $DisabledInheritance.Path -Erroraction SilentlyContinue
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
    Set-ADObject $GPODN -Add @{gPCWQLFilter=$WMIFilterLinkValue} -Erroraction Stop

    #Verifies that the WMI filter was actually applied to the GPO
    if ($null -eq $GPOAttributes.WmiFilter.Name)
    {
        throw "The WMI Filter was not properly applied to the Group Policy Object"
    }

    #Creates cleanup task that will automatically remove the GPO in 2 weeks from date of implementation
    $taskExists = Get-ScheduledTask -TaskName "Cleanup_Windows-RestoreIPv6" -Erroraction SilentlyContinue
    if ($taskExists -eq $null)
    {
        Register-ScheduledTask -TaskName "Cleanup_Windows-RestoreIPv6" -Xml (Get-Content "$ShareLocalPath\GPOSourceFilesRestore\Cleanup_Windows-RestoreIPv6.xml" | Out-String) -Force -Erroraction Stop
    }

    #Cleans up
    Remove-Item -LiteralPath $ShareLocalPath\Source_Windows-RestoreIPv6.zip -Force -Erroraction SilentlyContinue
    Remove-Item -LiteralPath $ShareLocalPath\GPOSourceFilesRestore -Force -Recurse -Erroraction SilentlyContinue
    Stop-Transcript
    $psISE.CurrentFile.SaveAS("$home\Temp_Windows-ManageIPv6")
    Remove-Item -LiteralPath "$home\Temp_Windows-ManageIPv6" -Force -Recurse -Erroraction SilentlyContinue
    sleep 1
    clear-host
    write-host "The group policy 'Windows-RestoreIPv6' has now been deployed"
    write-host ""
    write-host "It will automatically be deleted in 8 weeks to minimise group policy clutter"
    write-host "The 'Windows-RestoreIPv6_Reports' folder will be kept intact then"
    write-host ""
    write-host ""
    write-host "Developer Log: $DevLogOutput" -ForegroundColor DarkGray
    write-host ""
    write-host ""
    write-host "This ISE will forcefully close itself in 10 seconds"
    write-host ""
    sleep 10
    exit
}

Function Windows-HousekeepingIPv6
{
    Start-Transcript -Path $DevLogOutput -Append
    Remove-SmbShare -Name "Windows-DisableIPv6" -Force -Erroraction SilentlyContinue
    Remove-SmbShare -Name "Windows-RestoreIPv6" -Force -Erroraction SilentlyContinue
    Remove-SmbShare -Name "Windows-DisableIPv6_Reports" -Force -Erroraction SilentlyContinue
    Remove-SmbShare -Name "Windows-RestoreIPv6_Reports" -Force -Erroraction SilentlyContinue
    Remove-Item -LiteralPath "C:\Windows-DisableIPv6" -Force -Recurse -Erroraction SilentlyContinue
    Remove-Item -LiteralPath "C:\Windows-RestoreIPv6" -Force -Recurse -Erroraction SilentlyContinue
    Remove-Item -LiteralPath "C:\Windows-DisableIPv6_Reports" -Force -Recurse -Erroraction SilentlyContinue
    Remove-Item -LiteralPath "C:\Windows-RestoreIPv6_Reports" -Force -Recurse -Erroraction SilentlyContinue
    Remove-GPO -Name "Windows-DisableIPv6" -Erroraction SilentlyContinue
    Remove-GPO -Name "Windows-RestoreIPv6" -Erroraction SilentlyContinue
    Unregister-ScheduledTask -TaskName "Cleanup_Windows-DisableIPv6" -Confirm:$false -Erroraction SilentlyContinue
    Unregister-ScheduledTask -TaskName "Cleanup_Windows-RestoreIPv6" -Confirm:$false -Erroraction SilentlyContinue
    Stop-Transcript
    $psISE.CurrentFile.SaveAS("$home\Temp_Windows-ManageIPv6")
    Remove-Item -LiteralPath "$home\Temp_Windows-ManageIPv6" -Force -Recurse -Erroraction SilentlyContinue
    sleep 1
    clear-host
    write-host "All parts of both Windows-DisableIPv6 and Windows-RestoreIPv6 have been removed from this environment"
    write-host ""
    write-host ""
    write-host "Developer Log: $DevLogOutput" -ForegroundColor DarkGray
    write-host ""
    write-host ""
    write-host "This ISE will forcefully close itself in 10 seconds"
    write-host ""
    sleep 10
    exit
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
        try 
        {
            Windows-DisableIPv6
        }
        catch 
        {
            Stop-Transcript
            Remove-SmbShare -Name "Windows-DisableIPv6" -Force -Erroraction SilentlyContinue
            Remove-SmbShare -Name "Windows-RestoreIPv6" -Force -Erroraction SilentlyContinue
            Remove-SmbShare -Name "Windows-DisableIPv6_Reports" -Force -Erroraction SilentlyContinue
            Remove-SmbShare -Name "Windows-RestoreIPv6_Reports" -Force -Erroraction SilentlyContinue
            Remove-Item -LiteralPath "C:\Windows-DisableIPv6" -Force -Recurse -Erroraction SilentlyContinue
            Remove-Item -LiteralPath "C:\Windows-RestoreIPv6" -Force -Recurse -Erroraction SilentlyContinue
            Remove-Item -LiteralPath "C:\Windows-DisableIPv6_Reports" -Force -Recurse -Erroraction SilentlyContinue
            Remove-Item -LiteralPath "C:\Windows-RestoreIPv6_Reports" -Force -Recurse -Erroraction SilentlyContinue
            Remove-GPO -Name "Windows-DisableIPv6" -Erroraction SilentlyContinue
            Remove-GPO -Name "Windows-RestoreIPv6" -Erroraction SilentlyContinue
            Unregister-ScheduledTask -TaskName "Cleanup_Windows-DisableIPv6" -Confirm:$false -Erroraction SilentlyContinue
            Unregister-ScheduledTask -TaskName "Cleanup_Windows-RestoreIPv6" -Confirm:$false -Erroraction SilentlyContinue
            clear-host
            sleep 1
            write-host ""
            write-host "                                                                                            " -BackGroundColor Black
            write-host " ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! " -ForeGroundColor DarkRed -BackGroundColor Black
            write-host "                                                                                            " -BackGroundColor Black
            write-host "                  An error was detected while running the online installer                  " -ForeGroundColor Yellow -BackGroundColor Black
            write-host "         The installer was not able to self-remediate the error and was terminated          " -ForeGroundColor Yellow -BackGroundColor Black
            write-host "                            Any changes made have been reverted                             " -ForeGroundColor Yellow -BackGroundColor Black
            write-host "                                                                                            " -BackGroundColor Black
            write-host "       You may need to use the offline installer if the target system is unsupported        " -ForeGroundColor Yellow -BackGroundColor Black
            write-host "                 Please forward the below error message to the developer                    " -ForeGroundColor Yellow -BackGroundColor Black
            write-host "                                                                                            " -BackGroundColor Black
            write-host ""
            write-host $_.Exception.Message -ForeGroundColor Red -BackGroundColor Black
            write-host ""
        }
        break
    }

    if ($SelectedFunction -eq "2")
    {
        try 
        {
            Windows-RestoreIPv6
        }
        catch 
        {
            Stop-Transcript
            Remove-SmbShare -Name "Windows-DisableIPv6" -Force -Erroraction SilentlyContinue
            Remove-SmbShare -Name "Windows-RestoreIPv6" -Force -Erroraction SilentlyContinue
            Remove-SmbShare -Name "Windows-DisableIPv6_Reports" -Force -Erroraction SilentlyContinue
            Remove-SmbShare -Name "Windows-RestoreIPv6_Reports" -Force -Erroraction SilentlyContinue
            Remove-Item -LiteralPath "C:\Windows-DisableIPv6" -Force -Recurse -Erroraction SilentlyContinue
            Remove-Item -LiteralPath "C:\Windows-RestoreIPv6" -Force -Recurse -Erroraction SilentlyContinue
            Remove-Item -LiteralPath "C:\Windows-DisableIPv6_Reports" -Force -Recurse -Erroraction SilentlyContinue
            Remove-Item -LiteralPath "C:\Windows-DisableIPv6_Reports2" -Force -Recurse -Erroraction SilentlyContinue
            Remove-Item -LiteralPath "C:\Windows-RestoreIPv6_Reports" -Force -Recurse -Erroraction SilentlyContinue
            Remove-Item -LiteralPath "C:\Windows-RestoreIPv6_Reports2" -Force -Recurse -Erroraction SilentlyContinue
            Remove-GPO -Name "Windows-DisableIPv6" -Erroraction SilentlyContinue
            Remove-GPO -Name "Windows-RestoreIPv6" -Erroraction SilentlyContinue
            Unregister-ScheduledTask -TaskName "Cleanup_Windows-DisableIPv6" -Confirm:$false -Erroraction SilentlyContinue
            Unregister-ScheduledTask -TaskName "Cleanup_Windows-RestoreIPv6" -Confirm:$false -Erroraction SilentlyContinue
            clear-host
            sleep 1
            write-host ""
            write-host "                                                                                            " -BackGroundColor Black
            write-host " ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! ERROR! " -ForeGroundColor DarkRed -BackGroundColor Black
            write-host "                                                                                            " -BackGroundColor Black
            write-host "                  An error was detected while running the online installer                  " -ForeGroundColor Yellow -BackGroundColor Black
            write-host "         The installer was not able to self-remediate the error and was terminated          " -ForeGroundColor Yellow -BackGroundColor Black
            write-host "                            Any changes made have been reverted                             " -ForeGroundColor Yellow -BackGroundColor Black
            write-host "                                                                                            " -BackGroundColor Black
            write-host "       You may need to use the offline installer if the target system is unsupported        " -ForeGroundColor Yellow -BackGroundColor Black
            write-host "                 Please forward the below error message to the developer                    " -ForeGroundColor Yellow -BackGroundColor Black
            write-host "                                                                                            " -BackGroundColor Black
            write-host ""
            write-host $_.Exception.Message -ForeGroundColor Red -BackGroundColor Black
            write-host ""
            break
        }
        break
    }

    if ($SelectedFunction -eq "3")
    {
        try 
        {
            Windows-HouseKeepingIPv6
        }
        catch 
        {
            Stop-Transcript
            clear-host
            sleep 1
            write-host ""
            write-host "                                                                                            " -BackGroundColor Black
            write-host " ERROR? ERROR? ERROR? ERROR? ERROR? ERROR? ERROR? ERROR? ERROR? ERROR? ERROR? ERROR? ERROR? " -ForeGroundColor DarkRed -BackGroundColor Black
            write-host "                                                                                            " -BackGroundColor Black
            write-host "                           You should never recieve this popup                              " -ForeGroundColor Yellow -BackGroundColor Black
            write-host "                                                                                            " -BackGroundColor Black
            write-host "                 Please forward the below error message to the developer                    " -ForeGroundColor Yellow -BackGroundColor Black
            write-host "                                                                                            " -BackGroundColor Black
            write-host ""
            write-host $_.Exception.Message -ForeGroundColor Red -BackGroundColor Black
            write-host ""
            break
        }
        break
    }
}
&@FunctionMenu
$FunctionMenuexit
