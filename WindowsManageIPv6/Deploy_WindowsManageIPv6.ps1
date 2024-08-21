$DevLogOutput = "$home\VerboseDevLog_Windows-ManageIPv6.log"
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

#Defines the source script files
$DisableScript = @'
#Windows-DisableIPv6

#Failsafe trigger, if file is found, script will not run
$FailsafeExist = Test-Path -Path C:\Windows-DisableIPv6\failsafe.block
if ($FailsafeExist -eq $true)
{
    exit
}

#Makes sure the target is not an exchange server
$ExchangeExist = Get-Service -name MSExchangeServiceHost
if ($ExchangeExist -ne $null)
{
    #Create folder structure to be used
    $FolderExist = Test-Path -Path C:\Windows-DisableIPv6
    if ($FolderExist -ne $true)
    {
        New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6 | Out-Null
        sleep 1
    }
    New-Item -ItemType "file" -Path C:\Windows-DisableIPv6\failsafe.block | Out-Null
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
$FolderExist = Test-Path -Path C:\Windows-DisableIPv6
if ($FolderExist -ne $true)
{
    New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6 | Out-Null
    sleep 1
}
#Gets the current time to be used as timestamp suffix and removes any non-digits from string
$WholeTime = Get-Date -UFormat "%T"
#This regex is overkill but ensures removal of non-digits regardless of formatting used by system
$FormattedTime = $WholeTime -replace "[^\p{N}]+"

$transcriptFile = "C:\Windows-DisableIPv6\RollbackLog_" + "$FormattedTime" + ".txt"
Start-Transcript -Path $transcriptFile

#Check if the patch is already installed for logging purposes
$HotFixes = Get-Hotfix | Select-Object HotFixID
foreach ($HotFix in $HotFixes) 
{
    #Note: Only KBs for Windows Server 2012, 2012R2, 2016, 2019, and 2022 are checked, as no 2008R2 or older servers are expected to be present
    if (($HotFix.HotFixID -match "KB5041578") -or ($HotFix.HotFixID -match "KB5041160") -or ($HotFix.HotFixID -match "KB5041773") -or ($HotFix.HotFixID -match "KB5041828") -or ($HotFix.HotFixID -match "KB5041851")) 
    {
        clear-host
        write-host ""
        write-host "Please note that this server has already been patched with the required security update"
        write-host "The script will continue to disable IPv6 on all interfaces regardless"
        write-host ""
        break
    }
}

$ShareHostname = "QZQZQPLACEHOLDERQZQZQ2"

#Saves list of interfaces in case rollback is needed
$OutputFile = "C:\Windows-DisableIPv6\RollbackFile_" + "$FormattedTime" + ".csv"
$OutputFileReport = "\\$ShareHostname\Windows-DisableIPv6_Reports\IPv6OriginalSetup_" + "$hostname" + ".csv"
$AllInterfacesAndState = Get-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 | Select-Object Name,Enabled
$AllInterfacesAndState | Export-Csv -Path $OutputFile -NoTypeInformation
$AllInterfacesAndState | Export-Csv -Path $OutputFileReport -NoTypeInformation
$EnabledInterfaces = $AllInterfacesAndState | Where-Object Enabled -eq True

#Create log if first run
$HasReported = Test-Path -Path C:\Windows-DisableIPv6\hasReported.log
if ($HasReported -ne $true)
{
    New-Item -ItemType "file" -Path C:\Windows-DisableIPv6\hasReported.log | Out-Null
    sleep 1
}

#Disables IPv6 on all interfaces
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6

#Creates file to keep logging to only original run to keep logs clean
New-Item -ItemType "file" -Path C:\Windows-DisableIPv6\hasReported.log

clear-host
write-host "IPv6 has now been disabled on the following interfaces:"
foreach ($EnabledInterface in $EnabledInterfaces)
{
    write-host $EnabledInterface.Name
}
write-host ""
write-host "A backup of the previous configuration can be found at"$OutputFile
write-host "In case fallback is required, please reference this file."
write-host "Alternatively use rollback code with the ID"$FormattedTime
write-host ""
Stop-Transcript
break
'@

$RestoreScript = @'
#Windows-RestoreIPv6

#Relevance trigger, if file is not found, script will not run
$FailsafeExist = Test-Path -Path "C:\Windows-DisableIPv6\RollbackFile_*.csv"
if ($FailsafeExist -ne $true)
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
$FolderExist = Test-Path -Path C:\Windows-RestoreIPv6
if ($FolderExist -ne $true)
{
    New-Item -ItemType "directory" -Path C:\Windows-RestoreIPv6 | Out-Null
    sleep 1
}

#Gets the current time to be used as timestamp suffix and removes any non-digits from string
$WholeTime = Get-Date -UFormat "%T"
#This regex is overkill but ensures removal of non-digits regardless of formatting used by system
$FormattedTime = $WholeTime -replace "[^\p{N}]+"

$transcriptFile = "C:\Windows-RestoreIPv6\RestoreLog_" + "$FormattedTime" + ".txt"
Start-Transcript -Path $transcriptFile

$ShareHostname = "QZQZQPLACEHOLDERQZQZQ2"
$OutputFileReport = "\\$ShareHostname\Windows-RestoreIPv6_Reports\IPv6Restored_" + "$hostname" + ".csv"

#Create log if first run
$HasReported = Test-Path -Path C:\Windows-RestoreIPv6\hasReported.log
if ($HasReported -ne $true)
{
    New-Item -ItemType "file" -Path C:\Windows-RestoreIPv6\hasReported.log | Out-Null
    sleep 1
}

clear-host
$BackupFiles = "C:\Windows-DisableIPv6\RollbackFile_*.csv"
$OriginalBackupFile = dir $BackupFiles | sort lastwritetime | select -First 1
Copy-Item $OriginalBackupFile -Destination $OutputFileReport
[array]$BackupInterfaces = Import-Csv -Path $OriginalBackupFile 
$InterfacesToEnable = $BackupInterfaces | Where-Object Enabled -eq True
foreach ($InterfaceToEnable in $InterfacesToEnable)
{
    Enable-NetAdapterBinding -Name $InterfaceToEnable.Name -ComponentID ms_tcpip6
}
New-Item -ItemType "file" -Path C:\Windows-DisableIPv6\failsafe.block | Out-Null
clear-host
write-host "IPv6 has now been re-enabled on the following interfaces:"
foreach ($ReenabledInterface in $InterfacesToEnable)
{
    write-host $ReenabledInterface.Name
}
write-host ""
Stop-Transcript
break
'@

#Defines the source XML files to self-create
$backupXML = @'
<?xml version="1.0" encoding="utf-8"?><!-- Copyright (c) Microsoft Corporation.  All rights reserved. --><GroupPolicyBackupScheme bkp:version="2.0" bkp:type="GroupPolicyBackupTemplate" xmlns:bkp="http://www.microsoft.com/GroupPolicy/GPOOperations" xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations">
    <GroupPolicyObject><SecurityGroups><Group bkp:Source="FromDACL"><Sid><![CDATA[S-1-5-21-3395495481-4050882160-2184029742-519]]></Sid><SamAccountName><![CDATA[Enterprise Admins]]></SamAccountName><Type><![CDATA[UniversalGroup]]></Type><NetBIOSDomainName><![CDATA[DOMAIN]]></NetBIOSDomainName><DnsDomainName><![CDATA[domain.local]]></DnsDomainName><UPN><![CDATA[Enterprise Admins@domain.local]]></UPN></Group><Group bkp:Source="FromDACL"><Sid><![CDATA[S-1-5-21-3395495481-4050882160-2184029742-512]]></Sid><SamAccountName><![CDATA[Domain Admins]]></SamAccountName><Type><![CDATA[GlobalGroup]]></Type><NetBIOSDomainName><![CDATA[DOMAIN]]></NetBIOSDomainName><DnsDomainName><![CDATA[domain.local]]></DnsDomainName><UPN><![CDATA[Domain Admins@domain.local]]></UPN></Group></SecurityGroups><FilePaths/><GroupPolicyCoreSettings><ID><![CDATA[{37A336B4-5593-4167-AC4C-D3DA0FC4A42F}]]></ID><Domain><![CDATA[domain.local]]></Domain><SecurityDescriptor>01 00 04 9c 00 00 00 00 00 00 00 00 00 00 00 00 14 00 00 00 04 00 ec 00 08 00 00 00 05 02 28 00 00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 01 01 00 00 00 00 00 05 0b 00 00 00 00 00 24 00 ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 39 26 63 ca 70 8e 73 f1 2e a6 2d 82 00 02 00 00 00 02 24 00 ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 39 26 63 ca 70 8e 73 f1 2e a6 2d 82 00 02 00 00 00 02 24 00 ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 39 26 63 ca 70 8e 73 f1 2e a6 2d 82 07 02 00 00 00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 09 00 00 00 00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 0b 00 00 00 00 02 14 00 ff 00 0f 00 01 01 00 00 00 00 00 05 12 00 00 00 00 0a 14 00 ff 00 0f 00 01 01 00 00 00 00 00 03 00 00 00 00</SecurityDescriptor><DisplayName><![CDATA[Windows-DisableIPv6]]></DisplayName><Options><![CDATA[0]]></Options><UserVersionNumber><![CDATA[0]]></UserVersionNumber><MachineVersionNumber><![CDATA[131074]]></MachineVersionNumber><MachineExtensionGuids><![CDATA[[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]]]></MachineExtensionGuids><UserExtensionGuids/><WMIFilter><![CDATA[MSFT_SomFilter.ID="{09B5B9BD-40F6-4092-B2CB-FA3FBCC54921}",Domain="domain.local"]]></WMIFilter><WMIFilterName><![CDATA[All clients and servers excluding DCs]]></WMIFilterName></GroupPolicyCoreSettings> 
        <GroupPolicyExtension bkp:ID="{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" bkp:DescName="Registry">
            
            
            <FSObjectFile bkp:Path="%GPO_FSPATH%\Adm\*.*" bkp:SourceExpandedPath="\\DC.domain.local\sysvol\domain.local\Policies\{37A336B4-5593-4167-AC4C-D3DA0FC4A42F}\Adm\*.*"/>
        </GroupPolicyExtension>
        
        
        
        
        
        
        
        
        
    <GroupPolicyExtension bkp:ID="{F15C46CD-82A0-4C2D-A210-5D0D3182A418}" bkp:DescName="Unknown Extension"><FSObjectDir bkp:Path="%GPO_MACH_FSPATH%\Preferences" bkp:SourceExpandedPath="\\DC.domain.local\sysvol\domain.local\Policies\{37A336B4-5593-4167-AC4C-D3DA0FC4A42F}\Machine\Preferences" bkp:Location="DomainSysvol\GPO\Machine\Preferences"/><FSObjectDir bkp:Path="%GPO_MACH_FSPATH%\Preferences\ScheduledTasks" bkp:SourceExpandedPath="\\DC.domain.local\sysvol\domain.local\Policies\{37A336B4-5593-4167-AC4C-D3DA0FC4A42F}\Machine\Preferences\ScheduledTasks" bkp:Location="DomainSysvol\GPO\Machine\Preferences\ScheduledTasks"/><FSObjectFile bkp:Path="%GPO_MACH_FSPATH%\Preferences\ScheduledTasks\ScheduledTasks.xml" bkp:SourceExpandedPath="\\DC.domain.local\sysvol\domain.local\Policies\{37A336B4-5593-4167-AC4C-D3DA0FC4A42F}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" bkp:Location="DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"/></GroupPolicyExtension></GroupPolicyObject>
</GroupPolicyBackupScheme>
'@

$bkupinfoXML = '<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest"><GPOGuid><![CDATA[{37A336B4-5593-4167-AC4C-D3DA0FC4A42F}]]></GPOGuid><GPODomain><![CDATA[domain.local]]></GPODomain><GPODomainGuid><![CDATA[{30165640-b230-4d4c-9f21-2c1ab90a1385}]]></GPODomainGuid><GPODomainController><![CDATA[DC.domain.local]]></GPODomainController><BackupTime><![CDATA[2024-08-15T14:38:54]]></BackupTime><ID><![CDATA[{B4BA155A-AB98-4943-9610-328DD1EA1C37}]]></ID><Comment><![CDATA[]]></Comment><GPODisplayName><![CDATA[Windows-DisableIPv6]]></GPODisplayName></BackupInst>'

$gpreportXML = @'
<?xml version="1.0" encoding="utf-16"?>
<GPO xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.microsoft.com/GroupPolicy/Settings">
  <Identifier>
    <Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{37A336B4-5593-4167-AC4C-D3DA0FC4A42F}</Identifier>
    <Domain xmlns="http://www.microsoft.com/GroupPolicy/Types">domain.local</Domain>
  </Identifier>
  <Name>Windows-DisableIPv6</Name>
  <IncludeComments>true</IncludeComments>
  <CreatedTime>2024-08-15T14:35:15</CreatedTime>
  <ModifiedTime>2024-08-15T14:38:26</ModifiedTime>
  <ReadTime>2024-08-15T14:38:55.2940535Z</ReadTime>
  <SecurityDescriptor>
    <SDDL xmlns="http://www.microsoft.com/GroupPolicy/Types/Security">O:DAG:DAD:PAI(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;S-1-5-21-3395495481-4050882160-2184029742-519)(A;CI;LCRPLORC;;;ED)(A;CI;LCRPLORC;;;AU)(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;SY)(A;CIIO;CCDCLCSWRPWPDTLOSDRCWDWO;;;CO)S:AI(OU;CIIDSA;WPWD;;f30e3bc2-9ff0-11d1-b603-0000f80367c1;WD)(OU;CIIOIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIOIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)</SDDL>
    <Owner xmlns="http://www.microsoft.com/GroupPolicy/Types/Security">
      <SID xmlns="http://www.microsoft.com/GroupPolicy/Types">S-1-5-21-3395495481-4050882160-2184029742-512</SID>
      <Name xmlns="http://www.microsoft.com/GroupPolicy/Types">DOMAIN\Domain Admins</Name>
    </Owner>
    <Group xmlns="http://www.microsoft.com/GroupPolicy/Types/Security">
      <SID xmlns="http://www.microsoft.com/GroupPolicy/Types">S-1-5-21-3395495481-4050882160-2184029742-512</SID>
      <Name xmlns="http://www.microsoft.com/GroupPolicy/Types">DOMAIN\Domain Admins</Name>
    </Group>
    <PermissionsPresent xmlns="http://www.microsoft.com/GroupPolicy/Types/Security">true</PermissionsPresent>
    <Permissions xmlns="http://www.microsoft.com/GroupPolicy/Types/Security">
      <InheritsFromParent>false</InheritsFromParent>
      <TrusteePermissions>
        <Trustee>
          <SID xmlns="http://www.microsoft.com/GroupPolicy/Types">S-1-5-9</SID>
          <Name xmlns="http://www.microsoft.com/GroupPolicy/Types">NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS</Name>
        </Trustee>
        <Type xsi:type="PermissionType">
          <PermissionType>Allow</PermissionType>
        </Type>
        <Inherited>false</Inherited>
        <Applicability>
          <ToSelf>true</ToSelf>
          <ToDescendantObjects>false</ToDescendantObjects>
          <ToDescendantContainers>true</ToDescendantContainers>
          <ToDirectDescendantsOnly>false</ToDirectDescendantsOnly>
        </Applicability>
        <Standard>
          <GPOGroupedAccessEnum>Read</GPOGroupedAccessEnum>
        </Standard>
        <AccessMask>0</AccessMask>
      </TrusteePermissions>
      <TrusteePermissions>
        <Trustee>
          <SID xmlns="http://www.microsoft.com/GroupPolicy/Types">S-1-5-21-3395495481-4050882160-2184029742-519</SID>
          <Name xmlns="http://www.microsoft.com/GroupPolicy/Types">DOMAIN\Enterprise Admins</Name>
        </Trustee>
        <Type xsi:type="PermissionType">
          <PermissionType>Allow</PermissionType>
        </Type>
        <Inherited>false</Inherited>
        <Applicability>
          <ToSelf>true</ToSelf>
          <ToDescendantObjects>false</ToDescendantObjects>
          <ToDescendantContainers>true</ToDescendantContainers>
          <ToDirectDescendantsOnly>false</ToDirectDescendantsOnly>
        </Applicability>
        <Standard>
          <GPOGroupedAccessEnum>Edit, delete, modify security</GPOGroupedAccessEnum>
        </Standard>
        <AccessMask>0</AccessMask>
      </TrusteePermissions>
      <TrusteePermissions>
        <Trustee>
          <SID xmlns="http://www.microsoft.com/GroupPolicy/Types">S-1-5-18</SID>
          <Name xmlns="http://www.microsoft.com/GroupPolicy/Types">NT AUTHORITY\SYSTEM</Name>
        </Trustee>
        <Type xsi:type="PermissionType">
          <PermissionType>Allow</PermissionType>
        </Type>
        <Inherited>false</Inherited>
        <Applicability>
          <ToSelf>true</ToSelf>
          <ToDescendantObjects>false</ToDescendantObjects>
          <ToDescendantContainers>true</ToDescendantContainers>
          <ToDirectDescendantsOnly>false</ToDirectDescendantsOnly>
        </Applicability>
        <Standard>
          <GPOGroupedAccessEnum>Edit, delete, modify security</GPOGroupedAccessEnum>
        </Standard>
        <AccessMask>0</AccessMask>
      </TrusteePermissions>
      <TrusteePermissions>
        <Trustee>
          <SID xmlns="http://www.microsoft.com/GroupPolicy/Types">S-1-5-11</SID>
          <Name xmlns="http://www.microsoft.com/GroupPolicy/Types">NT AUTHORITY\Authenticated Users</Name>
        </Trustee>
        <Type xsi:type="PermissionType">
          <PermissionType>Allow</PermissionType>
        </Type>
        <Inherited>false</Inherited>
        <Applicability>
          <ToSelf>true</ToSelf>
          <ToDescendantObjects>false</ToDescendantObjects>
          <ToDescendantContainers>true</ToDescendantContainers>
          <ToDirectDescendantsOnly>false</ToDirectDescendantsOnly>
        </Applicability>
        <Standard>
          <GPOGroupedAccessEnum>Apply Group Policy</GPOGroupedAccessEnum>
        </Standard>
        <AccessMask>0</AccessMask>
      </TrusteePermissions>
      <TrusteePermissions>
        <Trustee>
          <SID xmlns="http://www.microsoft.com/GroupPolicy/Types">S-1-5-21-3395495481-4050882160-2184029742-512</SID>
          <Name xmlns="http://www.microsoft.com/GroupPolicy/Types">DOMAIN\Domain Admins</Name>
        </Trustee>
        <Type xsi:type="PermissionType">
          <PermissionType>Allow</PermissionType>
        </Type>
        <Inherited>false</Inherited>
        <Applicability>
          <ToSelf>true</ToSelf>
          <ToDescendantObjects>false</ToDescendantObjects>
          <ToDescendantContainers>true</ToDescendantContainers>
          <ToDirectDescendantsOnly>false</ToDirectDescendantsOnly>
        </Applicability>
        <Standard>
          <GPOGroupedAccessEnum>Edit, delete, modify security</GPOGroupedAccessEnum>
        </Standard>
        <AccessMask>0</AccessMask>
      </TrusteePermissions>
    </Permissions>
    <AuditingPresent xmlns="http://www.microsoft.com/GroupPolicy/Types/Security">false</AuditingPresent>
  </SecurityDescriptor>
  <FilterDataAvailable>true</FilterDataAvailable>
  <FilterName>All clients and servers excluding DCs</FilterName>
  <Computer>
    <VersionDirectory>2</VersionDirectory>
    <VersionSysvol>2</VersionSysvol>
    <Enabled>true</Enabled>
    <ExtensionData>
      <Extension xmlns:q1="http://www.microsoft.com/GroupPolicy/Settings/ScheduledTasks" xsi:type="q1:ScheduledTasksSettings">
        <q1:ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
          <q1:ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="Windows-DisableIPv6" image="0" changed="2024-08-15 14:38:19" uid="{6506CCB2-10F6-49E2-8B0A-0886CD703581}">
            <q1:GPOSettingOrder>1</q1:GPOSettingOrder>
            <q1:Properties action="C" name="Windows-DisableIPv6" runAs="NT AUTHORITY\System" logonType="S4U">
              <q1:Task version="1.2">
                <q1:RegistrationInfo>
                  <q1:Author>DOMAIN\administrator</q1:Author>
                  <q1:Description />
                </q1:RegistrationInfo>
                <q1:Triggers>
                  <q1:TimeTrigger>
                    <q1:Enabled>true</q1:Enabled>
                    <q1:StartBoundary>%LocalTimeXmlEx%</q1:StartBoundary>
                    <q1:EndBoundary>%LocalTimeXmlEx%</q1:EndBoundary>
                  </q1:TimeTrigger>
                </q1:Triggers>
                <q1:Settings>
                  <q1:AllowStartOnDemand>true</q1:AllowStartOnDemand>
                  <q1:DisallowStartIfOnBatteries>true</q1:DisallowStartIfOnBatteries>
                  <q1:StopIfGoingOnBatteries>true</q1:StopIfGoingOnBatteries>
                  <q1:AllowHardTerminate>true</q1:AllowHardTerminate>
                  <q1:StartWhenAvailable>true</q1:StartWhenAvailable>
                  <q1:RunOnlyIfNetworkAvailable>false</q1:RunOnlyIfNetworkAvailable>
                  <q1:WakeToRun>false</q1:WakeToRun>
                  <q1:Enabled>true</q1:Enabled>
                  <q1:Hidden>false</q1:Hidden>
                  <q1:DeleteExpiredTaskAfter>PT0S</q1:DeleteExpiredTaskAfter>
                  <q1:RunOnlyIfIdle>false</q1:RunOnlyIfIdle>
                  <q1:MultipleInstancesPolicy>IgnoreNew</q1:MultipleInstancesPolicy>
                  <q1:Priority>7</q1:Priority>
                  <q1:ExecutionTimeLimit>P3D</q1:ExecutionTimeLimit>
                  <q1:IdleSettings>
                    <q1:Duration>PT10M</q1:Duration>
                    <q1:WaitTimeout>PT1H</q1:WaitTimeout>
                    <q1:StopOnIdleEnd>true</q1:StopOnIdleEnd>
                    <q1:RestartOnIdle>false</q1:RestartOnIdle>
                  </q1:IdleSettings>
                </q1:Settings>
                <q1:Principals>
                  <q1:Principal id="Author">
                    <q1:UserId>NT AUTHORITY\System</q1:UserId>
                    <q1:LogonType>S4U</q1:LogonType>
                    <q1:RunLevel>HighestAvailable</q1:RunLevel>
                  </q1:Principal>
                </q1:Principals>
                <q1:Actions>
                  <q1:Exec>
                    <q1:Command>powershell.exe</q1:Command>
                    <q1:Arguments>-executionpolicy bypass -windowstyle hidden -noninteractive -nologo -file "\\DC\Windows-DisableIPv6\Windows-DisableIPv6.ps1</q1:Arguments>
                  </q1:Exec>
                </q1:Actions>
              </q1:Task>
            </q1:Properties>
            <q1:Filters />
          </q1:ImmediateTaskV2>
        </q1:ScheduledTasks>
      </Extension>
      <Name>Scheduled Tasks</Name>
    </ExtensionData>
  </Computer>
  <User>
    <VersionDirectory>0</VersionDirectory>
    <VersionSysvol>0</VersionSysvol>
    <Enabled>true</Enabled>
  </User>
  <LinksTo>
    <SOMName>domain</SOMName>
    <SOMPath>domain.local</SOMPath>
    <Enabled>true</Enabled>
    <NoOverride>false</NoOverride>
  </LinksTo>
</GPO>
'@

$gposcheduledtaskDisableXML = @'
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}"><ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="Windows-DisableIPv6" image="0" changed="2024-08-15 14:38:19" uid="{6506CCB2-10F6-49E2-8B0A-0886CD703581}"><Properties action="C" name="Windows-DisableIPv6" runAs="NT AUTHORITY\System" logonType="S4U"><Task version="1.2"><RegistrationInfo><Author>DOMAIN\administrator</Author><Description></Description></RegistrationInfo><Principals><Principal id="Author"><UserId>NT AUTHORITY\System</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context="Author"><Exec><Command>powershell.exe</Command><Arguments>-executionpolicy bypass -windowstyle hidden -noninteractive -nologo -file "\\QZQZQPLACEHOLDERQZQZQ\Windows-DisableIPv6\Windows-DisableIPv6.ps1</Arguments></Exec>
				</Actions></Task></Properties></ImmediateTaskV2>
</ScheduledTasks>
'@

$gposcheduledtaskRestoreXML = @'
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}"><ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="Windows-RestoreIPv6" image="0" changed="2024-08-15 14:38:19" uid="{6506CCB2-10F6-49E2-8B0A-0886CD703581}"><Properties action="C" name="Windows-RestoreIPv6" runAs="NT AUTHORITY\System" logonType="S4U"><Task version="1.2"><RegistrationInfo><Author>DOMAIN\administrator</Author><Description></Description></RegistrationInfo><Principals><Principal id="Author"><UserId>NT AUTHORITY\System</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context="Author"><Exec><Command>powershell.exe</Command><Arguments>-executionpolicy bypass -windowstyle hidden -noninteractive -nologo -file "\\QZQZQPLACEHOLDERQZQZQ\Windows-RestoreIPv6\Windows-RestoreIPv6.ps1</Arguments></Exec>
				</Actions></Task></Properties></ImmediateTaskV2>
</ScheduledTasks>
'@

$WMIFilterMOF = @'
instance of MSFT_SomFilter
{
	Author = "Administrator@domain.local";
	ChangeDate = "20240815143230.000000-000";
	CreationDate = "20240815143230.000000-000";
	Domain = "domain.local";
	ID = "{09B5B9BD-40F6-4092-B2CB-FA3FBCC54921}";
	Name = "All clients and servers excluding DCs";
	Rules = {
instance of MSFT_Rule
{
	Query = "SELECT * FROM Win32_OperatingSystem WHERE (ProductType = 1) OR (ProductType = 3)";
	QueryLanguage = "WQL";
	TargetNameSpace = "root\\CIMv2";
}};
};
'@

$CleanupRestoreXML = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-08-16T13:31:10.5153218</Date>
    <Author>Anders</Author>
    <URI>\Cleanup_Windows-RestoreIPv6</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>QQQQ-QQ-QQT12:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-executionpolicy bypass -windowstyle hidden -noninteractive -nologo -command "Remove-GPO -Name 'Windows-RestoreIPv6'; Unregister-ScheduledTask -TaskName 'Cleanup_Windows-RestoreIPv6' -Confirm:$false; Remove-Item -LiteralPath 'C:\Windows-RestoreIPv6' -Force -Recurse"</Arguments>
    </Exec>
  </Actions>
</Task>
'@

$CleanupDisableXML = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-08-16T13:31:10.5153218</Date>
    <Author>Anders</Author>
    <URI>\Cleanup_Windows-DisableIPv6</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>QQQQ-QQ-QQT12:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-executionpolicy bypass -windowstyle hidden -noninteractive -nologo -command "Remove-GPO -Name 'Windows-DisableIPv6'; Unregister-ScheduledTask -TaskName 'Cleanup_Windows-DisableIPv6' -Confirm:$false; Remove-Item -LiteralPath 'C:\Windows-DisableIPv6' -Force -Recurse"</Arguments>
    </Exec>
  </Actions>
</Task>

'@

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
    $DisableFolderExist = Test-Path -Path C:\Windows-DisableIPv6
    if ($DisableFolderExist -ne $true)
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
        sleep 1
        New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6 -Erroraction Stop
        clear-host
    }

    $DisableReportFolderExist = Test-Path -Path C:\Windows-DisableIPv6_Reports
    if ($DisableReportFolderExist -ne $true)
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
        sleep 1
        New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6_Reports -Erroraction Stop
        Copy-Item -Path "C:\Windows-DisableIPv6_Reports2\*" -Destination "C:\Windows-DisableIPv6_Reports" -Recurse -Erroraction SilentlyContinue
        Remove-Item -LiteralPath "C:\Windows-DisableIPv6_Reports2" -Force -Recurse -Erroraction SilentlyContinue
        clear-host
    }

    #Shares the folder
    sleep 1
    New-SmbShare -Name "Windows-DisableIPv6" -Path "C:\Windows-DisableIPv6" -ReadAccess "Everyone" -Erroraction Stop
    New-SmbShare -Name "Windows-DisableIPv6_Reports" -Path "C:\Windows-DisableIPv6_Reports" -ChangeAccess "Everyone" -Erroraction Stop
    $hostname = hostname
    $ShareRemotePath = "\\"+$hostname+"\Windows-DisableIPv6"
    $ShareLocalPath = "C:\Windows-DisableIPv6"

    #Creates source folder files structure
    New-Item -Path "C:\Windows-DisableIPv6\GPOSourceFilesDisable\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks" -ItemType Directory

    #Create source XML files
    $backupXML | out-file "$ShareLocalPath\GPOSourceFilesDisable\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\Backup.xml" -Encoding UTF8
    $bkupinfoXML | out-file "$ShareLocalPath\GPOSourceFilesDisable\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\bkupInfo.xml" -Encoding UTF8
    $gpreportXML | out-file "$ShareLocalPath\GPOSourceFilesDisable\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\gpreport.xml" -Encoding UTF8
    $gposcheduledtaskDisableXML | out-file "$ShareLocalPath\GPOSourceFilesDisable\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Encoding UTF8
    $WMIFilterMOF | out-file "$ShareLocalPath\GPOSourceFilesDisable\IPv6WMIFilter.mof"
    $CleanupDisableXML | out-file "$ShareLocalPath\GPOSourceFilesDisable\Cleanup_Windows-DisableIPv6.xml" -Encoding UTF8
    $DisableScript  | out-file "$ShareLocalPath\Windows-DisableIPv6.ps1"

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
    sleep 2
    $GPOAttributes = Get-GPO $GPOName
    sleep 1

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
    clear-host
    sleep 1
    write-host ""
    write-host "                                                                                  " -BackGroundColor Black
    write-host " SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! " -ForeGroundColor DarkGreen -BackGroundColor Black
    write-host "                                                                                  " -BackGroundColor Black
    write-host "           The Group Policy 'Windows-DisableIPv6' has now been deployed           " -ForeGroundColor Yellow -BackGroundColor Black
    write-host "                      The policy will self-delete in 2 weeks                      " -ForeGroundColor Yellow -BackGroundColor Black
    write-host "                                                                                  " -BackGroundColor Black
    write-host "                         This shell will self-terminate                           " -ForeGroundColor Yellow -BackGroundColor Black
    write-host "                                                                                  " -BackGroundColor Black
    write-host ""
    write-host "Developer Log: $DevLogOutput" -ForeGroundColor Gray -BackGroundColor Black
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
    $RestoreFolderExist = Test-Path -Path C:\Windows-RestoreIPv6
    if ($RestoreFolderExist -ne $true)
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
        sleep 1
        New-Item -ItemType "directory" -Path C:\Windows-DisableIPv6_Reports -Erroraction Stop
        Copy-Item -Path "C:\Windows-RestoreIPv6_Reports2\*" -Destination "C:\Windows-RestoreIPv6_Reports" -Recurse -Erroraction SilentlyContinue
        Remove-Item -LiteralPath "C:\Windows-RestoreIPv6_Reports2" -Force -Recurse -Erroraction SilentlyContinue
        clear-host
    }

    $RestoreReportFolderExist = Test-Path -Path C:\Windows-RestoreIPv6_Reports
    if ($RestoreReportFolderExist -ne $true)
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
        sleep 1
        New-Item -ItemType "directory" -Path C:\Windows-RestoreIPv6_Reports -Erroraction Stop
        clear-host
    }

    #Shares the folder
    sleep 1
    New-SmbShare -Name "Windows-RestoreIPv6" -Path "C:\Windows-RestoreIPv6" -ReadAccess "Everyone" -ErrorAction Stop
    New-SmbShare -Name "Windows-RestoreIPv6_Reports" -Path "C:\Windows-RestoreIPv6_Reports" -ChangeAccess "Everyone" -Erroraction Stop
    $hostname = hostname
    $ShareRemotePath = "\\"+$hostname+"\Windows-RestoreIPv6"
    $ShareLocalPath = "C:\Windows-RestoreIPv6"

    #Creates source folder files structure
    New-Item -Path "C:\Windows-RestoreIPv6\GPOSourceFilesRestore\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks" -ItemType Directory

    #Create source XML files
    $backupXML | out-file "$ShareLocalPath\GPOSourceFilesRestore\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\Backup.xml" -Encoding UTF8
    $bkupinfoXML | out-file "$ShareLocalPath\GPOSourceFilesRestore\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\bkupInfo.xml" -Encoding UTF8
    $gpreportXML | out-file "$ShareLocalPath\GPOSourceFilesRestore\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\gpreport.xml" -Encoding UTF8
    $gposcheduledtaskRestoreXML | out-file "$ShareLocalPath\GPOSourceFilesRestore\{B4BA155A-AB98-4943-9610-328DD1EA1C37}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Encoding UTF8
    $WMIFilterMOF | out-file "$ShareLocalPath\GPOSourceFilesRestore\IPv6WMIFilter.mof"
    $CleanupRestoreXML | out-file "$ShareLocalPath\GPOSourceFilesRestore\Cleanup_Windows-RestoreIPv6.xml" -Encoding UTF8
    $RestoreScript | out-file "$ShareLocalPath\Windows-RestoreIPv6.ps1"

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
    sleep 2
    $GPOAttributes = Get-GPO $GPOName
    sleep 1
    
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
    clear-host
    sleep 1
    write-host ""
    write-host "                                                                                  " -BackGroundColor Black
    write-host " SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! " -ForeGroundColor DarkGreen -BackGroundColor Black
    write-host "                                                                                  " -BackGroundColor Black
    write-host "           The Group Policy 'Windows-RestoreIPv6' has now been deployed           " -ForeGroundColor Yellow -BackGroundColor Black
    write-host "                      The policy will self-delete in 8 weeks                      " -ForeGroundColor Yellow -BackGroundColor Black
    write-host "                                                                                  " -BackGroundColor Black
    write-host "                         This shell will self-terminate                           " -ForeGroundColor Yellow -BackGroundColor Black
    write-host "                                                                                  " -BackGroundColor Black
    write-host ""
    write-host "Developer Log: $DevLogOutput" -ForeGroundColor Gray -BackGroundColor Black
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
    clear-host
    sleep 1
    write-host ""
    write-host "                                                                                  " -BackGroundColor Black
    write-host " SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! SUCCESS! " -ForeGroundColor DarkGreen -BackGroundColor Black
    write-host "                                                                                  " -BackGroundColor Black
    write-host "         Any previous implementations of either DisableIPv6 or RestoreIPv6        " -ForeGroundColor Yellow -BackGroundColor Black
    write-host "                 have now been completely removed from this server                " -ForeGroundColor Yellow -BackGroundColor Black
    write-host "                                                                                  " -BackGroundColor Black
    write-host "                         This shell will self-terminate                           " -ForeGroundColor Yellow -BackGroundColor Black
    write-host "                                                                                  " -BackGroundColor Black
    write-host ""
    write-host "Developer Log: $DevLogOutput" -ForeGroundColor Gray -BackGroundColor Black
    write-host ""
    sleep 10
    exit
}

$FunctionMenu = 
{
    cls
    sleep 1
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
