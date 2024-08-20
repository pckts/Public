$KeyExist = Test-Path -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsAI\"
if ($KeyExist -ne $true)
{New-item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsAI\"}
Remove-itemproperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsAI\" -Name 'DisableAIDataAnalysis'
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsAI\" -Name 'DisableAIDataAnalysis' -Value 1 -PropertyType DWord  