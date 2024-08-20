$RecallState = Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsAI\
if ($RecallState.DisableAIDataAnalysis -eq "1")
{exit 0} else {exit 1}