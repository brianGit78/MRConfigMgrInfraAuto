############################
#  os-config.HyperVGuest-UsePMTimer.ps1
#  1/28/2010
#
###########################


#get OS version
$win32OperatingSystem = get-wmiobject -class Win32_OperatingSystem

#get Host type (VM or not)
$win32ComputerSystem = get-wmiobject -class Win32_ComputerSystem

#get current state of boot.ini
[string]$bootCfg = cmd.exe /c bootcfg.exe /query

[bool]$isVirtualMachine = $false
[bool]$isWin2k3 = $false
[bool]$containsUsePMTimer = $false

if ($win32ComputerSystem.Model.ToUpper() -eq "VIRTUAL MACHINE"){$isVirtualMachine = $true}
if ($win32OperatingSystem.Name.ToUpper().Contains("WINDOWS SERVER 2003")){$isWin2k3 = $true}
if ($bootCfg.ToUpper().Contains("/USEPMTIMER")){$containsUsePMTimer = $true}

write-host "Is Virtual Machine: 	$isVirtualMachine"
write-host "Is Windows Server 2003: 	$isWin2k3"
write-host "Usepmtimer exists: 		$containsUsePMTimer"

if (($isVirtualMachine -eq $true) -AND ($isWin2k3 -eq $true) -AND ($containsUsePMTimer -eq $false))
{
	write-host "Machine requires the usepmtimer switch"
	cmd.exe /c bootcfg.exe /raw "/usepmtimer" /A /ID 1

	#validate the change
	[string]$bootCfgValidate = cmd.exe /c bootcfg.exe /query
	if ($bootCfgValidate.ToUpper().Contains("/USEPMTIMER"))
	{
		write-host "Usepmtimer added successfully"
		Exit 0
	}
	else
	{
		write-host "!!!Usepmtimer not added successfully"
		Exit 1
	}
	
}
else
{
	write-host "Machine does not require usePMTimer"
	Exit 0
}

