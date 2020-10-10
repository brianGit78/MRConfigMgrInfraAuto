###################
# Network Teaming Script
# os-network.teaming.ps1
# change log: 
#	v1 - initial release, intel teaming
#	v2 - broadcom teaming support, exit script immediately if no team present in profile name  
#
#
#	Note: to obtain a non-machine specific team file for broadcom adapters, use this command: BACSCli -t TEAM "save -f BDF C:\temp\BACS-BDF.txt" 
#
#
#
###################

$debugPreference = "Continue"
#$debugPreference = "SilentlyContinue"

###################
#Turn all the ConfigMgr Variables into Powershell Variables
#Create Task Sequence Environment object
$tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment

#Convert the task sequence variables into PowerShell variables 
$tsenv.GetVariables() | % {Set-Variable -Name "$_" -Value "$($tsenv.Value($_))" } 


####################
#Setup MRDOT Path
if (test-path "c:\MRDOT")
{
	[string]$dotRoot = "C:\MRDOT"
}
else
{
	write-host "Unable to find C:\MRDOT"
	Exit 1
}


###############################################################################
##  function checkAndInitLib
##  Description : validate the library exists and then dot source it (function itself must be dot sourced [. checkAndInitLib])
##  in : absolute path to library file
##  out: either dot sourced library or fail 1
function checkAndInitLib($lib)
{
	if (!(Test-Path $lib))
	{
		write-host "Unable to find library $lib"
		Exit 1
	}
	else
	{
		write-host "Initializing Library $lib"
		. $lib
	}
}

. checkAndInitLib "$dotRoot\Libraries\Microsoft.Mediaroom.DOT.WindowsConfiguration.ps1"


#use environment independant way to check process architecture
if (test-path "C:\Program Files (x86)")
{
	$procArch = "AMD64"
}
else
{
	$procArch = "x86"
}


#get the directory the script is running from
$workingDir = Split-path (Resolve-Path $myInvocation.MyCommand.Path)
write-debug "workingdir: $workingDir"

####################
#Setup Logging
[string]$global:logfile = "$dotRoot\Logs\os-network.Teaming.txt"

if (test-path $global:logfile)
{
	$lastLogFile = $global:logfile.Replace(".txt","-LAST.txt")

	if (test-path $lastLogFile){Remove-Item $lastLogFile -force}

	rename-item $global:logfile $lastLogFile

}

CreateLogFile $global:logfile
WriteEvent $global:logfile ""
WriteEvent $global:logfile "***New Installation Started***"
WriteEvent $global:logfile "Running setup as: $env:userdomain\$env:username"
WriteEvent $global:logfile "Script working directory: $workingDir"
WriteEvent $global:logfile "Actual Processor Architecture: $procArch"
WriteEvent $global:logfile "Running Processor Architecture: $env:PROCESSOR_ARCHITECTURE"


##############################
#Set working variables

#msiexec path
[string]$msiExec = $env:winDir + "\System32\MSIEXEC.EXE"

#get the networkAdapter wmi object
$networkAdapters = Get-WmiObject -class Win32_NetworkAdapter | where -filterscript {$_.NetConnectionID -ne $null}



#enable all the nics
sleep 20
enableNics


####################
#determine manufacturer

[bool]$global:intelNetwork = $false
[bool]$global:nvidiaNetwork = $false
[bool]$global:broadcomNetwork = $false
[bool]$global:hpNetwork = $false

foreach ($networkAdapter in $networkAdapters)
{
	if ($networkAdapter.caption.Contains("Intel") -eq $True)
	{
		[bool]$global:intelNetwork = $true
		WriteEvent $logfile "Intel Adapter found"
		$templateDir = 	"$workingDir\Templates\Intel"
		Write-Debug $templateDir
		break
	}

	if ($networkAdapter.caption.Contains("Broadcom") -eq $True)
	{
		[bool]$global:broadcomNetwork = $true
		WriteEvent $logfile "Broadcom Adapter found"
		$templateDir = 	"$workingDir\Templates\Broadcom"
		Write-Debug $templateDir
		break
	}

	if ($networkAdapter.caption.Contains("NVIDIA") -eq $True)
	{
		[bool]$global:nvidiaNetwork = $true
		WriteEvent $logfile "NVIDIA Adapter found"
		WriteEvent $logfile "You will have to edit this script to make it work"
		break	
	}

	if ($networkAdapter.caption.Contains("HewlettPackard") -eq $True)
	{
		[bool]$global:hpNetwork = $true
		WriteEvent $logfile "HP Adapter found"
		WriteEvent $logfile "You will have to edit this script to make it work"
		break	
	}
}





#get the WMI software collection
if ($procArch -eq "AMD64") 
{
	$wmiSoftwareFeature = Get-WMIObject -class Win32_SoftwareFeature | where -filterscript {$_.Caption -ne $null}
}
else
{
	$wmiSoftwareFeature = Get-WMIObject -class Win32_Product | where -filterscript {$_.Caption -ne $null}
}

##############################################################################################################################################
#Intel SW install
##############################################################################################################################################
#########################
#Install Intel Drivers and Software

if ($global:intelNetwork -eq $True)
{
	#determine if Intel ANS is installed
	[bool]$productIntelANS = $false
	foreach ($feature in $wmiSoftwareFeature)
	{
		[string]$featureCaption = $feature.Caption
		if ($featureCaption.Contains("PROSet"))
		{
			[bool]$productIntelANS = $true
			break
		}
	}

	#set installer path for for base drivers
	if ($procArch -eq "AMD64"){[string]$baseDriverSetup = "$workingDir\Intel\APPS\SETUP\SETUPBD\Winx64\SetupBD.exe"}
	if(!(test-path $baseDriverSetup)){writeEvent $logfile "Unable to find $baseDriverSetup. Terminating"; Exit 1 }

	#set installer path for proset
	if ($procArch -eq "AMD64"){[string]$prosetSetup = "$workingDir\Intel\APPS\PROSETDX\Winx64\DXSetup.exe"}
	if(!(test-path $prosetSetup)){writeEvent $logfile "Unable to find $prosetSetup. Terminating"; Exit 1 }	

	#set installer path for proset
	if ($procArch -eq "AMD64"){[string]$prosetMSI = "$workingDir\Intel\APPS\PROSETDX\Winx64\PROSETDX.MSI"}
	if(!(test-path $prosetMSI)){writeEvent $logfile "Unable to find $prosetMSI. Terminating"; Exit 1 }	


	#set the msi log file path
	$setupLogFile = "$dotRoot\Logs\IntelProset.txt"
	writeEvent $logfile "Installer log: $setupLogFile"

	#check the version of Intel ANS - if it's 13.5.0.0 then uninstall it
	if ($productIntelANS -eq $true)
	{
		$intelSoftwareFeature = Get-WmiObject -query "SELECT * FROM Win32_SoftwareFeature WHERE Vendor LIKE 'Intel'"

		foreach ($feature in $intelSoftwareFeature)
		{
			#may need to convert this version type and use -le operator
			if ($feature.version -eq "13.5.0.0")
			{
				[bool]$intelOldVersion = $true
				break
			}
		}

		#initiate uninstall
		#writeEvent $logfile "Uninstalling Previous version of Intel Proset with ANS (13.5)..."
		#cmd.exe /c msiexec.exe /x $prosetMSI /qn /liew $setupLogfile

		#writeEvent $logfile "Uninstalling Previous version of Intel Base Drivers (13.5)..."
		#$baseDriverCmd = "$baseDriverSetup /u"
		#cmd.exe /c $baseDriverCmd

	}

	#check the software again
	if ($procArch -eq "AMD64") 
	{
		$wmiSoftwareFeature = Get-WMIObject -class Win32_SoftwareFeature | where -filterscript {$_.Caption -ne $null}
	}
	else
	{
		$wmiSoftwareFeature = Get-WMIObject -class Win32_Product | where -filterscript {$_.Caption -ne $null}
	}

	#determine if Intel ANS is installed (again)
	[bool]$productIntelANS = $false
	foreach ($feature in $wmiSoftwareFeature)
	{
		[string]$featureCaption = $feature.Caption
		if ($featureCaption.Contains("PROSet"))
		{
			[bool]$productIntelANS = $true
			break
		}
	}


	if (($productIntelANS -eq $false) -OR ($intelOldVersion -eq $true))
	{

		#execute the installation
		writeEvent $logfile "Installing Intel Base Drivers..."
		$baseDriverCmd = "$baseDriverSetup /s /nr"
		cmd.exe /c $baseDriverCmd
	
		writeEvent $logfile "Installing Intel Proset with ANS..."
		$prosetCmd = "$prosetSetup /qn /liew $setupLogfile"
		cmd.exe /c $prosetCmd

		#verify installation
		if ($procArch -eq "AMD64") 
		{
			$wmiSoftwareFeature = Get-WMIObject -class Win32_SoftwareFeature | where -filterscript {$_.Caption -ne $null}
		}
		else
		{
			$wmiSoftwareFeature = Get-WMIObject -class Win32_Product | where -filterscript {$_.Caption -ne $null}
		}

		foreach ($feature in $wmiSoftwareFeatureVerify)
		{
			[string]$featureCaption = $feature.Caption
			if ($featureCaption.Contains("PROSet"))
			{
				writeEvent $logfile "Intel ANS Software is already installed"
				[bool]$productIntelANS = $true
				break
			}
		}

		#validate install was successful			
		if ($productIntelANS -eq $false){writeEvent $logfile "Installation of Intel ANS was not successful! Check the log $setupLogFile"}
	}

}
##############################################################################################################################################
#Broadcom SW install
##############################################################################################################################################
#Install Broadcom Drivers and Software

if ($global:broadcomNetwork -eq $True)
{
	#these are the versions for the software currently included with the script
	[system.version]$broadcomDriverCurrentVersion = "14.4.8.4"
	[system.version]$baspCurrentVersion = "14.4.11.3"

	#set installation path based on cpu platform for the driver and management application
	if ($procArch -eq "AMD64"){[string]$setupFile = "$workingDir\Broadcom\MgmtApps\x64\setup.exe"; [string]$driverSetupFile = "$workingDir\Broadcom\W2K3_W2K8_64\DrvInst\setup.exe"}
	if ($procArch -eq "x86"){[string]$setupFile = "$workingDir\Broadcom\MgmtApps\IA32\setup.exe"; [string]$driverSetupFile = "$workingDir\Broadcom\W2K3_W2K8\DrvInst\setup.exe"}

	#check for the base driver installation
	[bool]$productBroadcomDrivers = $false
	foreach ($feature in $wmiSoftwareFeature)
	{
		[string]$featureCaption = $feature.Caption

		if (($featureCaption.Contains("NetXtreme II Drivers")) -AND ($feature.version -ge $broadcomDriverCurrentVersion))
		{
			[bool]$productBroadcomDrivers = $true
			$featureVersion = $feature.version.ToString()
			writeEvent $logfile "Broadcom NetXtreme II Drivers are at the most current version as specified in the script"
			write-debug "Installed Version: $featureversion"
			write-debug "Required Version: $broadcomDriverCurrentVersion"
			break
		}
	}

	if ($productBroadcomDrivers -eq $false)
	{
		#set the log file path
		$driverSetupLogFile = "$dotRoot\Logs\BroadcomDrivers.txt"

		#execute the Driver installation
		writeEvent $logfile "Broadcom NetXtreme II Drivers need to be upgraded"
		write-debug "Installed Version: $feature.version.ToString()"
		write-debug "Required Version: $broadcomDriverCurrentVersion"
		writeEvent $logfile "Installing Broadcom Drivers..."
		$cmd = "$driverSetupFile /s /v`" /qn /L $driverSetupLogFile"
		cmd.exe /c $cmd
		writeEvent $logfile "Broadcom Driver Setup Complete. Log file: $driverSetupLogFile"

	}

	#########################


	#determine if Broadcom BASP is installed
	[bool]$productBroadcomBASP = $false
	foreach ($feature in $wmiSoftwareFeature)
	{
		[string]$featureCaption = $feature.Caption
		if (($featureCaption.Contains("Broadcom Management")) -AND ($feature.version -ge $baspCurrentVersion))
		{
			[bool]$productBroadcomBASP = $true
			$featureVersion = $feature.version.ToString()
			writeEvent $logfile "Broadcom BASP is at the most current version as specified in the script"
			write-debug "Installed Version: $featureVersion"
			write-debug "Required Version: $baspCurrentVersion"
			break
		}
	}

	if ($productBroadcomBASP -eq $false) 
	{

		#set the log file path
		$setupLogFile = "$dotRoot\Logs\BroadcomBasp.txt"
		$featureVersion = $feature.version.ToString()
		#execute the BASP installation
		writeEvent $logfile "Broadcom BASP needs to be installed or upgraded"
		write-debug "Installed Version: $featureversion"
		write-debug "Required Version: $baspCurrentVersion"
		$cmd = "$setupFile /s /v`" /qn /L $setupLogFile REBOOT=ReallySuppress"
		cmd.exe /c $cmd
		writeEvent $logfile "Broadcom Driver Setup Complete. Log file: $setupLogFile"

	}

	#check the software again
	if ($procArch -eq "AMD64") 
	{
		$wmiSoftwareFeature = Get-WMIObject -class Win32_SoftwareFeature | where -filterscript {$_.Caption -ne $null}
	}
	else
	{
		$wmiSoftwareFeature = Get-WMIObject -class Win32_Product | where -filterscript {$_.Caption -ne $null}
	}

	#exit with a vengance if the previous installers are not showing up as the correct version

	#if (!(($featureCaption.Contains("NetXtreme II Drivers")) -AND ($feature.version -ge $broadcomDriverCurrentVersion))){writeEvent $logfile "Something prevented the broadcom driver software from updating. Check your versioning."; Exit 1}
	#if (!(($featureCaption.Contains("Broadcom Management Programs")) -AND ($feature.version -ge $baspCurrentVersion))){writeEvent $logfile "Something prevented the broadcom management software from updating. Check your versioning."; Exit 1}
}


##############################################################################################################################################
#Figure out what the team file is
##############################################################################################################################################

#########################
#Find and Validate the team file
#order is - manifest variable first, shortened (-12), templates\platform\role.txt, templates\role.txt, exit 1

if (!($winHostName)){$winHostName = $ENV:COMPUTERNAME}
[string]$role = $winHostName.SubString(0, ($winHostName.Length -3)).SubString(6)
[string]$rolefile = $role + ".TXT"

write-debug $netTeamConfigFile
#create trimmed version of team file for large names
if ($netTeamConfigFile.contains("`)7"))
{	
	$spot = $netTeamConfigFile.IndexOf("`)7")
	$altnetTeamConfigFile = $netTeamConfigFile.Remove($spot+1)
	$altnetTeamConfigFile = $altnetTeamConfigFile + ".TXT"
	writeEvent $logfile "More than 7 teams specified in manifest. Truncating to new name: $altnetTeamConfigFile"
}

#parse the team file name to see if we even need teaming
[string]$firstTeam = $netTeamConfigFile.Remove(12)
if (($netTeamConfigFile) -AND ($firstTeam.ToUpper().Contains("X-X") -eq $true))
{
	writeEvent $logfile "This machine does not need to be teamed. Exiting as a success. Team name: $firstTeam"
	Exit 0
}

#check if the variable is present and exists in the template dir
if(($netTeamConfigFile) -AND (test-path "$templateDir\$netTeamConfigFile"))
{
	$teamfile = "$templateDir\$netTeamConfigFile"
	writeEvent $logfile "Found Manifest team file: $teamFile"
}
elseif (($netTeamConfigFile) -AND (test-path "$workingDir\Templates\$netTeamConfigFile"))
{
	$teamfile = "$workingDir\Templates\$netTeamConfigFile"
	writeEvent $logfile "Found Manifest team file: $teamFile"
}
elseif (($altnetTeamConfigFile) -AND (test-path "$templateDir\$altnetTeamConfigFile"))
{
	$teamfile = "$templateDir\$netTeamConfigFile"
	writeEvent $logfile "Found Truncated Manifest team file: $teamFile"
}
elseif(test-path "$templateDir\$rolefile")
{
	$teamfile = "$templateDir\$rolefile "
	writeEvent $logfile "Found Role team file: $teamFile"
}	
elseif(test-path "$workingDir\Templates\$rolefile")
{
	$teamfile = "$workingDir\Templates\$rolefile "
	writeEvent $logfile "Found Role team file: $teamFile"
}
else
{
	writeEvent $logfile "Unable to find a valid team file. Exiting."
	Exit 1
}

#final sanity check for team file
if (!(test-path $teamfile)){writeEvent $logfile "Cannot Find teamfile $teamfile"; Exit 1}else{writeEvent $logfile "Using teamfile $teamfile"}

##
#fix up the netnic1MacAddress value if present
$teamEdit = (Get-Content $teamFile) | Foreach-Object {$_.Replace('^netNic1MacAddress^', $netNic1MacAddress)}
$teamEdit | Set-Content $teamFile 

#fix up the netnic2MacAddress value if present
$teamEdit = (Get-Content $teamFile) | Foreach-Object {$_.Replace('^netNic2MacAddress^', $netNic2MacAddress)}
$teamEdit | Set-Content $teamFile 


#########################
#Configure the Intel Team

if ($global:intelNetwork -eq $True)
{

	#check for teaming tool (should be same location on x86 and amd64)
	$savResDXTool = "C:\Program Files\Intel\DMIX\SavResDX.vbs"
	if (!(test-path $savResDXTool)){writeEvent $logfile "Unable to find Intel Teaming Tool $savResDXTool. Exiting.";Exit 1}

	writeEvent $logFile "Removing existing Intel teams..."
	cscript.exe /nologo $savResDXTool removeansonly
	enablenics

	writeEvent $logfile "Creating Intel network team..."	
	[string]$cmd = "`"$teamFile`""
	write-debug $cmd
	cscript.exe /nologo $savResDXTool restore $cmd
	write-debug "Exit Code $LASTEXITCODE"

	$null = cmd.exe /c ipconfig /release
	$null = cmd.exe /c ipconfig /renew

	#if ($LASTEXITCODE -ne 0){rollback}

}

#########################
#Configure the Broadcom Team

if ($global:broadcomNetwork -eq $True)
{
	#check for Broadcom Tool
	[string]$bacsCliCmd = "C:\Program Files\Broadcom\BACS\BACScli.exe"
	if (!(test-path $bacsCliCmd)){writeEvent $logfile "Unable to find $bacsCliCmd. Exiting with error."; Exit 1}

	#redeclare with quotes because cmd.exe fails
	[string]$bacsCliCmd = "`"C:\Program Files\Broadcom\BACS\BACScli.exe`""

	#remove existing broadcom teams
	writeEvent $logfile "Removing existing Broadcom teams..."
	[string]$removeTeam = "$bacsCliCmd -t team `"remove -c all`""
	cmd.exe /c `"$removeTeam`"

	#disable RSS for team members
	$broadcomTeamMembers = @()

	$teamFileContent = Get-Content $teamFile
	
	foreach ($line in $teamFileContent)
	{
		#writeEvent $logfile $line

		if ($line.Contains("pnic:         "))
		{

			#writeEvent $logfile "Found line with pnic"

			$newline = $line.replace("pnic:         ","")
			$broadcomTeamMembers += $newline
		}
	}

	foreach ($teamMember in $broadcomTeamMembers)
	{
		#writeEvent $logfile "Disabling Receive Side Scaling on team member: " $teamMember

		[string]$disableRSS = "$bacsCliCmd -t NDIS -f BDF -i $teamMember `"cfg advanced \`"Receive Side Scaling\`"=Disable`""
		cmd.exe /c `"$disableRSS`"
	}

	#create teams
	[string]$createTeam = "$bacsCliCmd -t TEAM `"add $teamFile`""
	writeEvent $logfile "Creating Broadcom Team..."
	cmd.exe /c `"$createTeam`"
	writeEvent $logfile "Exit Code $LASTEXITCODE"

	$null = cmd.exe /c ipconfig /release
	$null = cmd.exe /c ipconfig /renew

	if ($LASTEXITCODE -ne 0){rollback}
}


#########################
#Roll Back Function

function rollback()
{
    writeEvent $logfile "Network Teaming Failed. Dumping Diagnostic Information."
    
   	writeEvent $logfile ""
	writeEvent $logfile "============================================================================="

	writeEvent $logfile "adsAdminMac = $adsAdminMac"
	writeEvent $logfile "netnic1MacAddress = $netnic1MACAddress"

    	writeEvent $logfile "============================================================================="
	writeEvent $logfile "Dumping FAILED IP Configuration (ipconfig /all)."
	
	$ipconfigAll = cmd.exe /c ipconfig /all
	foreach ($line in $ipconfigAll){writeEvent $logfile $line}
    
    	writeEvent $logfile "============================================================================="
	writeEvent $logfile "Dumping Interface Configuration (getmac)."
    
	$getmacCMD = cmd.exe /c ipconfig /all
	foreach ($line in $getmacCMD){writeEvent $logfile $line}
    
	writeEvent $logfile "============================================================================="
	writeEvent $logfile "Dumping System Information (systeminfo)."
    
	$systeminfoCMD = cmd.exe /c systeminfo
	foreach ($line in $systeminfoCMD){writeEvent $logfile $line}


	writeEvent $logfile "============================================================================="
	writeEvent $logfile "============================================================================="

	if ($global:intelNetwork -eq $true)
	{
		writeEvent $logFile "Removing existing Intel teams..."
		cscript.exe /nologo $savResDXTool removeansonly

	}

	if ($global:broadcomNetwork -eq $true)
	{
		#remove existing broadcom teams
		writeEvent $logfile "Removing all Broadcom Teams..."
		[string]$removeTeam = "$bacsCliCmd -t team `"remove -c all`""
		cmd.exe /c `"$removeTeam`"
	}

	sleep 20
	enablenics

	$null = cmd.exe /c ipconfig /release
	$null = cmd.exe /c ipconfig /renew

	Exit 1
}


#####################
#  Validate connectivity using http to the management point
#

#give the connections an opportunity to configure
sleep 60

[string]$managementPoint = $_SMSTSMP
$webport = "80"

writeEvent $global:logfile "Validating connection to $managementPoint port $webport"
$tcp = new-object System.Net.Sockets.TcpClient($managementPoint, $webport)

if (($tcp) -AND ($tcp.connected -eq $true))
{
	writeEvent $global:logfile "Contacting Management Point successful! Network Teaming is complete."
	Exit 0
}
else
{
	writeEvent $logfile "Unable to create socket connection to $managementPoint on $webPort"

	writeEvent $logfile ""
	writeEvent $logfile "============================================================================="
	writeEvent $logfile "Dumping FAILED IP Configuration"
	writeEvent $logfile "============================================================================="
	$ipconfigAll = cmd.exe /c ipconfig /all
	foreach ($line in $ipconfigAll){writeEvent $logfile $line}

	rollback
}