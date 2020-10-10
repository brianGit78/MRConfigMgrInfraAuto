####################################################################
#   os-network.SetStaticIPAddresses.ps1
#
#   Change Log
#	v1 - brian
#	removed win2k3 parts, fixed disable nics function, removed overly verbose logging
#	v2 - brian
#	using connection to port 80 on management point as validation instead of ping.
#	v3 - brian
#	fixed removal of static route function (removeststaticroutes)
#	v4 - brian
#	fixed default gateway for nics #6-18, cleaned up some logging, added some diag info to nic failure
#	allowed subnet and shorthand masks for static routes
#
####################################################################

#Turn all the ConfigMgr Variables into Powershell Variables
#Create Task Sequence Environment object
$tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment

# Convert the task sequence variables into PowerShell variables 
$tsenv.GetVariables() | % { Set-Variable -Name "$_" -Value "$($tsenv.Value($_))" } 

####################
#Setup Logging
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
[string]$global:logfile = "$dotRoot\Logs\os-network.SetStaticIPAddress.txt"

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


####################
#Map the TS variables to script variables

#static route variables
[hashtable]$winStaticRoute1 = @{"Network"	= "$winStaticRouteNetwork1"
				"SubnetMask"	= "$winStaticRouteSubnetMask1"
				"Gateway"	= "$winStaticRouteGateway1"}

[hashtable]$winStaticRoute2 = @{"Network"	= "$winStaticRouteNetwork2"
				"SubnetMask"	= "$winStaticRouteSubnetMask2"
				"Gateway"	= "$winStaticRouteGateway2"}

[hashtable]$winStaticRoute3 = @{"Network"	= "$winStaticRouteNetwork3"
				"SubnetMask"	= "$winStaticRouteSubnetMask3"
				"Gateway"	= "$winStaticRouteGateway3"}

[hashtable]$winStaticRoute4 = @{"Network"	= "$winStaticRouteNetwork4"
				"SubnetMask"	= "$winStaticRouteSubnetMask4"
				"Gateway"	= "$winStaticRouteGateway4"}

[hashtable]$winStaticRoute5 = @{"Network"	= "$winStaticRouteNetwork5"
				"SubnetMask"	= "$winStaticRouteSubnetMask5"
				"Gateway"	= "$winStaticRouteGateway5"}

[hashtable]$winStaticRoute6 = @{"Network"	= "$winStaticRouteNetwork6"
				"SubnetMask"	= "$winStaticRouteSubnetMask6"
				"Gateway"	= "$winStaticRouteGateway6"}


#network interface variables
[hashtable]$netnic1 = @{"Name"				= "$netnic1Name"
			"PnpDeviceId" 			= "$netnic1PnPDeviceID"
			"MacAddress"			= "$netnic1MacAddress"
			"IpAddress"			= "$netnic1IpAddress"
			"SubnetMask"			= "$netnic1SubnetMask"
			"DefaultGateway"		= "$netnic1DefaultGateway"
			"DnsServerSearchOrder"		= "$netnic1DnsServerSearchOrder"
			"DefaultGatewayMetric"		= "$netnic1DefaultGatewayMetric"
			"NetBiosConfig"			= "$netnic1NetBiosConfig"
			"DnsRegistrationEnabled"	= "$netnic1DNSRegistrationEnabled"
			"DnsSuffixRegistrationEnabled"	= "$netnic1DnsSuffixRegistrationEnabled"}

[hashtable]$netnic2 = @{"Name"				= "$netnic2Name"
			"PnpDeviceId" 			= "$netnic2PnPDeviceID"
			"MacAddress"			= "$netnic2MacAddress"
			"IpAddress"			= "$netnic2IpAddress"
			"SubnetMask"			= "$netnic2SubnetMask"
			"DefaultGateway"		= "$netnic2DefaultGateway"
			"DnsServerSearchOrder"		= "$netnic2DnsServerSearchOrder"
			"DefaultGatewayMetric"		= "$netnic2DefaultGatewayMetric"
			"NetBiosConfig"			= "$netnic2NetBiosConfig"
			"DnsRegistrationEnabled"	= "$netnic2DNSRegistrationEnabled"
			"DnsSuffixRegistrationEnabled"	= "$netnic2DnsSuffixRegistrationEnabled"}

[hashtable]$netnic3 = @{"Name"				= "$netnic3Name"
			"PnpDeviceId" 			= "$netnic3PnPDeviceID"
			"MacAddress"			= "$netnic3MacAddress"
			"IpAddress"			= "$netnic3IpAddress"
			"SubnetMask"			= "$netnic3SubnetMask"
			"DefaultGateway"		= "$netnic3DefaultGateway"
			"DnsServerSearchOrder"		= "$netnic3DnsServerSearchOrder"
			"DefaultGatewayMetric"		= "$netnic3DefaultGatewayMetric"
			"NetBiosConfig"			= "$netnic3NetBiosConfig"
			"DnsRegistrationEnabled"	= "$netnic3DNSRegistrationEnabled"
			"DnsSuffixRegistrationEnabled"	= "$netnic3DnsSuffixRegistrationEnabled"}

[hashtable]$netnic4 = @{"Name"				= "$netnic4Name"
			"PnpDeviceId" 			= "$netnic4PnPDeviceID"
			"MacAddress"			= "$netnic4MacAddress"
			"IpAddress"			= "$netnic4IpAddress"
			"SubnetMask"			= "$netnic4SubnetMask"
			"DefaultGateway"		= "$netnic4DefaultGateway"
			"DnsServerSearchOrder"		= "$netnic4DnsServerSearchOrder"
			"DefaultGatewayMetric"		= "$netnic4DefaultGatewayMetric"
			"NetBiosConfig"			= "$netnic4NetBiosConfig"
			"DnsRegistrationEnabled"	= "$netnic4DNSRegistrationEnabled"
			"DnsSuffixRegistrationEnabled"	= "$netnic4DnsSuffixRegistrationEnabled"}

[hashtable]$netnic5 = @{"Name"				= "$netnic5Name"
			"PnpDeviceId" 			= "$netnic5PnPDeviceID"
			"MacAddress"			= "$netnic5MacAddress"
			"IpAddress"			= "$netnic5IpAddress"
			"SubnetMask"			= "$netnic5SubnetMask"
			"DefaultGateway"		= "$netnic5DefaultGateway"
			"DnsServerSearchOrder"		= "$netnic5DnsServerSearchOrder"
			"DefaultGatewayMetric"		= "$netnic5DefaultGatewayMetric"
			"NetBiosConfig"			= "$netnic5NetBiosConfig"
			"DnsRegistrationEnabled"	= "$netnic5DNSRegistrationEnabled"
			"DnsSuffixRegistrationEnabled"	= "$netnic5DnsSuffixRegistrationEnabled"}

[hashtable]$netnic6 = @{"Name"				= "$netnic6Name"
			"PnpDeviceId" 			= "$netnic6PnPDeviceID"
			"MacAddress"			= "$netnic6MacAddress"
			"IpAddress"			= "$netnic6IpAddress"
			"SubnetMask"			= "$netnic6SubnetMask"
			"DefaultGateway"		= "$netnic6DefaultGateway"
			"DefaultGatewayMetric"		= "$netnic6DefaultGatewayMetric"}

[hashtable]$netnic7 = @{"Name"				= "$netnic7Name"
			"PnpDeviceId" 			= "$netnic7PnPDeviceID"
			"MacAddress"			= "$netnic7MacAddress"
			"IpAddress"			= "$netnic7IpAddress"
			"SubnetMask"			= "$netnic7SubnetMask"
			"DefaultGateway"		= "$netnic7DefaultGateway"
			"DefaultGatewayMetric"		= "$netnic7DefaultGatewayMetric"}

[hashtable]$netnic8 = @{"Name"				= "$netnic8Name"
			"PnpDeviceId" 			= "$netnic8PnPDeviceID"
			"MacAddress"			= "$netnic8MacAddress"
			"IpAddress"			= "$netnic8IpAddress"
			"SubnetMask"			= "$netnic8SubnetMask"
			"DefaultGateway"		= "$netnic8DefaultGateway"
			"DefaultGatewayMetric"		= "$netnic8DefaultGatewayMetric"}

[hashtable]$netnic9 = @{"Name"				= "$netnic9Name"
			"PnpDeviceId" 			= "$netnic9PnPDeviceID"
			"MacAddress"			= "$netnic9MacAddress"
			"IpAddress"			= "$netnic9IpAddress"
			"SubnetMask"			= "$netnic9SubnetMask"
			"DefaultGateway"		= "$netnic9DefaultGateway"
			"DefaultGatewayMetric"		= "$netnic9DefaultGatewayMetric"}

[hashtable]$netnic10 = @{"Name"				= "$netnic10Name"
			"PnpDeviceId" 			= "$netnic10PnPDeviceID"
			"MacAddress"			= "$netnic10MacAddress"
			"IpAddress"			= "$netnic10IpAddress"
			"SubnetMask"			= "$netnic10SubnetMask"
			"DefaultGateway"		= "$netnic10DefaultGateway"
			"DefaultGatewayMetric"		= "$netnic10DefaultGatewayMetric"}

[hashtable]$netnic11 = @{"Name"				= "$netnic11Name"
			"PnpDeviceId" 			= "$netnic11PnPDeviceID"
			"MacAddress"			= "$netnic11MacAddress"
			"IpAddress"			= "$netnic11IpAddress"
			"SubnetMask"			= "$netnic11SubnetMask"
			"DefaultGateway"		= "$netnic11DefaultGateway"
			"DefaultGatewayMetric"		= "$netnic11DefaultGatewayMetric"}

[hashtable]$netnic12 = @{"Name"				= "$netnic12Name"
			"PnpDeviceId" 			= "$netnic12PnPDeviceID"
			"MacAddress"			= "$netnic12MacAddress"
			"IpAddress"			= "$netnic12IpAddress"
			"SubnetMask"			= "$netnic12SubnetMask"
			"DefaultGateway"		= "$netnic12DefaultGateway"
			"DefaultGatewayMetric"		= "$netnic12DefaultGatewayMetric"}

[hashtable]$netnic13 = @{"Name"				= "$netnic13Name"
			"PnpDeviceId" 			= "$netnic13PnPDeviceID"
			"MacAddress"			= "$netnic13MacAddress"
			"IpAddress"			= "$netnic13IpAddress"
			"SubnetMask"			= "$netnic13SubnetMask"
			"DefaultGateway"		= "$netnic13DefaultGateway"
			"DefaultGatewayMetric"		= "$netnic13DefaultGatewayMetric"}

[hashtable]$netnic14 = @{"Name"				= "$netnic14Name"
			"PnpDeviceId" 			= "$netnic14PnPDeviceID"
			"MacAddress"			= "$netnic14MacAddress"
			"IpAddress"			= "$netnic14IpAddress"
			"SubnetMask"			= "$netnic14SubnetMask"
			"DefaultGateway"		= "$netnic14DefaultGateway"
			"DefaultGatewayMetric"		= "$netnic14DefaultGatewayMetric"}

[hashtable]$netnic15 = @{"Name"				= "$netnic15Name"
			"PnpDeviceId" 			= "$netnic15PnPDeviceID"
			"MacAddress"			= "$netnic15MacAddress"
			"IpAddress"			= "$netnic15IpAddress"
			"SubnetMask"			= "$netnic15SubnetMask"
			"DefaultGateway"		= "$netnic15DefaultGateway"
			"DefaultGatewayMetric"		= "$netnic15DefaultGatewayMetric"}

[hashtable]$netnic16 = @{"Name"				= "$netnic16Name"
			"PnpDeviceId" 			= "$netnic16PnPDeviceID"
			"MacAddress"			= "$netnic16MacAddress"
			"IpAddress"			= "$netnic16IpAddress"
			"SubnetMask"			= "$netnic16SubnetMask"
			"DefaultGateway"		= "$netnic16DefaultGateway"
			"DefaultGatewayMetric"		= "$netnic16DefaultGatewayMetric"}

[hashtable]$netnic17 = @{"Name"				= "$netnic17Name"
			"PnpDeviceId" 			= "$netnic17PnPDeviceID"
			"MacAddress"			= "$netnic17MacAddress"
			"IpAddress"			= "$netnic17IpAddress"
			"SubnetMask"			= "$netnic17SubnetMask"
			"DefaultGateway"		= "$netnic17DefaultGateway"
			"DefaultGatewayMetric"		= "$netnic17DefaultGatewayMetric"}

[hashtable]$netnic18 = @{"Name"				= "$netnic18Name"
			"PnpDeviceId" 			= "$netnic18PnPDeviceID"
			"MacAddress"			= "$netnic18MacAddress"
			"IpAddress"			= "$netnic18IpAddress"
			"SubnetMask"			= "$netnic18SubnetMask"
			"DefaultGateway"		= "$netnic18DefaultGateway"
			"DefaultGatewayMetric"		= "$netnic18DefaultGatewayMetric"}

###############
#Script Variables
#

[string]$regexIPAddress = "^(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])$"

#$networkAdapters = Get-WmiObject -class Win32_NetworkAdapter | where -filterscript {$_.NetConnectionID -ne $null}
$wmiOperatingSystem = Get-WmiObject -class Win32_OperatingSystem

#Win32_NetworkAdapter - NetConnectionStatus
[int]$netStatusDISABLED	= 0
[int]$netStatusCONNECTING = 1
[int]$netStatusCONNECTED = 2
[int]$netStatusDISCONNECTING = 3
[int]$netStatusHWNOTPRESENT = 4
[int]$netStatusHWDISABLED = 5
[int]$netStatusHWMALFUNCTION = 6
[int]$netStatusMEDIADISCONNECTED = 7
[int]$netStatusAUTHENTICATING = 8
[int]$netStatusAUTHSUCCESS = 9
[int]$netStatusAUTHFAIL = 10
[int]$netStatusINVALIDADDR = 11
[int]$netStatusCREDSREQ = 12

#####################
#  Configuration Functions
#


#disables all nics that are set to DHCP
function disableUnusedNics()
{
	writeEvent $logfile "Disabling unused network interfaces..."
	$networkAdapters = Get-WmiObject -class Win32_NetworkAdapter | where -filterscript {$_.NetConnectionID -ne $null}

	foreach ($networkAdapter in $networkAdapters)
	{
		[string]$nicConnectionID = $networkadapter.NetConnectionID
		$interfaceIndex = $networkAdapter.InterfaceIndex

		#fixed for teaming 12/03/2010 - only disable nics with IP bound to them
		$networkAdapterConfiguration = Get-WmiObject -class Win32_NetworkAdapterConfiguration | where -filterscript {($_.InterfaceIndex -eq $interfaceIndex) -AND ($_.IPEnabled -eq $true)}

		foreach ($nic in $networkAdapterConfiguration)
		{
			if ($nic.DHCPEnabled -eq $true)
			{
				writeEvent $logfile "Disabling $nicConnectionID"
        			$disableNic="netsh interface set interface `"$($networkAdapter.NetConnectionID)`" DISABLED"
        			cmd /c $disableNic
			}
		}

		#this will disable the adapter if it has no static IP and is in a disconnected state (netconnectionstatus = $netStatusMEDIADISCONNECTED)
		$networkAdapterConfiguration = Get-WmiObject -class Win32_NetworkAdapterConfiguration | where -filterscript {($_.InterfaceIndex -eq $interfaceIndex)}

		foreach ($nic in $networkAdapterConfiguration)
		{
			if (($nic.DHCPEnabled -eq $true) -AND ($networkAdapter.NetConnectionStatus -eq $netStatusMEDIADISCONNECTED))
			{
				writeEvent $logfile "Disabling $nicConnectionID"
        			$disableNic="netsh interface set interface `"$($networkAdapter.NetConnectionID)`" DISABLED"
        			cmd /c $disableNic
			}
		}

	}

	writeEvent $logfile "Completed disabling unused network interfaces..."
}


function resetNicNames()
{
	writeEvent $global:logfile "==================================="
	writeEvent $global:logfile "Changing connection names to their defaults...."

	$networkAdapters = Get-WmiObject -class Win32_NetworkAdapter | where -filterscript {$_.NetConnectionID -ne $null}

	[int]$n = -1

	foreach ($networkAdapter in $networkAdapters)
	{
		#writeevent $global:logfile $n
		$null = $n++
		[string]$nic = $networkAdapter.NetConnectionID
		[string]$connectionName = "Local Area Connection $n"


		#handle special case
		if ($connectionName -eq "Local Area Connection 0")
		{
			$connectionName = "Local Area Connection"
		}

		if ($nic -ne $connectionName)
		{
			writeEvent $global:logfile "Changing connections name from `"$nic`" to `"$connectionName`""

			if ($windows2003 -eq $true)
			{
				$cmd = "netsh interface set interface name=`"$nic`" newname=`"$connectionName`""
				cmd.exe /c $cmd 
			}		
			else
			{
				$networkAdapter.NetConnectionID = $connectionName
				$networkAdapter.Put()
			}
		}
	}

	writeEvent $global:logfile "Completed changing connection names to their defaults."
	writeEvent $global:logfile "==================================="
	writeEvent $global:logfile ""
}


function revertDHCP()
{
    writeEvent $global:logfile ""
    writeEvent $global:logfile "==================================="
    writeEvent $global:logfile "Enabling DHCP on all adapters..."

    $netConfigs = Get-WmiObject -class Win32_NetworkAdapterConfiguration | where -filterscript {$_.IPEnabled -eq $true}

    foreach ($netConfig in $netConfigs)
    {
	$nicIndex = $netConfig.Index
	$networkAdapter = Get-WmiObject -class Win32_NetworkAdapter | where -filterscript {$_.index -eq $nicIndex}

	[string]$targetNic = $networkAdapter.NetConnectionID
 
	writeEvent $global:logfile "Enabling DHCP: $targetNic"
        $cmd="netsh interface ip set address name=`"$targetNic`" source=dhcp"
    	#writeevent $global:logfile "running command: $cmd"
        cmd /c $cmd

        $cmd="netsh interface ip set dns `"$targetNic`" source=dhcp"
	#writeEvent $global:logfile "running command: $cmd"
        cmd /c $cmd
 
    }

    writeEvent $global:logfile "Completed enabling DHCP on all adapters."
    writeEvent $global:logfile "==================================="
    writeEvent $global:logfile ""

}

#this function removes all persistent routes
function removePersistentRoutes()
{
	if (!($persistentRoutes)){return}

	writeEvent $global:logfile "Deleting Persistent Routes"
	$persistentRoutes = Get-WmiObject -class Win32_IP4PersistedRouteTable

	foreach ($route in $persistentRoutes)
	{
		if (($route.Destination -match $regexIPAddress) -eq $True)
		{
			#$route.Destination = $null
			#$route.Mask = $null
			#$route.Metric1 = $null
			#$route.NextHop = $null
			#$route.Put()
			[string]$routeDestination = $route.Destination
			$cmd = "route delete $routeDestination"
			writeEvent $global:logfile "Deleting route $routeDestination"
		        cmd /c $cmd
		}
	}
}

#the rollback function simply calls other functions
function rollBack()
{
	writeEvent $global:logfile "Rolling back all network changes..."
	
	enableNics

	resetNicNames

	revertDHCP

	removePersistentRoutes
}


#this function adds persistent routes
function configurePersistentRoute([hashtable]$route)
{
	
	#check the variables
	if (($route.Network -match $regexIPAddress) -eq $False){return}
	if (($route.Gateway -match $regexIPAddress) -eq $False){return}

	#handle full or 
	if ($route.SubnetMask.Length -eq 2)
	{
		#convert subnet mask
		$mask = ConvertTo-Mask $route.SubnetMask

	}
	elseif(($route.Gateway -match $regexIPAddress) -eq $True)
	{
		[string]$mask = $route.SubnetMask
	}
	else{return}

	#build the route command string to echo and execute
	[string]$network = $route.Network
	[string]$gateway = $route.Gateway	
	[string]$routeString = "$Network MASK $mask $gateway"

	writeEvent $global:logfile "Setting Static Route $routeString"
	
	[string]$cmd = "/c route.exe -p ADD $routeString"
	cmd.exe $cmd
	#$outString = "cmd.exe $cmd" | out-string

	#writeEvent $global:logfile "standard out " $outString
	#if ($outString.Contains("failed") -eq $True){writeEvent $global:logfile "FAILED!!!"}

}


function configureAdapter([hashtable]$nic)
{
	[string]$nicName = $nic.name

	#check if the interface has a well formed IP Address assigned. if not, exit function.
	if (($nic['IpAddress'] -match $regExIPAddress) -eq $False)
	{
		#writeEvent $global:logfile "Interface $nicname does not have an IP Address assigned. Skipping."
		return
	}

	##convert the variables into useful types (hashtable object was also behaving strangely)
	[string]$nicName = $nic.Name
	[string]$nicPnpDeviceID = $nic.PnpdeviceId
	[string]$nicMacAddress = $nic.MacAddress

	#Change MAC to contains colons	
	If ($nicMacAddress.contains(“-“) –eq $true)
	{
		$nicMacAddress = $nicMacAddress.Replace(“-“,”:”)
	}
	Elseif ($nicMacAddress.length -lt 17)
	{
		$nicMacAddress= $nicMacAddress.Insert(2,":").Insert(5,":").Insert(8,":").Insert(11,":").Insert(14,":")
	}

	[string]$nicIpAddress = $nic.IpAddress
	[string]$nicSubnetMask = $nic.SubnetMask
	[string]$nicDefaultGateway = $nic.DefaultGateway
	[string]$nicDnsServerSearchOrder = $nic.DnsServerSearchOrder
	[string]$nicDefaultGatewayMetric = $nic.DefaultGatewayMetric
	[int]$nicNetBiosConfig = $nic.NetBiosConfig

	if (($nicNetBiosConfig -ne 0)  -OR ($nicNetBiosConfig -ne 1))
	{
		        $nicNetBiosConfig = 2
			[string]$nicNetBiosConfigDisplay = "Disabled"
	}

	#$nicNetBiosConfigDisplay = & switch ($nicNetBiosConfig) { 0 {"Enabled via DHCP"}; 1 {"Enabled"}; 2 {"Disabled"}}

	[string]$nicDnsRegistrationEnabled = $nic.DnsRegistrationEnabled
    	[string]$nicDnsSuffixRegistrationEnabled = $nic.DnsSuffixRegistrationEnabled	

	writeEvent $global:logfile "====================================================="
	writeEvent $global:logfile "Begining Configuration of network interface $nicname"
	writeEvent $global:logfile ""
	writeEvent $global:logfile " Connection Name:	       $nicName"
	writeEvent $global:logfile " PlugnPlay Device ID:      $nicPnpDeviceId"
	writeEvent $global:logfile " Mac Address:              $nicMacAddress" 
	writeEvent $global:logfile " IP Address:               $nicIPAddress "
	writeEvent $global:logfile " Subnet Mask:              $nicSubnetMask"
	writeEvent $global:logfile " Default Gateway:          $nicDefaultGateway"
	writeEvent $global:logfile " DNS Servers:              $nicDnsServerSearchOrder"
	writeEvent $global:logfile " Default Gateway Metric:   $nicDefaultGatewayMetric"
	writeEvent $global:logfile " NetBios over TCP/IP:      $nicNetBiosConfigDisplay"
	writeEvent $global:logfile " DNS Registration Enabled: $nicDnsRegistrationEnabled"
	writeEvent $global:logfile " DNS Suffix Registration:  $nicDnsSuffixRegistrationEnabled"
	writeEvent $global:logfile ""

	#create the WMI objects
	$networkAdapters = Get-WmiObject -class Win32_NetworkAdapter | where -filterscript {$_.NetConnectionID -ne $null}
	$networkAdaptersConfig = Get-WmiObject -class Win32_NetworkAdapterConfiguration

	#check if the interface has a well formed subnet mask assigned.
	if (($nicSubnetMask -match $regExIPAddress) -eq $False)
	{
		writeEvent $global:logfile "Invalid Subnet mask specified. Bad data from manifest. Exiting with error."
		Exit 1
	}

	######################################
	## Find the physical adapter
	#Check if the PnPDeviceID or MAC Address exists, if otherwise, revert and exit the entire script with error level 1

	#this assumes index starts at zero
	[int]$n = -1

	while (($nicIndex -eq $null) -OR ($networkAdapters.count -eq $n))
	{
		#needed to change this to work with teamed adapters. the same mac occurs twice, need only the IP one
		foreach ($networkAdapterConfig in $networkAdaptersConfig)
		{
			$n++

			if (($nicMacAddress -eq $networkAdapterConfig.MACAddress) -AND ($networkAdapterConfig.IPEnabled -eq $true))
			{
				writeEvent $global:logfile "Found MAC Address for $nicName"
				$nicIndex = $networkAdapterConfig.InterfaceIndex
				break
			}
		}

		if ($nicIndex -eq $null){writeEvent $logfile "Unable to find an IP adapter with MAC: $nicMacAddress, trying plug and play Device ID.."}

		if ($nicIndex -eq $null)
		{
			foreach ($networkAdapter in $networkAdapters)
			{
				[string]$PnpDeviceID = $networkAdapter.PNPDeviceID

				$n++
	
				if ($nicPNPDeviceID -eq $PnpDeviceID)
				{	
					writeEvent $global:logfile "Found PNPDeviceID for $nicName"
					$nicIndex = $networkAdapter.InterfaceIndex
				}
			}
		}
		

		if ($nicIndex -eq $null)
		{
			writeEvent $global:logfile "FATAL ERROR: Unable to find PnPDeviceID or MAC Address for Nic: $nicName" 
			writeEvent $global:logfile "" 
			rollBack
			Exit 1
		}
		
	}

	######################################
	##begin configuring the adapters
	$targetNicConfig = Get-WmiObject -class Win32_NetworkAdapterConfiguration | where -filterscript {$_.InterfaceIndex -eq $nicIndex}
	$targetNic = Get-WmiObject -class Win32_NetworkAdapter | where -filterscript {$_.InterfaceIndex -eq $nicIndex}


	#change the name of the adapter
	$targetNicName = $targetnic.netconnectionid
	writeEvent $global:logfile "Changing connections name from $targetNicName to $nicname"
	writeEvent $global:logfile ""

	#name the network interface
	if ($windows2003 -eq $true)
	{
		$cmd = "netsh interface set interface name=`"$targetNicName`" newname=`"$nicname`""
		cmd.exe /c $cmd
	}
	else
	{
		$targetNic.NetConnectionID = $nicName
		$targetNic.Put()
	}


	#set the static IP Address
	#different command for a default gateway or not
    	if (($nicDefaultGateway -match $regExIPAddress) -eq $true)
    	{
		writeEvent $global:logfile "-Setting the Static IP Address $nicIpAddress $nicSubnetMask and Default Gateway $nicDefaultGateway"
		$cmd="netsh interface ip set address name=`"$nicname`" static $nicipaddress $nicsubnetmask $nicDefaultGateway $nicDefaultGatewayMetric"
		cmd /c $cmd
    	}
	else
	{
		$cmd="netsh interface ip set address name=`"$nicname`" static $nicipaddress $nicsubnetmask"
		cmd /c $cmd
	}

    	#configure netBIOS on interface
	writeEvent $global:logfile "-Setting the NetBios Configuration to $nicNetBiosConfig"
    	if ($nicNetBiosConfig -le 1)
    	{
    		$return = $targetNicConfig.SetTcpipNetBios($nicNetBiosConfig)
            	if ($windows2003 -ne $true){$targetNic.Put()}
		errorCodes $return
    		#0 Enable via DHCP
    		#1 Enable
    		#2 Disable
    	}
        else
        {
            	$return = $targetNicConfig.SetTcpipNetBios(2)
            	if ($windows2003 -ne $true){$targetNic.Put()}
        }

    	## Set Adapter DNS Specific information

	#convert dns registration
	if ($nicDnsRegistrationEnabled.ToUpper() -eq "TRUE")
	{
		$dnsReg = "primary"
		writeEvent $global:logfile "-Setting Dynamic DNS Registration to enabled"
	}
	else
	{
		$dnsReg = "none"
		writeEvent $global:logfile "-Setting Dynamic DNS Registration to disabled"
	}

    	#set the dns server search order, check for most common conditions (1.1.1.1\1.1.1.2, 1.1.1.1/1.1.1.2 and 1.1.1.1)
    	#should also be able to support more than two dns servers, but has not been tested for it specifically
    	if ($nicDnsServerSearchOrder.contains("\")  -eq $true)
    	{
    		$dnsServers = $nicDnsServerSearchOrder.Split("\")
    	}
    	elseif ($nicDnsServerSearchOrder.contains("/") -eq $true)
    	{
    		$dnsServers = $nicDnsServerSearchOrder.Split("/")
    	}
    	elseif (($nicDnsServerSearchOrder -match $regexIPAddress) -eq $True)
    	{
    		#set the connection here if only a single DNS Server is specified
		writeEvent $global:logfile "-Setting Primary DNS Servers to $nicDnsServerSearchOrder"

		$cmd="netsh interface ip set dns `"$nicname`" static $nicDnsServerSearchOrder register=$dnsreg"
		cmd /c $cmd
    	}
    	
    	#set the dns server search order if there are multiple dns servers
    	if($dnsServers -is [system.array])
    	{
    		if (($dnsServers[0] -match $regexIPAddress) -eq $true)
    		{
			[string]$dnsserver1 = $dnsServers[0]
			writeEvent $global:logfile "-Setting Primary DNS Servers to $dnsserver1"
			$cmd="netsh interface ip set dns `"$nicname`" static $dnsserver1 register=$dnsreg"
			cmd /c $cmd
    		}
		
		if (($dnsServers[1] -match $regexIPAddress) -eq $true)
		{
			[string]$dnsserver2 = $dnsServers[1]
			writeEvent $global:logfile "-Setting Secondary DNS Server to $dnsserver2"
			$cmd="netsh interface ip add dns `"$nicname`" $dnsserver2"
			cmd /c $cmd
		}
    	}

	writeEvent $global:logfile "Completed Configuration of $nicName."
	writeEvent $global:logfile "====================================================="
	writeEvent $global:logfile ""
}


#some utility functions (to be moved to library at some point)

#sourced from http://www.indented.co.uk/index.php/2010/01/23/powershell-subnet-math/
Function ConvertTo-DottedDecimalIP([String]$IP) 
{

	Switch -RegEx ($IP) 
	{
		"([01]{8}\.){3}[01]{8}"
	{

      Return [String]::Join('.', $( $IP.Split('.') | %{[Convert]::ToInt32($_, 2) } ))}
    "\d" {

      $IP = [UInt32]$IP
      $DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
        $Remainder = $IP % [Math]::Pow(256, $i)
        ($IP - $Remainder) / [Math]::Pow(256, $i)
        $IP = $Remainder
       } )

      Return [String]::Join('.', $DottedIP)
    }
    default {
      Write-Error "Cannot convert this format"
    }
  }
}


Function ConvertTo-Mask([Byte]$MaskLength)
{
	Return ConvertTo-DottedDecimalIP ([Convert]::ToUInt32($(("1" * $MaskLength).PadRight(32, "0")), 2))
}


#####################
#####################
#  Main
#

####################
#Determine Operating System Version

$wmiOperatingSystem = Get-WmiObject -class Win32_OperatingSystem

$osName = $wmiOperatingSystem.Name

if ($osName.Contains("2003") -eq $True){writeEvent $logfile "Windows Server 2003 detected";[bool]$windows2003 = $true}else{[bool]$windows2003 = $false}

#####################
#  Configure the interfaces
#

$turnoffFirewall  = "netsh advfirewall set allprofiles state off"
cmd.exe /c $turnoffFirewall

#delete all current persistent routes
removePersistentRoutes

enableNics
resetNicNames
revertDHCP

configureAdapter $netnic1
configureAdapter $netnic2
configureAdapter $netnic3
configureAdapter $netnic4
configureAdapter $netnic5
configureAdapter $netnic6
configureAdapter $netnic7
configureAdapter $netnic8
configureAdapter $netnic9
configureAdapter $netnic10
configureAdapter $netnic11
configureAdapter $netnic12
configureAdapter $netnic13
configureAdapter $netnic14
configureAdapter $netnic15
configureAdapter $netnic16
configureAdapter $netnic17
configureAdapter $netnic18

disableUnusedNics


#####################
#  Configure the routes
#

configurePersistentRoute $winStaticRoute1
configurePersistentRoute $winStaticRoute2
configurePersistentRoute $winStaticRoute3
configurePersistentRoute $winStaticRoute4
configurePersistentRoute $winStaticRoute5
configurePersistentRoute $winStaticRoute6

#####################
#  Validate connectivity using http to the management point
#

#give the connections an opportunity to configure
cmd.exe /c ipconfig /flushdns
sleep 240

if ($_SMSTSMP)
{
	[string]$managementPoint = $_SMSTSMP
	$webport = "80"

	writeEvent $global:logfile "Verifying socket connection to $managementPoint on port $webport"
	$tcp = new-object System.Net.Sockets.TcpClient($managementPoint, $webport)
}
else
{
	writeEvent $logfile "No Management Point specified. Script is probably running interactively."
	writeEvent $logfile "Press Ctrl-C to stop the script processing and accept the changes."
	writeEvent $logfile "Otherwise, settings will be rolled back in 30 seconds..."
	sleep 30
}

if (($tcp) -AND ($tcp.connected -eq $true))
{
	writeEvent $logfile "Completion of Static IP Address Assignment Success!"
	cmd.exe /c ipconfig /registerdns
	Exit 0
}
else
{
	writeEvent $logfile "Unable to create socket connection to $managementPoint on $webPort"
	writeEvent $logfile "============================================================================="
	writeEvent $logfile "Gathering diagnostic information"
	writeEvent $logfile "============================================================================="

	writeEvent $logfile ""
	writeEvent $logfile "Analyzing variables for common mistakes...."

	if((($netnic1DefaultGateway -match $regexIPAddress) -eq $false) -AND (($netnic1DefaultGateway -match $regexIPAddress) -eq $false))
	{
		writeEvent $logfile "Potential Configuration Problem: netNic1 does not have a default gateway and there are no static routes."
	}

	#try to ping the first 3 gateways
	$ping = new-object system.net.networkinformation.ping

	if ($netnic1.DefaultGateway -match $regexIPAddress)
	{
		[string]$netnic1DefaultGateway = $netnic1.DefaultGateway
		writeEvent $logfile "Pinging netnic1 Default Gateway $netnic1DefaultGateway"
		$ping = cmd.exe /c ping $netnic1DefaultGateway
		foreach ($line in $ping){writeEvent $logfile $line}
	}

	if ($netnic2.DefaultGateway -match $regexIPAddress)
	{
		[string]$netnic2DefaultGateway = $netnic2.DefaultGateway
		writeEvent $logfile "Pinging netnic2 Default Gateway $netnic2DefaultGateway"
		$ping = cmd.exe /c ping $netnic2DefaultGateway
		foreach ($line in $ping){writeEvent $logfile $line}
	}

	if ($netnic3.DefaultGateway -match $regexIPAddress)
	{
		[string]$netnic3DefaultGateway = $netnic3.DefaultGateway
		writeEvent $logfile "Pinging netnic3 Default Gateway $netnic3DefaultGateway"
		$ping = cmd.exe /c ping $netnic3DefaultGateway
		foreach ($line in $ping){writeEvent $logfile $line}
	}

	#get nslookup of management point
	if ($_SMSTSMP)
	{
		writeEvent $logfile "Getting Nslookup results"
		writeEvent $logfile "nslookup -debug " $_SMSTSMP
		$nslookup = cmd.exe /c nslookup -debug $_SMSTSMP
		foreach ($line in $nslookup){writeEvent $logfile $line}
	}

	writeEvent $logfile ""
	writeEvent $logfile "============================================================================="
	writeEvent $logfile "Dumping FAILED IP Configuration"
	writeEvent $logfile "============================================================================="
	$ipconfigAll = cmd.exe /c ipconfig /all
	foreach ($line in $ipconfigAll){writeEvent $logfile $line}

	writeEvent $logfile ""
	writeEvent $logfile "============================================================================="
	writeEvent $logfile "Dumping FAILED Route Configuration"
	writeEvent $logfile "============================================================================="
	$routePrint = cmd.exe /c route print
	foreach ($line in $routePrint){writeEvent $logfile $line}

	writeEvent $global:logfile "Rolling back to DHCP. Review your configuration to see why I cannot talk to the Management Point."
	rollback

	Exit 1
}