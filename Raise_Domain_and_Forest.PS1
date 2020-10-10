
#Wait for AD to initialize
$lastHours = [DateTime]::Now.AddHours(-1)

#loop for 10 minutes
[int]$i = 0
if ($i -ne 20)
{
                while ($adComplete -eq $null)
                {
                                #look for an instance of event ID 1394 within the last hour. Loop until it happens.
                                $adComplete = get-eventlog "Directory Service" | where {$_.EventID -eq 1394}
                                write-host "Checking for Event ID 1394 to verify AD initialization"

                                if ($adComplete -eq $null)
                                {
                                                write-host "Checking again in 30 seconds"
                                                sleep 30
                                }
                                $i++

                                if ($adComplete -ne $null)
                                {
                                                write-host "Event Found, proceeding"
                                }
                }
}

#######Promote domain to Windows2003Domain

$dom = [System.DirectoryServices.ActiveDirectory.Domain]::getcurrentdomain() 
write-host "Domain found to be " $dom.name
$dom.domainmode
if($dom.DomainMode.tostring().toupper() -eq "WINDOWS2000MIXEDDOMAIN")
{
write-host "Raising domain functionality to Windows2000NativeDomain"
$dom.RaiseDomainFunctionality('Windows2000NativeDomain') 
if($? -eq $true)
{
}
else
{
throw "An error occured Raising domain functionality to Windows2000NativeDomain"
}
}

write-host "Domain functionality raised to Windows2000NativeDomain"
if($dom.DomainMode.tostring().toupper() -eq "WINDOWS2000NATIVEDOMAIN")
{
write-host "Raising domain functionality to Windows2003Domain"
$dom.RaiseDomainFunctionality('Windows2003Domain') 
if($? -eq $true)
{
}
else
{
throw "An error occured Raising domain functionality to Windows2003Domain"
}
}

write-host "Domain functionality raised to Windows2003Domain"
#######Promote forest to Windows2003Forest

$for = [System.DirectoryServices.ActiveDirectory.Forest]::getcurrentforest() 
write-host "Raising forest functionality to Windows2003Forest"
if($for.Forestmode.tostring().toupper() -ne "WINDOWS2003FOREST")
{
$for.RaiseForestFunctionality('Windows2003Forest') 
if($? -eq $true)
{
}
else
{
throw "An error occured Raising forest functionality to Windows2003Forest"
}

}
write-host "Forest functionality raised Windows2003Forest"
