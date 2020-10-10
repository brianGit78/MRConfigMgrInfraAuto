$path="^path^"
$path=$path + "\"
$adsmachine="^adsdeploymentserver^"
$certname="^certname^"

if($adsmachine -eq "^adsdeploymentserver^" -or $adsmachine-eq "")
{
throw "^adsdeploymentserver^ variable was not string replaced."
}
if($certname -eq "^certname^" -or $certname -eq "")
{
throw "^certname^ variable was not string replaced. Check your project plan for #CERTNAME# sequencer variable before running this step."
}

write-host "Copying issuing ca certificate to ADS for publish in AD."
$cmd="copy \\" + $adsmachine + "\c$\deploy\local\certificates\" + $certname + " " + $path + $certname
cmd /c $cmd

write-host "Copying root ca certificate to ADS for publish in AD."
$cmd="copy \\" + $adsmachine + "\c$\deploy\local\certificates\root.cer" + " " + $path + "root.cer"
cmd /c $cmd

write-host "Publishing issuing cert to AD"
$cmd="certutil -f -dspublish " + $path + $certname
cmd /c $cmd
write-host "Publishing root cert to AD"
$cmd="certutil -f -dspublish " + $path + "root.cer RootCA"
cmd /c $cmd