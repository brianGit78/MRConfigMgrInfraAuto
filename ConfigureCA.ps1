
##
## This script depends on ldfide commandline tool, in server 2008 install via "servermanagercmd.exe -i RSAT-ADDS"
## Also depends on $dotroot\libraries\*.ps1 supporting files 
##
## Required (must be reviewed/set before running the script)
##           - $caProfile (indicates which issuing CA configuration will be performed)
##
## Optional (must be reviewed, might need to be changed to suit specific configuration)
##           - $domainfqdn and $sccmServer (if script is being run interactively, update these variables - when run via task sequence these are set via SCCM device variables)
##           - $branchAutoenroll, $backendAutoenroll, $CFAutoenroll (if not using reference naming convention for server names, update these arrays)




########################################################
##  show-help
function show-help
{
	WriteEvent $global:logfile "usage - os-ca.postinstall.ps1 [caprofile] [domainfqdn] [sccmserver]"
	WriteEvent $global:logfile ""
	WriteEvent $global:logfile "valid values for caProfile are:"
	WriteEvent $global:logfile " 1 - This script is executing on the branch CA, and CF CA will exist in the environment"
	WriteEvent $global:logfile " 2 - This script is executing on Client Facing CA (separate CFCA exists, AKA `"enhanced PKI`" configuration)"
	WriteEvent $global:logfile " 3 - This script is executing on the branch CA, and CF CA will NOT exist (there is not a separate Client Facing CA in the branch)"
	WriteEvent $global:logfile " 4 - This script is executing on the backend CA / or for a Single Domain environment (Branch/Backend CA)"
	WriteEvent $global:logfile ""
	WriteEvent $global:logfile  "Sample: os-ca.postinstall.ps1 1 br.cntoso.com cntosoemsbr001"
	WriteEvent $global:logfile  ""
	exit 1
}



########################################################
##  setMediaroomOIDFriendlyName
##  Description : 
##  in : none
##  out: template creation or skip
########################################################

function setMediaroomOIDFriendlyName
{
	trap [Exception]
	{
		WriteEvent $global:logfile ("Error in setMediaroomOIDFriendlyName: "+$_.Exception.Message)
		exit -1
	}
	[string]$templateLDFFile = $workingDir + "\MediaroomOIDFriendlyName.ldf"
	[string]$CertTemplateName                       = "MediaroomOID"
				
	writeEvent $global:logfile "$certTemplateName LDF template does not exist. Creating template."
	#check for an exising LDF
	if (Test-Path $templateLDFFile)
	{
		WriteEvent $global:logfile  "Found existing LDF file. Deleting..."
		Remove-Item -path $templateLDFFile
	}
	
	#Create the file
	WriteEvent $global:logfile "Creating LDF file"
	$templateLDF = New-Item -type file $templateLDFFile
	
    #get the naming context to add the cert template to
                $rootDSE = [ADSI]"LDAP://RootDSE"
                $defaultNamingContext = $rootDSE.Get("defaultNamingContext")
    
	#add lines to the file
	
	add-content $templateLDF "dn: CN=5592405.0B90E7EB17BAFEFAD4883EF0347C4191,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,$defaultNamingContext"
	add-content $templateLDF "changetype: add"
	add-content $templateLDF "objectClass: top"
	add-content $templateLDF "objectClass: msPKI-Enterprise-Oid"
	add-content $templateLDF "cn: 5592405.0B90E7EB17BAFEFAD4883EF0347C4191"
	add-content $templateLDF "distinguishedName: CN=5592405.0B90E7EB17BAFEFAD4883EF0347C4191,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,$defaultNamingContext"
	add-content $templateLDF "instanceType: 4"
	add-content $templateLDF "whenCreated: 20070907230041.0Z"
	add-content $templateLDF "whenChanged: 20070907230041.0Z"
	add-content $templateLDF "displayName: Mediaroom Server Identity"
	add-content $templateLDF "uSNCreated: 16459"
	add-content $templateLDF "uSNChanged: 16461"
	add-content $templateLDF "showInAdvancedViewOnly: TRUE"
	add-content $templateLDF "name: 5592405.0B90E7EB17BAFEFAD4883EF0347C4191"
	add-content $templateLDF "flags: 3"
	add-content $templateLDF "objectCategory: CN=ms-PKI-Enterprise-Oid,CN=Schema,CN=Configuration,$defaultNamingContext"
	add-content $templateLDF "msPKI-Cert-Template-OID: 1.2.840.113556.1.6.40.1.2.1"
	
	writeEvent $global:logfile "Setting the Mediaroom OID friendly name with ldifde"
                                
    ldifde -i -f $templateLDFFile

	if ($LASTEXITCODE -ne 0)
	{
		WriteEvent $global:logfile ("Exit code is non-zero value in setMediaroomOIDFriendlyName: $LASTEXITCODE")
		exit -1	   
	}
}
 
########################################################
##  Create ClientServerCertTemplate
##  Description : Create OpsMgr certificate template
##  in : none
##  out: template creation or skip
########################################################

function configureMediaroomClientServerCertTemplate()
{
	trap [Exception]
	{
		WriteEvent $global:logfile ("Error in configureMediaroomClientServerCertTemplate: "+$_.Exception.Message)
		exit -1
	}

	[string]$templateLDFFile = $workingDir + "\MediaroomClientServerTemplate.ldf"
	[string]$CertTemplateName                       = "MediaroomClientServerCertificate"
                
	#get the naming context to add the cert template to
	$rootDSE = [ADSI]"LDAP://RootDSE"
	$defaultNamingContext = $rootDSE.Get("defaultNamingContext")

	#build out the path to the cert
	[string]$templateDN = "CN=$certTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + $defaultNamingContext
	$templateLDAP = [ADSI]"LDAP://$templateDN"

	writeEvent $global:logfile "Checking to see if the certificate template already exists..."
	if ($templateLDAP.cn -eq $null)
	{

					writeEvent $global:logfile "$certTemplateName certificate template does not exist. Creating template."
					#check for an exising LDF
					if (Test-Path $templateLDFFile)
					{
									WriteEvent $global:logfile  "Found existing LDF file. Deleting..."
									Remove-Item -path $templateLDFFile
					}

					#Create the file
					WriteEvent $global:logfile "Creating LDF file"
					$templateLDF = New-Item -type file $templateLDFFile

					#add lines to the file
                                

					add-content $templateLDF "dn: CN=$certTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$defaultNamingContext"
					add-content $templateLDF "changetype: add"
					add-content $templateLDF "objectClass: top"
					add-content $templateLDF "objectClass: pKICertificateTemplate"
					add-content $templateLDF "cn: $certTemplateName"
					add-content $templateLDF "distinguishedName: CN=$certTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$defaultNamingContext"
					add-content $templateLDF "instanceType: 4"
					add-content $templateLDF "displayName: $certTemplateName"
					add-content $templateLDF "showInAdvancedViewOnly: TRUE"
					add-content $templateLDF "name: $certTemplateName"
					add-content $templateLDF "flags: 131649"
					add-content $templateLDF "revision: 100"
					add-content $templateLDF "objectCategory: CN=PKI-Certificate-Template,CN=Schema,CN=Configuration,$defaultNamingContext"
					add-content $templateLDF "pKIDefaultKeySpec: 1"
					add-content $templateLDF "pKIKeyUsage:: oAA="
					add-content $templateLDF "pKIMaxIssuingDepth: 0"
					add-content $templateLDF "pKIExpirationPeriod:: AIByDl3C/f8="
					add-content $templateLDF "pKIOverlapPeriod:: AICmCv/e//8="
					add-content $templateLDF "pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.1"
					add-content $templateLDF "pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2"
					add-content $templateLDF "pKIDefaultCSPs: 1,Microsoft RSA SChannel Cryptographic Provider"
					add-content $templateLDF "msPKI-RA-Signature: 0"
					add-content $templateLDF "msPKI-Enrollment-Flag: 0"
					add-content $templateLDF "msPKI-Private-Key-Flag: 16"
					add-content $templateLDF "msPKI-Certificate-Name-Flag: 1"
					add-content $templateLDF "msPKI-Minimal-Key-Size: 2048"
					add-content $templateLDF "msPKI-Template-Schema-Version: 2"
					add-content $templateLDF "msPKI-Template-Minor-Revision: 2"
					add-content $templateLDF "msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.5140656.2377373.7291310.1077647.6265397.123.14681413.11175396"
					add-content $templateLDF "msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.1"
					add-content $templateLDF "msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.2"

					writeEvent $global:logfile "Installing the template with ldifde"
                                
					ldifde -i -f $templateLDFFile

					writeEvent $global:logfile "Sleeping 60 seconds"
					sleep 60

	}
	else
	{
					writeEvent $global:logfile "Found existing $certTemplateName certificate."
	}


	#delete the template cache
	writeEvent $global:logfile "Deleting the certificate template cache"
	reg delete HKCU\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache /v Timestamp /f
	reg delete HKLM\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache /v Timestamp /f

	writeEvent $global:logfile "Setting the CA to issue this template"
	certutil -setcatemplates +$certTemplateName

	if ($LASTEXITCODE -ne 0)
	{
		WriteEvent $global:logfile ("Exit code is non-zero value in configureMediaroomClientServerCertTemplate: $LASTEXITCODE")
		exit -1	   
	}

} # end function configureMediaroomClientServerCertTemplate()


########################################################
##  Create MediaroomCertTemplate
##  Description : Create Mediaroom IPTVe OID certificate template 
##  in : none
##  out: template creation or skip
########################################################

function configureMediaroomCertTemplate()
{
	trap [Exception]
	{
		WriteEvent $global:logfile ("Error in configureMediaroomCertTemplate: "+$_.Exception.Message)
		exit -1
	}
    [string]$templateLDFFile = $workingDir + "\MediaroomCertTemplate.ldf"
    [string]$CertTemplateName                       = "MediaroomCertificate"
                
    #get the naming context to add the cert template to
    $rootDSE = [ADSI]"LDAP://RootDSE"
    $defaultNamingContext = $rootDSE.Get("defaultNamingContext")

    #build out the path to the cert
    [string]$templateDN = "CN=$certTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + $defaultNamingContext
    $templateLDAP = [ADSI]"LDAP://$templateDN"

    writeEvent $global:logfile "Checking to see if the certificate template already exists..."
    if ($templateLDAP.cn -eq $null)
    {

                    writeEvent $global:logfile "$certTemplateName certificate template does not exist. Creating template."
                    #check for an exising LDF
                    if (Test-Path $templateLDFFile)
                    {
                                    WriteEvent $global:logfile  "Found existing LDF file. Deleting..."
                                    Remove-Item -path $templateLDFFile
                    }

                    #Create the file
                    WriteEvent $global:logfile "Creating LDF file"
                    $templateLDF = New-Item -type file $templateLDFFile

                    #add lines to the file
                                

                    add-content $templateLDF "dn: CN=$certTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$defaultNamingContext"
                    add-content $templateLDF "changetype: add"
                    add-content $templateLDF "objectClass: top"
                    add-content $templateLDF "objectClass: pKICertificateTemplate"
                    add-content $templateLDF "cn: $certTemplateName"
                    add-content $templateLDF "distinguishedName: CN=$certTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$defaultNamingContext"
                    add-content $templateLDF "instanceType: 4"
                    add-content $templateLDF "displayName: $certTemplateName"
                    add-content $templateLDF "showInAdvancedViewOnly: TRUE"
                    add-content $templateLDF "name: $certTemplateName"
                    add-content $templateLDF "flags: 131649"
                    add-content $templateLDF "revision: 100"
                    add-content $templateLDF "objectCategory: CN=PKI-Certificate-Template,CN=Schema,CN=Configuration,$defaultNamingContext"
                    add-content $templateLDF "pKIDefaultKeySpec: 1"
                    add-content $templateLDF "pKIKeyUsage:: oAA="
                    add-content $templateLDF "pKIMaxIssuingDepth: 0"
                    add-content $templateLDF "pKIExpirationPeriod:: AIByDl3C/f8="
                    add-content $templateLDF "pKIOverlapPeriod:: AICmCv/e//8="
                    add-content $templateLDF "pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.1"
                    add-content $templateLDF "pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2"
                    add-content $templateLDF "pKIExtendedKeyUsage: 1.2.840.113556.1.6.40.1.2.1"
                    add-content $templateLDF "pKIDefaultCSPs: 1,Microsoft RSA SChannel Cryptographic Provider"
                    add-content $templateLDF "msPKI-RA-Signature: 0"
                    add-content $templateLDF "msPKI-Enrollment-Flag: 40"
                    add-content $templateLDF "msPKI-Private-Key-Flag: 16"
                    add-content $templateLDF "msPKI-Certificate-Name-Flag: 1207959552"
                    add-content $templateLDF "msPKI-Minimal-Key-Size: 2048"
                    add-content $templateLDF "msPKI-Template-Schema-Version: 2"
                    add-content $templateLDF "msPKI-Template-Minor-Revision: 2"
                    add-content $templateLDF "msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.6971055.6418846.5524922.5044298.13501444.118.8811440.5592405"
                    add-content $templateLDF "msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.1"
                    add-content $templateLDF "msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.2"
                    add-content $templateLDF "msPKI-Certificate-Application-Policy: 1.2.840.113556.1.6.40.1.2.1"

                    writeEvent $global:logfile "Installing the template with ldifde"

                    ldifde -i -f $templateLDFFile

                    writeEvent $global:logfile "Sleeping 60 seconds"
                    sleep 60

    }
    else
    {
                    writeEvent $global:logfile "Found existing $certTemplateName certificate."
    }


    #delete the template cache
    writeEvent $global:logfile "Deleting the certificate template cache"
    reg delete HKCU\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache /v Timestamp /f
    reg delete HKLM\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache /v Timestamp /f

    writeEvent $global:logfile "Setting the CA to issue this template"
    certutil -setcatemplates +$certTemplateName

	if ($LASTEXITCODE -ne 0)
	{
		WriteEvent $global:logfile ("Exit code is non-zero value in configureMediaroomCertTemplate: $LASTEXITCODE")
		exit -1	   
	}

}# end function configureMediaroomCertTemplate()


########################################################
##  Create MediaroomCFCertTemplate
##  Description : Create Mediaroom Client Facing IPTVe OID certificate template 
##  in : none
##  out: template creation or skip
########################################################

function configureMediaroomCFCertTemplate()
{
	trap [Exception]
	{
		WriteEvent $global:logfile ("Error in configureMediaroomCFCertTemplate: "+$_.Exception.Message)
		exit -1
	}

    [string]$templateLDFFile = $workingDir + "\MediaroomCFCertTemplate.ldf"
    [string]$CertTemplateName                       = "MediaroomClientFacingCertificate"
                
    #get the naming context to add the cert template to
    $rootDSE = [ADSI]"LDAP://RootDSE"
    $defaultNamingContext = $rootDSE.Get("defaultNamingContext")

    #build out the path to the cert
    [string]$templateDN = "CN=$certTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + $defaultNamingContext
    $templateLDAP = [ADSI]"LDAP://$templateDN"

    writeEvent $global:logfile "Checking to see if the certificate template already exists..."
    if ($templateLDAP.cn -eq $null)
    {

                    writeEvent $global:logfile "$certTemplateName certificate template does not exist. Creating template."
                    #check for an exising LDF
                    if (Test-Path $templateLDFFile)
                    {
                                    WriteEvent $global:logfile  "Found existing LDF file. Deleting..."
                                    Remove-Item -path $templateLDFFile
                    }

                    #Create the file
                    WriteEvent $global:logfile "Creating LDF file"
                    $templateLDF = New-Item -type file $templateLDFFile

                    #add lines to the file
                                

                    add-content $templateLDF "dn: CN=$certTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$defaultNamingContext"
                    add-content $templateLDF "changetype: add"
                    add-content $templateLDF "objectClass: top"
                    add-content $templateLDF "objectClass: pKICertificateTemplate"
                    add-content $templateLDF "cn: $certTemplateName"
                    add-content $templateLDF "distinguishedName: CN=$certTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$defaultNamingContext"
                    add-content $templateLDF "instanceType: 4"
                    add-content $templateLDF "displayName: $certTemplateName"
                    add-content $templateLDF "showInAdvancedViewOnly: TRUE"
                    add-content $templateLDF "name: $certTemplateName"
                    add-content $templateLDF "flags: 131649"
                    add-content $templateLDF "revision: 100"
                    add-content $templateLDF "objectCategory: CN=PKI-Certificate-Template,CN=Schema,CN=Configuration,$defaultNamingContext"
                    add-content $templateLDF "pKIDefaultKeySpec: 1"
                    add-content $templateLDF "pKIKeyUsage:: oAA="
                    add-content $templateLDF "pKIMaxIssuingDepth: 0"
                    add-content $templateLDF "pKIExpirationPeriod:: AIByDl3C/f8="
                    add-content $templateLDF "pKIOverlapPeriod:: AICmCv/e//8="
                    add-content $templateLDF "pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.1"
                    add-content $templateLDF "pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2"
                    add-content $templateLDF "pKIExtendedKeyUsage: 1.2.840.113556.1.6.40.1.2.1"
                    add-content $templateLDF "pKIDefaultCSPs: 1,Microsoft RSA SChannel Cryptographic Provider"
                    add-content $templateLDF "msPKI-RA-Signature: 0"
                    add-content $templateLDF "msPKI-Enrollment-Flag: 40"
                    add-content $templateLDF "msPKI-Private-Key-Flag: 16"
                    add-content $templateLDF "msPKI-Certificate-Name-Flag: 1207959552"
                    add-content $templateLDF "msPKI-Minimal-Key-Size: 2048"
                    add-content $templateLDF "msPKI-Template-Schema-Version: 2"
                    add-content $templateLDF "msPKI-Template-Minor-Revision: 2"
                    add-content $templateLDF "msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.6971055.6418846.5524922.5044298.13501444.118.8811440.5592406"
                    add-content $templateLDF "msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.1"
                    add-content $templateLDF "msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.2"
                    add-content $templateLDF "msPKI-Certificate-Application-Policy: 1.2.840.113556.1.6.40.1.2.1"

                    writeEvent $global:logfile "Installing the template with ldifde"

                    ldifde -i -f $templateLDFFile
                                
                    writeEvent $global:logfile "Sleeping 60 seconds"
                    sleep 60

    }
    else
    {
                    writeEvent $global:logfile "Found existing $certTemplateName certificate."
    }


    #delete the template cache
    writeEvent $global:logfile "Deleting the certificate template cache"
    reg delete HKCU\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache /v Timestamp /f
    reg delete HKLM\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache /v Timestamp /f

    writeEvent $global:logfile "Setting the CA to issue this template"
    certutil -setcatemplates +$certTemplateName

	if ($LASTEXITCODE -ne 0)
	{
		WriteEvent $global:logfile ("Exit code is non-zero value in configureMediaroomCFCertTemplate: $LASTEXITCODE")
		exit -1	   
	}

} #end function configureMediaroomCFCertTemplate()


########################################################
##  Create SSLUserTemplate
##  Description : Create Mediaroom Client Facing IPTVe OID certificate template 
##  in : none
##  out: template creation or skip
########################################################

function configureSSLUserTemplate()
{
	trap [Exception]
	{
		WriteEvent $global:logfile ("Error in configureSSLUserTemplate: "+$_.Exception.Message)
		exit -1
	}
    [string]$templateLDFFile = $workingDir + "\SSLUserTemplate.ldf"
    [string]$CertTemplateName                       = "MediaroomSSLUserCertificate"
                
    #get the naming context to add the cert template to
    $rootDSE = [ADSI]"LDAP://RootDSE"
    $defaultNamingContext = $rootDSE.Get("defaultNamingContext")

    #build out the path to the cert
    [string]$templateDN = "CN=$certTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + $defaultNamingContext
    $templateLDAP = [ADSI]"LDAP://$templateDN"

    writeEvent $global:logfile "Checking to see if the certificate template already exists..."
    if ($templateLDAP.cn -eq $null)
    {

                    writeEvent $global:logfile "$certTemplateName certificate template does not exist. Creating template."
                    #check for an exising LDF
                    if (Test-Path $templateLDFFile)
                    {
                                    WriteEvent $global:logfile  "Found existing LDF file. Deleting..."
                                    Remove-Item -path $templateLDFFile
                    }

                    #Create the file
                    WriteEvent $global:logfile "Creating LDF file"
                    $templateLDF = New-Item -type file $templateLDFFile

                    #add lines to the file
                                

                    add-content $templateLDF "dn: CN=$certTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$defaultNamingContext"
                    add-content $templateLDF "changetype: add"
                    add-content $templateLDF "objectClass: top"
                    add-content $templateLDF "objectClass: pKICertificateTemplate"
                    add-content $templateLDF "cn: $certTemplateName"
                    add-content $templateLDF "distinguishedName: CN=$certTemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$defaultNamingContext"
                    add-content $templateLDF "instanceType: 4"
                    add-content $templateLDF "displayName: $certTemplateName"
                    add-content $templateLDF "showInAdvancedViewOnly: TRUE"
                    add-content $templateLDF "name: $certTemplateName"
                    add-content $templateLDF "flags: 131649"
                    add-content $templateLDF "revision: 100"
                    add-content $templateLDF "objectCategory: CN=PKI-Certificate-Template,CN=Schema,CN=Configuration,$defaultNamingContext"
                    add-content $templateLDF "pKIDefaultKeySpec: 1"
                    add-content $templateLDF "pKIKeyUsage:: oAA="
                    add-content $templateLDF "pKIMaxIssuingDepth: 0"
                    add-content $templateLDF "pKIExpirationPeriod:: AIByDl3C/f8="
                    add-content $templateLDF "pKIOverlapPeriod:: AICmCv/e//8="
                    add-content $templateLDF "pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.1"
                    add-content $templateLDF "pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2"
                    add-content $templateLDF "pKIExtendedKeyUsage: 1.3.6.1.4.1.311.10.3.4"
                    add-content $templateLDF "pKIDefaultCSPs: 1,Microsoft Enhanced Cryptographic Provider v1.0"
                    add-content $templateLDF "msPKI-RA-Signature: 0"
                    add-content $templateLDF "msPKI-Enrollment-Flag: 0"
                    add-content $templateLDF "msPKI-Private-Key-Flag: 16"
                    add-content $templateLDF "msPKI-Certificate-Name-Flag: 1"
                    add-content $templateLDF "msPKI-Minimal-Key-Size: 2048"
                    add-content $templateLDF "msPKI-Template-Schema-Version: 2"
                    add-content $templateLDF "msPKI-Template-Minor-Revision: 2"
                    add-content $templateLDF "msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.5252110.5918962.7684521.10209155.7836277.230.11793316.4864434"
                    add-content $templateLDF "msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.1"
                    add-content $templateLDF "msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.2"
                    add-content $templateLDF "msPKI-Certificate-Application-Policy: 1.3.6.1.4.1.311.10.3.4"

                    writeEvent $global:logfile "Installing the template with ldifde"

                    ldifde -i -f $templateLDFFile

                    writeEvent $global:logfile "Sleeping 60 seconds"
                    sleep 60

    }
    else
    {
                    writeEvent $global:logfile "Found existing $certTemplateName certificate."
    }


    #delete the template cache
    writeEvent $global:logfile "Deleting the certificate template cache"
    reg delete HKCU\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache /v Timestamp /f
    reg delete HKLM\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache /v Timestamp /f

    writeEvent $global:logfile "Setting the CA to issue this template"
    certutil -setcatemplates +$certTemplateName

	if ($LASTEXITCODE -ne 0)
	{
		WriteEvent $global:logfile ("Exit code is non-zero value in configureSSLUserTemplate: $LASTEXITCODE")
		exit -1	   
	}

} #end function configureSSLUserTemplate()




##################################################################
##
## configureCertEnrollmentV2
## in:  none
## out: none
##################################################################
function configureCertEnrollmentV2() 
{

	trap [Exception]
	{
		WriteEvent $global:logfile ("Error in configureCertEnrollmentV2: "+$_.Exception.Message)
		exit -1
	}
	$branchAutoenroll = "CGSG","SFSG","SFBR","BMGMT","TSERV","DSERV","HPNR","VSERV","MDSSF","MDSPF","PFSF","MMGMT","PFAPPS","MDSCF","MDSING","MDSFE","TSSERV"
	$CFAutoenroll = "SYNC","CFSG"
	$BackendAutoenroll = "ASERV","AMGMT","ACTRL","VCTRL","VCRT","VMGMT","RSERV","MDIST"

	$strFilter = "(&(objectCategory=Computer))"

	$objDomain = New-Object System.DirectoryServices.DirectoryEntry
	$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
	$objSearcher.SearchRoot = $objDomain
	$objSearcher.PageSize = 1000
	$objSearcher.Filter = $strFilter
	$objSearcher.SearchScope = "Subtree"

	$colProplist = "name"
	foreach ($i in $colPropList){$objSearcher.PropertiesToLoad.Add($i)}

	$colResults = $objSearcher.FindAll()	

	## configure MediaroomCertificate group

	$branchldapstring="CN=MediaroomCertificate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + $objdomain.distinguishedName
	#build BranchAD group for acls
	WriteEvent $global:logfile  "Building MediaroomAutoEnroll Domain Group"
	$cmd="net localgroup /domain MediaroomAutoEnroll /add /comment:`"Mediaroom machines that receive autoenrolled certificates`""
	cmd /c $cmd
	start-sleep 5
	WriteEvent $global:logfile "branchldapstring = $branchldapstring"
	WriteEvent $global:logfile "Granting Access to MediaroomAutoEnroll group."
	$msg = dsacls `"$branchldapstring`" /G `"MediaroomAutoEnroll:GA`"
	WriteEvent $global:logfile $msg
	#   Add branch machines to MediaroomAutoEnroll group 
	WriteEvent $global:logfile "Add branch machines to MediaroomAutoEnroll group" 

	foreach ($objResult in $colResults)
	{          
		$objItem = $objResult.Properties 
		foreach ($role in $branchAutoenroll)
		{
			$myrole = "*" + $role + "*"
			$machinename=$objItem.name
			$msg = "checking " + $machinename + " -like $myrole"
			WriteEvent $global:logfile $msg 
			if ($objItem.name -like $myrole)
			{
        		WriteEvent $global:logfile  "Adding $machinename to MediaroomAutoEnroll Group"
				$cmd="net localgroup /domain MediaroomAutoEnroll " + $machinename + "$ /add"
				WriteEvent $global:logfile $cmd
				cmd /c $cmd                                
			}
		}              
	}

	#   Add backend machines to MediaroomAutoEnroll group 
	WriteEvent $global:logfile  "Add backend machines to MediaroomAutoEnroll group"
	foreach ($objResult in $colResults)
    {          
		$objItem = $objResult.Properties 
        foreach ($role in $backendAutoenroll)
        {
			$myrole = "*" + $role + "*"
            $machinename=$objItem.name
            $msg = "checking " + $machinename + " -like $myrole"
            WriteEvent $global:logfile $msg 
            if ($objItem.name -like $myrole)
            {
				$machinename=$objItem.name
                WriteEvent $global:logfile "Adding $machinename to MediaroomAutoEnroll Group"
                $cmd="net localgroup /domain MediaroomAutoEnroll " + $machinename + "$ /add"
                WriteEvent $global:logfile  $cmd
                cmd /c $cmd
                break
			}
		}
	}


	##################################################################
	##
	## configure MediaroomClientFacingCertificate group

	$branchldapstring="CN=MediaroomClientFacingCertificate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + $objdomain.distinguishedName
	#build BranchAD group for acls
	WriteEvent $global:logfile  "Building MediaroomCFAutoEnroll Domain Group"
	$cmd="net localgroup /domain MediaroomCFAutoEnroll /add /comment:`"Mediaroom Client Facing machines that receive autoenrolled certificates`""
	cmd /c $cmd
	start-sleep 5
	WriteEvent $global:logfile  "Granting Access to MediaroomCFAutoEnroll group."
	$msg = dsacls `"$branchldapstring`" /G `"MediaroomCFAutoEnroll:GA`"
	WriteEvent $global:logfile $msg

	foreach ($objResult in $colResults)
	{          
		$objItem = $objResult.Properties 
		foreach ($role in $cfAutoenroll)
		{
			$myrole = "*" + $role + "*"
			$machinename=$objItem.name
			$msg = "checking " + $machinename + " -like $myrole"
			WriteEvent $global:logfile $msg 
			if ($objItem.name -like $myrole)
			{
				$machinename=$objItem.name
				WriteEvent $global:logfile  "Adding $machinename to MediaroomCFAutoEnroll Group"
				$cmd="net localgroup /domain MediaroomCFAutoEnroll " + $machinename + "$ /add"
				WriteEvent $global:logfile  $cmd
				cmd /c $cmd
				break
			}
		}              
	}


	if ($LASTEXITCODE -ne 0)
	{
		WriteEvent $global:logfile ("Exit code is non-zero value in configureCertEnrollmentV2: $LASTEXITCODE")
		##exit -1	   
	}
} #end function configureCertEnrollmentV2() 


####################################################################################
##
##

function setPermissionsOnsWebServerTemplate
{
	trap [Exception]
	{
		WriteEvent $global:logfile ("Error in setPermissionsOnsWebServerTemplate: "+$_.Exception.Message)
		exit -1
	}
    $objDomain = New-Object System.DirectoryServices.DirectoryEntry
    $branchldapstring="CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + $objdomain.distinguishedName
    #build BranchAD group for acls
    WriteEvent $global:logfile  "Giving SYSTEM full control of Web Server template"

    start-sleep 5
    WriteEvent $global:logfile "branchldapstring = $branchldapstring"
    $msg = dsacls `"$branchldapstring`" /G `"SYSTEM:GA`"
    WriteEvent $global:logfile $msg

	if ($LASTEXITCODE -ne 0)
	{
		WriteEvent $global:logfile ("Exit code is non-zero in setPermissionsOnsWebServerTemplate: $LASTEXITCODE")
		exit -1	   
	}
}

####################################################################################
##
## Main entry point
##
####################################################################################

########################################################
## 
## init variables

#valid values for caProfile are:
# 1 - This script is executing on the branch CA, and CF CA will exist in the environment
# 2 - This script is executing on Client Facing CA (separate CFCA exists, AKA "enhanced PKI" configuration)
# 3 - This script is executing on the branch CA, and CF CA will NOT exist (there is not a separate Client Facing CA in the branch)
# 4 - This script is executing on the backend CA / or for a Single Domain environment (Branch/Backend CA)

# caProfile must be specified as an argument to the script
$caProfile = $args[0]

# if running script interactively, then domain FQDN and SCCM server must be specified at commandline
# if running in SCCM, these will be overwritten with TS variables
[string]$domainfqdn = $args[1]
[string]$sccmServer= $args[2]


$dotRoot="C:\MRDOT"
$workingDir = "c:\MRDOT"

New-Item -path ENV:drkROOT -value $dotRoot -force
New-Item -path ENV:dotROOT -value $dotRoot -force

####################
#initialize the libraries
if (test-path "$dotRoot\Libraries\Microsoft.Mediaroom.DOT.WindowsConfiguration.ps1")
{
                . "$dotRoot\Libraries\Microsoft.Mediaroom.DOT.WindowsConfiguration.ps1"
}
else
{
                WriteEvent $global:logfile "Unable to find library $dotRoot\Libraries\Microsoft.Mediaroom.DOT.WindowsConfiguration.ps1"
                Exit 1
}

if (test-path "$dotRoot\Libraries\Microsoft.Mediaroom.DOT.Logging.ps1")
{
                . "$dotRoot\Libraries\Microsoft.Mediaroom.DOT.Logging.ps1"
}
else
{
                WriteEvent $global:logfile "Unable to find library $dotRoot\Libraries\Microsoft.Mediaroom.DOT.Logging.ps1"
                Exit 1
}
if (test-path "$dotRoot\Libraries\Microsoft.Mediaroom.DOT.ActiveDirectory.ps1")
{
                . "$dotRoot\Libraries\Microsoft.Mediaroom.DOT.ActiveDirectory.ps1"
}
else
{
                WriteEvent $global:logfile "Unable to find library $dotRoot\Libraries\Microsoft.Mediaroom.DOT.ActiveDirectory.ps1"
                Exit 1
}



####################
#Setup Logging

[string]$global:logFile = "$dotRoot\Logs\os-ca.postinstall.log"
CreateLogFile $global:logfile
writeEvent $global:logfile "Setting up logging"


WriteEvent $global:logfile ""
WriteEvent $global:logfile "***New Installation Started***"
WriteEvent $global:logfile "Running script as $env:userdomain\$env:username"


$domainarray = $domainfqdn.split(".".tochararray())
$dom = [System.DirectoryServices.ActiveDirectory.Domain]::getcurrentdomain()
$branch=$dom.name
WriteEvent $global:logfile "domain = $dom"
WriteEvent $global:logfile "Branch = $branch"

$ldapstring="CN=configuration,"
for($x=0;$x -lt $domainarray.length ; $x++)
{
                if($x -eq $domainarray.length-1)
                {
                                $ldapstring=$ldapstring + " DC=" + $domainarray[$x]
                }
                else
                {
                                $ldapstring=$ldapstring + " DC=" + $domainarray[$x] + ","
                }
}



#Turn all the ConfigMgr Variables into Powershell Variables
#Create Task Sequence Environment object
$tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment

# Convert the task sequence variables into PowerShell variables 
$tsenv.GetVariables() | % { Set-Variable -Name "$_" -Value "$($tsenv.Value($_))" } 



if ($_SMSTSPackageID -ne $null) #we are running within an SCCM task sequence
{

                WriteEvent $global:logfile  "_SMSTSPackageID -ne null, we think we are inside an SCCM sequence"
                #Turn all the ConfigMgr Variables into Powershell Variables
                #Create Task Sequence Environment object
                $tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
                
                # Convert the task sequence variables into PowerShell variables 
                $tsenv.GetVariables() | % { Set-Variable -Name "$_" -Value "$($tsenv.Value($_))" } 
                
                [string]$domainfqdn = $WinDomainDNSName
                [string]$sccmServer=$_SMSTSMP
}
else #we are not running within an SCCM task sequence, set these variables manually
{
                
                WriteEvent $global:logfile  "We are not running within a task sequence - the following variables were set within the script"

}# end if ($_SMSTSPackageID -ne $null)

# Lets make sure we have all out variables populated before continuing
if ($caProfile.length  -eq 0) {ERROR! caProfile is BLANK!;show-help}
else {     WriteEvent $global:logfile "caProfile = $caProfile"}

if ($domainfqdn.length  -eq 0) { ERROR! domainfqdn is BLANK!;show-help}
else {     WriteEvent $global:logfile "domainfqdn = $domainfqdn"}

if ($sccmServer.length  -eq 0) {WriteEvent $global:logfile "ERROR! sccmServer is BLANK!";show-help}
else { WriteEvent $global:logfile "sccmServer = $sccmServer"}



$msg = "ldapstring = " + $ldapstring
WriteEvent $global:logfile $msg



#########################################################
## ensure certificate services are installed
$certsvc = get-service | where{$_.name -eq "certsvc"}
if ($certsvc -eq $null)
                {$errmsg = "error - certificate services are not installed"
                writeEvent $global:logfile $errmsg
                Throw $errmsg
                }
                                
$vars = get-variable

WriteEvent $global:logfile "DUMPING all variables available to script:"
foreach ($v in $vars)
                {
                if ($v.name -ne "vars")
                {
                
                                $nval = "Name: " + $v.name
                                $vval = " Value: " + $v.value
                                WriteEvent $global:logfile $nval
                                WriteEvent $global:logfile $vval
                  }
                }
 
#Declare Configuration NC
certutil -setreg CA\DSConfigDN $ldapstring
#Define CRL Publication Intervals
certutil -setreg CA\CRLPeriodUnits 26
certutil -setreg CA\CRLPeriod "Weeks"
certutil -setreg CA\CRLDeltaPeriodUnits 0
certutil -setreg CA\CRLDeltaPeriod "Days"
#Enable all auditing events for the Issuing CA
certutil -setreg CA\AuditFilter 127
#Set Validity Period for Issued Certificates
certutil -setreg CA\ValidityPeriodUnits 2
certutil -setreg CA\ValidityPeriod "Years"
#Restart Certificate Services
#net stop certsvc
#net start certsvc
#start-sleep 20
certutil -crl
reg delete HKCU\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache /v Timestamp /f
reg delete HKLM\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache /v Timestamp /f




# If caProfile 1 then Branch issuing CA. Add only MediaroomCertTemplate
if($caProfile -eq 1)
{
                WriteEvent $global:logfile "caProfile 1 Installing MediaroomCertTemplate"
                configureMediaroomCertTemplate
                configureMediaroomClientServerCertTemplate
}
#if caProfile=2 then CF issuing CA. Add MediaroomCFCertTemplate
elseif($caProfile -eq 2)
{
                WriteEvent $global:logfile  "caProfile 2 Installing MediaroomCFCertTemplate"
                configureMediaroomCFCertTemplate
                
}
# if caProfile=3 then Branch issuing is the only CA. Add both templates.
elseif ($caProfile -eq 3)
{
                WriteEvent $global:logfile  "caProfile 3 Installing MediaroomCertTemplate and MediaroomCFCertTemplate"
                configureMediaroomCFCertTemplate
                configureMediaroomCertTemplate
                
}


# If caProfile 4 then Backend issuing CA. Add MediaroomCertTemplate, SSLUserTemplate, ClientServerCertTemplate
elseif($caProfile -eq 4)
{
                WriteEvent $global:logfile  "caProfile 4 Installing MediaroomCertTemplates for backend (or Branch/Backend in Single Domain Environment)"
                configureMediaroomCertTemplate
                configureSSLUserTemplate
                configureMediaroomClientServerCertTemplate
    			setPermissionsOnsWebServerTemplate
				setMediaroomOIDFriendlyName
}

Else 
{
show-help
}

configureCertEnrollmentV2

$compName = [Environment]::MachineName;
AddMemberToGroup "CN=$compName,OU=Member Servers" "CN=Cert Publishers,CN=Users"

WriteEvent $global:logfile  "Next steps:"
WriteEvent $global:logfile  "Step 1 - publish the root CA certificate into AD via certutil -f -dspublish root.cer"
WriteEvent $global:logfile  "Step 2 - Setup Autoenrollment via GPO"
