function Invoke-vCDNSXRestMethod {

    [CmdletBinding(DefaultParameterSetName="BearerAuth")]

    param (
        [Parameter (Mandatory=$true,ParameterSetName="BasicAuth")]
            #PSCredential object containing authentication details to be used for connection to vCloud Director API
            [System.Management.Automation.PSCredential]$cred,
        [Parameter (Mandatory=$true,ParameterSetName="BasicAuth")]
            #vCloud Director ip address or FQDN
            [string]$server,
        [Parameter (Mandatory=$true,ParameterSetName="BasicAuth")]
            #TCP Port on -server to connect to
            [int]$port,
        [Parameter (Mandatory=$true,ParameterSetName="BasicAuth")]
            #Protocol - HTTP/HTTPS
            [string]$protocol,
        [Parameter (Mandatory=$false,ParameterSetName="BasicAuth")]
            #Validates the certificate presented by vCloud Director for HTTPS connections
            [bool]$ValidateCertificate,
        [Parameter (Mandatory=$true,ParameterSetName="BasicAuth")]
        [Parameter (ParameterSetName="BearerAuth")]
            #REST method of call.  Get, Put, Post, Delete, Patch etc
            [string]$method,
        [Parameter (Mandatory=$true,ParameterSetName="BasicAuth")]
        [Parameter (ParameterSetName="BearerAuth")]
            #URI of resource (/api/sessions).  Should not include protocol, server or port.
            [string]$URI,
        [Parameter (Mandatory=$false,ParameterSetName="BasicAuth")]
        [Parameter (ParameterSetName="BearerAuth")]
            #Content to be sent to server when method is Put/Post/Patch
            [string]$body = "",
            [Parameter (Mandatory=$false,ParameterSetName="BasicAuth")]
        [Parameter (ParameterSetName="BearerAuth")]
            #Set acceptable API version
            [Validateset("v8.2","v9.0","v9.1","v9.5","v9.7","v10.0")]
            [string]$vCDversion,
        [Parameter (Mandatory=$false,ParameterSetName="BearerAuth")]
            #Pre-populated connection object as returned by Connect-vCDNSX
            [psObject]$connection,
        [Parameter (Mandatory=$false,ParameterSetName="BearerAuth")]
            #Hashtable collection of KV pairs representing additional headers to send to the NSX-T Manager during REST call
            [System.Collections.Hashtable]$extraheader,
        [Parameter (Mandatory=$false,ParameterSetName="BearerAuth")]
            #Request timeout value - passed directly to underlying invoke-restmethod call
            [int]$Timeout=600
    )

    Write-Debug "$($MyInvocation.MyCommand.Name) : ParameterSetName : $($pscmdlet.ParameterSetName)"

    if ($pscmdlet.ParameterSetName -eq "BasicAuth") {
        #write-host "using basic-authentication"
        if ( -not $ValidateCertificate) {
            #allow untrusted certificate presented by the remote system to be accepted
            #[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
        $headerDictionary = @{}
        $base64cred = [system.convert]::ToBase64String([system.text.encoding]::ASCII.Getbytes("$($cred.GetNetworkCredential().username)@$($cred.GetNetworkCredential().Domain):$($cred.GetNetworkCredential().password)"))
        $headerDictionary.add("Authorization", "Basic $Base64cred")
    }
    else {
        #write-host "using Bearer-authentication"
        #ensure we were either called with a connection or there is a defaultConnection (user has
        #called connect-nsxserver)
        #Little Grr - $connection is a defined variable with no value so we cant use test-path
        if (!$connection) {

            #Now we need to assume that DefaultvCDNSXConnection does not exist...
            if (!$DefaultvCDNSXonnection) {
                throw "Not connected.  Connect to vCloud Director with Connect-vCSNSXAPI first."
            }
            else {
                #Write-host "$($MyInvocation.MyCommand.Name) : Using default connection"
                $connection = $DefaultvCDNSXonnection
            }
        }
        $headerDictionary = @{}
        $headerDictionary.add("Authorization", "Bearer $($connection.BearerAccessToken)")
        $server = $connection.Server
        $port = $connection.Port
        $protocol = $connection.Protocol
    }


    if ( $pscmdlet.ParameterSetName -eq "BearerAuth" ) {
        $headerDictionary += $connection.Headers
        
    } else {
        if ($vCDversion) {
            switch ($vCDversion) {
                "v8.2" {$headerDictionary.add("accept", "application/*+xml;version=27.0")}
                "v9.0" {$headerDictionary.add("accept", "application/*+xml;version=29.0")}
                "v9.1" {$headerDictionary.add("accept", "application/*+xml;version=30.0")}
                "v9.5" {$headerDictionary.add("accept", "application/*+xml;version=31.0")}
                "v9.7" {$headerDictionary.add("accept", "application/*+xml;version=32.0")}
                "v10.0" {$headerDictionary.add("accept", "application/*+xml;version=33.0")}
            }
        } elseif ($extraheader) {
            $extraheader | ForEach-Object {$headerDictionary.add($_)}
        }
    }
    $headerDictionary.add("Content-Type", "application/xml")
    $FullURI = "$($protocol)://$($server):$($Port)$($URI)"
    write-debug "$($MyInvocation.MyCommand.Name) : Method: $method, URI: $FullURI, Body: `n$($body )"
    
    #do rest call
    write-host "executing $($Method) : $($FullURI)"
        try {
        if ( $PsBoundParameters.ContainsKey('Body')) {
            $response = invoke-restmethod -method $method -headers $headerDictionary -uri $FullURI -body $body -TimeoutSec $Timeout -SkipCertificateCheck -ResponseHeadersVariable responseHeaders
        } else {
            $response = invoke-restmethod -method $method -uri $FullURI -headers $headerDictionary -TimeoutSec $Timeout -SkipCertificateCheck -ResponseHeadersVariable responseHeaders
            
        }
    }
    catch {
        #Get response from the exception
        $return = $_.exception.response
     }
    #switch ( $response ) {
    #    { $_ -is [xml] } { $FormattedResponse = "`n$($response.outerxml | Format-Xml)" }
    #    #{ $_ -is [System.String] } { $FormattedResponse = $response }
    ##    #{ $_ -is [json] } { $FormattedResponse = $response }
    #    default { $formattedResponse = "Response type unknown" }
    #}
    #$FormattedResponse = $response 

    write-debug "$($MyInvocation.MyCommand.Name) : Response: $FormattedResponse"
    if ( $pscmdlet.ParameterSetName -eq "BearerAuth" ) {
        if ( $connection.DebugLogging ) {
            Add-Content -Path $Connection.DebugLogfile -Value "$(Get-Date -format s)  Response: $FormattedResponse"
        }
    }

    #Workaround for bug in invoke-restmethod where it doesnt complete the tcp session close to our server after certain calls.
    #We end up with connectionlimit number of tcp sessions in close_wait and future calls die with a timeout failure.
    #So, we are getting and killing active sessions after each call.  Not sure of performance impact as yet - to test
    #and probably rewrite over time to use invoke-webrequest for all calls... PiTA!!!! :|

    $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($FullURI)
    $ServicePoint.CloseConnectionGroup("") | out-null
    write-debug "$($MyInvocation.MyCommand.Name) : Closing connections to $FullURI."
    
    $return = [PSCustomObject]@{
        xml     = [xml]$response.outerxml
        Session = $response.Session
        Headers = $responseHeaders
    }
    #Return
    $return
}


function Connect-vCDNSXAPI {

param (
        [Parameter (Mandatory=$true)]
            #vCloud Director ip address or FQDN
            [string]$Server,
        [Parameter (Mandatory=$false)]
            #TCP Port on -server to connect to
            [int]$Port="443",
        [Parameter (Mandatory=$false)]
            #Protocol - HTTP/HTTPS
            [string]$Protocol="https",
        [Parameter (Mandatory=$true)]
            #username and password
            [System.Management.Automation.PSCredential]$cred,
        [Parameter (Mandatory=$true)]
            #domain/tenantIT
            [string]$TenantID
    )

    $secpasswd = ConvertTo-SecureString $($cred.GetNetworkCredential().password) -AsPlainText -Force
    if (!$cred.GetNetworkCredential().Domain) {
        if (!$TenantID) {
            Write-Host "No Tenant specified! please add Domain/TenantID"
        } else {
            $username = "$($cred.GetNetworkCredential().username)"+"@"+"$($TenantID)"
        }
    } else {
        $username = "$($cred.GetNetworkCredential().username)"
    }
    $vCDcredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)

    
    try {
        $response = Invoke-vCDNSXRestMethod -server $Server -port $port -protocol $Protocol -cred $vCDcredential -method post -URI "/api/sessions" -vCDversion v9.5
    }
    catch {

        Throw "Unable to connect to vCloud Director at $Server.  $_"
    }
    
    if ($response.Headers.'X-VMWARE-VCLOUD-ACCESS-TOKEN') {
        
        $headers = @{}
        [string]$contenttype = $response.Headers.'Content-Type'
        $vCDversion = ($contenttype).Substring($contenttype.IndexOf('=')+1,4)
        write-host -ForegroundColor Yellow "Succesfully connected to vCloud Director at $($Server) with API version $($vCDversion)"
        switch ($vCDversion) {
            "27.0" {$headers.add("accept", "application/*+xml;version=27.0")}
            "29.0" {$headers.add("accept", "application/*+xml;version=29.0")}
            "30.0" {$headers.add("accept", "application/*+xml;version=30.0")}
            "31.0" {$headers.add("accept", "application/*+xml;version=31.0")}
            "32.0" {$headers.add("accept", "application/*+xml;version=32.0")}
            "33.0" {$headers.add("accept", "application/*+xml;version=33.0")}
        }
        $ConnectionObj = [PSCustomObject]@{
            Server = $Server
            Port = $Port
            Protocol = $Protocol
            Authentication = "Bearer"
            BearerAccessToken = $response.Headers.'X-VMWARE-VCLOUD-ACCESS-TOKEN'
            Headers = $headers
        }
        Set-Variable -Name DefaultvCDNSXonnection -value $ConnectionObj -scope Global
        
    } else {
        Write-Error "Username or Password incorrect"
    }
    $response
}

function Disconnect-vCDNSXAPI {

    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server"
    } else {
        write-host -ForegroundColor Yellow "Connected to (default) vCloud Director server at: $($DefaultvCDNSXonnection.server)"
        $answer = read-host "Are you sure you want to disconnect (y/n)?"
        if ($answer.ToLower() -eq "y") {
            Set-Variable -Name DefaultvCDNSXonnection -value $null -scope Global
            write-host "Succesfully disconnected!"
        }
    }
}

function Get-vCDNSXOrg {

    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $OrgResponse = Invoke-vCDNSXRestMethod -method get -URI "/api/org"
        $OrgGuid = $OrgResponse.xml.OrgList.org.href.substring($OrgResponse.xml.OrgList.org.href.LastIndexOf('/')+1)
        $OrgName = ($OrgResponse.xml).OrgList.Org.name
        $OrgHref = $OrgResponse.xml.OrgList.org.href
        $OrgAPI = $OrgResponse.xml.OrgList.org.href.Substring(($OrgResponse.xml.OrgList.org.href.IndexOf($DefaultvCDNSXonnection.server)+($DefaultvCDNSXonnection.server).Length))
    }
    $OrgResponse = [PSCustomObject]@{
        OrgName = $OrgName
        OrgGUID = $OrgGuid
        Orghref = $OrgHref
        OrgApi  = $OrgAPI 
    }
    $OrgResponse 
}

function Get-vCDNSXOrgVDC {

param (
    [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
    #Vdc Organization GUID
    [string]$OrgGuid
)

    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $VdcResponse = Invoke-vCDNSXRestMethod -method get -URI "/api/admin/org/$($OrgGuid)"
    }

    $vDCReturn = [PSCustomObject]@{
        OrgVdcName = $VdcResponse.xml.AdminOrg.Vdcs.Vdc.name
        OrgVdcHref = $VdcResponse.xml.AdminOrg.Vdcs.Vdc.href
        OrgVdcGuid = $VdcResponse.xml.AdminOrg.Vdcs.Vdc.id.split(":")[3]
    }
    $vDCReturn 
}

function Get-vCDNSXOrgVDCvApp {

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter( Mandatory=$false)] 
        #VM/Vapp object matches VmName
        [string]$vAppName
    )
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        if ($OrgVdcGuid) {
            $OrgVdcvAppResponse = Invoke-vCDNSXRestMethod -method get -URI "/api/vApps/query?vdc=$($OrgVdcGuid)"
        } else {
            $OrgVdcvAppResponse = Invoke-vCDNSXRestMethod -method get -URI "/api/vApps/query"
        }
    }

    $OrgVdcvAppReturn = @()
    foreach ($OrgVdcvAppObject in $OrgVdcvAppResponse.xml.QueryResultRecords.VAppRecord) {

        $OrgVdcvAppsObjectReturn = [PSCustomObject]@{
            OrgVdcvAppName = $OrgVdcvAppObject.name
            OrgVdcvAppOwnerName = $OrgVdcvAppObject.ownerName
            OrgVdcvAppHref = $OrgVdcvAppObject.href
            OrgVdcvAppStatus = $OrgVdcvAppObject.status
            OrgVdcvAppVdc = $OrgVdcvAppObject.vdc
        }
        $OrgVdcvAppReturn += $OrgVdcvAppsObjectReturn
    }
    if ($vAppName) {$OrgVdcvAppReturn = $OrgVdcvAppReturn | Where-Object {$_.OrgVdcvAppName -match $vAppName}}
    $OrgVdcvAppReturn
}

function Get-vCDNSXOrgVDCvAppVM {

    [CmdletBinding(DefaultParameterSetName="OrgVdcvAppHref")]

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false,ParameterSetName="OrgVdcvAppHref")]
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false,ParameterSetName="OrgVdcvAppName")] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter(ValueFromPipelineByPropertyName=$true,Mandatory=$false,ParameterSetName="OrgVdcvAppHref")] 
        #VM/Vapp object matches VmName
        [string]$OrgVdcvAppHref,
        [Parameter( Mandatory=$false,ParameterSetName="OrgVdcvAppName")] 
        #VM/Vapp object matches VmName
        [string]$OrgVdcvAppName
    )
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        if ($pscmdlet.ParameterSetName -eq "OrgVdcvAppHref") {
            $Uri = [system.uri]$OrgVdcvAppHref
            
            $OrgVdcvAppResponse = Invoke-vCDNSXRestMethod -method get -URI $uri.LocalPath
            
        }
        if ($OrgVdcGuid) {
            $OrgVdcvAppResponse = Invoke-vCDNSXRestMethod -method get -URI "/api/vApps/query?vdc=$($OrgVdcGuid)"
        } else {
            $OrgVdcvAppResponse = Invoke-vCDNSXRestMethod -method get -URI "/api/vApps/query"
        }
    }

    $OrgVdcvAppReturn = @()
    foreach ($OrgVdcvAppObject in $OrgVdcvAppResponse.xml.QueryResultRecords.VAppRecord) {

        $OrgVdcvAppsObjectReturn = [PSCustomObject]@{
            OrgVdcvAppName = $OrgVdcvAppObject.name
            OrgVdcvAppOwnerName = $OrgVdcvAppObject.ownerName
            OrgVdcvAppHref = $OrgVdcvAppObject.href
            OrgVdcvAppStatus = $OrgVdcvAppObject.status
            OrgVdcvAppVdc = $OrgVdcvAppObject.vdc
        }
        $OrgVdcvAppReturn += $OrgVdcvAppsObjectReturn
    }
    if ($vAppName) {$OrgVdcvAppReturn = $OrgVdcvAppReturn | Where-Object {$_.OrgVdcvAppName -match $vAppName}}
    $OrgVdcvAppReturn
}


function Get-vCDNSXIpset {

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter( Mandatory=$false)] 
        #IPSet object matches IpSetName
        [string]$IpSetName
    )
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $IpSetObjResponse = Invoke-vCDNSXRestMethod -method get -URI "/network/services/ipset/scope/$($OrgVdcGuid)"
    }

    $IpSetObjectReturn = @()
    foreach ($IpSetXMLObject in $IpSetObjResponse.xml.list.ipset) {

        $IpSetPSObject = [PSCustomObject]@{
            IpSetName = $IpSetXMLObject.name
            IpSetValue = $IpSetXMLObject.value
            IpSetGuid = $IpSetXMLObject.objectId
            IpSetInheritanceAllowed = $IpSetXMLObject.inheritanceAllowed
        }
        $IpSetObjectReturn += $IpSetPSObject
    }
    if ($IpSetName) {$IpSetObjectReturn = $IpSetObjectReturn | Where-Object {$_.IpSetName -match $IpSetName}}
    $IpSetObjectReturn 
}

function Get-vCDNSXMacset {

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter( Mandatory=$false)] 
        #MacSet object matches MacSetName
        [string]$MacSetName
    )
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $MacsetObjResponse = Invoke-vCDNSXRestMethod -method get -URI "/network/services/macset/scope/$($OrgVdcGuid)"
    }

    $MacsetXMLObjectReturn = @()
    foreach ($MacsetXMLObject in $MacsetObjResponse.xml.list.macset) {

        $MacSetPSObject = [PSCustomObject]@{
            MacsetName = $MacsetXMLObject.name
            MacsetValue = $MacsetXMLObject.value
            MacsetGuid = $MacsetXMLObject.objectId
            MacsetInheritanceAllowed = $MacsetXMLObject.inheritanceAllowed
        }
        $MacsetXMLObjectReturn += $MacSetPSObject
    }
    if ($MacSetName) {$MacsetXMLObjectReturn = $MacsetXMLObjectReturn | Where-Object {$_.MacsetName -match $MacSetName}}
    $MacsetXMLObjectReturn 
}

function Get-vCDNSXService {

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter( Mandatory=$false)] 
        #Service object matches ServiceName
        [string]$ServiceName
    )
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $ServiceObjResponse = Invoke-vCDNSXRestMethod -method get -URI "/network/services/application/scope/$($OrgVdcGuid)"
    }

    $ServiceXMLObjectReturn = @()
    foreach ($ServiceXMLObject in $ServiceObjResponse.xml.list.application) {

        $ServicePSObject = [PSCustomObject]@{
            ServiceName = $ServiceXMLObject.name
            ServiceValue = $ServiceXMLObject.element
            ServiceGuid = $ServiceXMLObject.objectId
        }
        $ServiceXMLObjectReturn += $ServicePSObject
    }
    if ($ServiceName) {$ServiceXMLObjectReturn = $ServiceXMLObjectReturn | Where-Object {$_.ServiceName -match $ServiceName}}
    $ServiceXMLObjectReturn 
}

function Get-vCDNSXServiceGroup {

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter( Mandatory=$false)] 
        #ServiceGroup object matches ServiceGroupName
        [string]$ServiceGroupName
    )
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $ServiceGroupObjResponse = Invoke-vCDNSXRestMethod -method get -URI "/network/services/applicationgroup/scope/$($OrgVdcGuid)"
    }

    $ServiceGroupXMLObjectReturn = @()
    foreach ($ServiceGroupXMLObject in $ServiceGroupObjResponse.xml.list.applicationgroup) {

        $ServiceGroupPSObject = [PSCustomObject]@{
            ServiceGroupName = $ServiceGroupXMLObject.name
            ServiceGroupMember = $ServiceGroupXMLObject.member
            ServiceGroupGuid = $ServiceGroupXMLObject.objectId
        }
        $ServiceGroupXMLObjectReturn += $ServiceGroupPSObject
    }
    if ($ServiceGroupName) {$ServiceGroupXMLObjectReturn = $ServiceGroupXMLObjectReturn | Where-Object {$_.ServiceGroupName -match $ServiceGroupName}}
    $ServiceGroupXMLObjectReturn 
}

function Get-vCDNSXSecurityGroup {

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter( Mandatory=$false)] 
        #SecurityGroup object matches SecurityGroupName
        [string]$SecurityGroupName
    )
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method get -URI "/network/services/securitygroup/scope/$($OrgVdcGuid)"
    }

    $SecurityGroupXMLObjectReturn = @()
    foreach ($SecurityGroupXMLObject in $SecurityGroupObjResponse.xml.list.securitygroup) {

        $SecurityGroupPSObject = [PSCustomObject]@{
            SecurityGroupName = $SecurityGroupXMLObject.name
            SecurityGroupMember = $SecurityGroupXMLObject.member
            SecurityGroupGuid = $SecurityGroupXMLObject.objectId
        }
        $SecurityGroupXMLObjectReturn += $SecurityGroupPSObject
    }
    if ($SecurityGroupName) {$SecurityGroupXMLObjectReturn = $SecurityGroupXMLObjectReturn | Where-Object {$_.SecurityGroupName -match $SecurityGroupName}}
    $SecurityGroupXMLObjectReturn 
}

function Get-vCDNSXSecurityTag{

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter( Mandatory=$false)] 
        #Securitytag object matches SecuritytagName
        [string]$SecuritytagName
    )
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $SecuritytagObjResponse = Invoke-vCDNSXRestMethod -method get -URI "/network/services/securitytags/tag/scope/$($OrgVdcGuid)"
    }

    $SecuritytagsXMLObjectReturn = @()
    foreach ($SecuritytagsXMLObject in $SecuritytagObjResponse.xml.securityTags.securityTag) {

        $SecuritytagsPSObject = [PSCustomObject]@{
            SecuritytagName = $SecuritytagsXMLObject.name
            SecuritytagGuid = $SecuritytagsXMLObject.objectId
        }
        $SecuritytagsXMLObjectReturn += $SecuritytagsPSObject
    }
    if ($SecuritytagName) {$SecuritytagsXMLObjectReturn = $SecuritytagsXMLObjectReturn | Where-Object {$_.SecuritytagName -match $SecuritytagName}}

    $SecuritytagsXMLObjectReturn 
}

function Get-vCDNSXSecurityTagVMs{

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        #Security Tag GUID
        [string]$SecuritytagGuid
    )
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $SecuritytagVMObjResponse = Invoke-vCDNSXRestMethod -method get -URI "/network/services/securitytags/tag/$SecuritytagGuid/vm"
    }

    $SecuritytagVmXMLObjectReturn = @()
    foreach ($SecuritytagVmXMLObject in $SecuritytagVMObjResponse.xml.basicinfolist.basicinfo) {

        $SecuritytagVmPSObject = [PSCustomObject]@{
            SecuritytagVmName = $SecuritytagVmXMLObject.name
            SecuritytagVmGuid = $SecuritytagVmXMLObject.objectId
        }
        $SecuritytagVmXMLObjectReturn += $SecuritytagVmPSObject
    }
    $SecuritytagVmXMLObjectReturn 
}


function New-vCDNSXIpset {

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter(Mandatory=$true)] 
        #Name of the IpSet object
        [string]$IpSetName,
        [Parameter( Mandatory=$true)] 
        #Value of the IpSet object
        [string]$IpSetValue,
        [Parameter( Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$Description
    )

    [string] $IpSetBody = '<ipset><description>’ + $description + ‘</description><name>’ + $IpSetName + ‘</name><value>’ + $IpSetValue + ‘</value><inheritanceAllowed>true</inheritanceAllowed></ipset>'
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $IpSetObjResponse = Invoke-vCDNSXRestMethod -method post -URI "/network/services/ipset/$($OrgVdcGuid)" -body $IpSetBody
    }
    if ($IpSetObjResponse.Headers) {Write-host -ForegroundColor Yellow "Successfully created IpSet Object $($IpSetName)"}
    $IpSetObjReturn = Get-vCDNSXIpset -OrgVdcGuid $OrgVdcGuid | Where-Object {$_.IpSetName -eq $IpSetName}
    
    $IpSetObjReturn
}

function New-vCDNSXMacSet {

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter(Mandatory=$true)] 
        #Name of the MacSet object
        [string]$MacSetName,
        [Parameter( Mandatory=$true)] 
        #Value of the MacSet object
        [string]$MacSetValue,
        [Parameter( Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$Description
    )

    [string] $MacSetBody = '<macset><description>’ + $description + ‘</description><name>’ + $MacSetName + ‘</name><value>’ + $MacSetValue + ‘</value><inheritanceAllowed>true</inheritanceAllowed></macset>'
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $MacSetObjResponse = Invoke-vCDNSXRestMethod -method post -URI "/network/services/macset/$($OrgVdcGuid)" -body $MacSetBody
    }
    if ($MacSetObjResponse.Headers) {Write-host -ForegroundColor Yellow "Successfully created MacSet Object $($MacSetName)"}
    $MacSetObjReturn = Get-vCDNSXMacSet -OrgVdcGuid $OrgVdcGuid | Where-Object {$_.MacSetName -eq $MacSetName}
    
    $MacSetObjReturn
}

function New-vCDNSXSecurityGroup {

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter(Mandatory=$true)] 
        #Name of the SecurityGroup object
        [string]$SecurityGroupName,
        [Parameter( Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$Description
    )

    [string] $SecurityGroupBody = '<securitygroup><description>’ + $description + ‘</description><name>’ + $SecurityGroupName + ‘</name><scope><id>globalroot-0</id><objectTypeName>GlobalRoot</objectTypeName><name>Global</name></scope></securitygroup>'
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method post -URI "/network/services/securitygroup/bulk/$($OrgVdcGuid)" -body $SecurityGroupBody
    }
    if ($SecurityGroupObjResponse.Headers) {Write-host -ForegroundColor Yellow "Successfully created SecurityGroup Object $($SecurityGroupName)"}
    $SecurityGroupObjReturn = Get-vCDNSXSecurityGroup -OrgVdcGuid $OrgVdcGuid | Where-Object {$_.SecurityGroupName -eq $SecurityGroupName}
    
    $SecurityGroupObjReturn
}

function New-vCDNSXSecurityTag {

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter(Mandatory=$true)] 
        #Name of the SecurityTag object
        [string]$SecurityTagName,
        [Parameter( Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$Description
    )

    [string] $SecurityTagBody = '<securityTag><description>’ + $description + ‘</description><name>’ + $SecurityTagName + ‘</name><isUniversal>false</isUniversal><extendedAttributes></extendedAttributes></securityTag>'
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $SecurityTagObjResponse = Invoke-vCDNSXRestMethod -method post -URI "/network/services/securitytags/tag/scope/$($OrgVdcGuid)" -body $SecurityTagBody
    }
    if ($SecurityTagObjResponse.Headers) {Write-host -ForegroundColor Yellow "Successfully created SecurityTag Object $($SecurityTagName)"}
    $SecurityTagObjReturn = Get-vCDNSXSecurityTag -OrgVdcGuid $OrgVdcGuid | Where-Object {$_.SecurityTagName -eq $SecurityTagName}
    
    $SecurityTagObjReturn
}

function Add-vCDNSXSecurityGroupMember {

    param (
        [Parameter (Mandatory=$true)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        #Name of the SecurityGroup object
        [string]$SecurityGroupGuid,
        [Parameter( Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$VmObject
    )
    
    if (!$DefaultvCDNSXonnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method get -URI "/network/services/securitygroup/$SecurityGroupGuid" -body $SecurityGroupBody
    }
    write-host $SecurityGroupObjResponse
    $SecurityGroupObjReturn = Get-vCDNSXSecurityGroup -OrgVdcGuid $OrgVdcGuid | Where-Object {$_.SecurityGroupName -eq $SecurityGroupName}
    
    $SecurityGroupObjReturn
}