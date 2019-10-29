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
        if (!$connection) {

            #Now we need to assume that DefaultvCDNSXConnection does not exist...
            if (!$DefaultvCDNSXconnection) {
                throw "Not connected.  Connect to vCloud Director with Connect-vCDNSXAPI first."
            }
            else {
                #Write-host "$($MyInvocation.MyCommand.Name) : Using default connection"
                $connection = $DefaultvCDNSXconnection
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
    if (!($PSVersionTable.PSVersion.Major -ge 6)) {
        Write-Error "This module only works with PowerShell version 6 or higher"
        return
    }

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
        Set-Variable -Name DefaultvCDNSXconnection -value $ConnectionObj -scope Global
        $OrgVcdGuid = (Get-vCDNSXOrg | Get-vCDNSXOrgVDC).OrgVdcGuid
        $ConnectionObj = [PSCustomObject]@{
            Server = $Server
            Port = $Port
            Protocol = $Protocol
            Authentication = "Bearer"
            BearerAccessToken = $response.Headers.'X-VMWARE-VCLOUD-ACCESS-TOKEN'
            Headers = $headers
            OrgVdcGuid = $OrgVcdGuid
        }
        Set-Variable -Name DefaultvCDNSXconnection -value $ConnectionObj -scope Global
        
    } else {
        Write-Error "Username or Password incorrect"
    }
    $response
}

function Disconnect-vCDNSXAPI {

    if (!$DefaultvCDNSXconnection) {
        Write-Error "Not connected to a (default) vCloud Director server"
    } else {
        write-host -ForegroundColor Yellow "Connected to (default) vCloud Director server at: $($DefaultvCDNSXconnection.server)"
        $answer = read-host "Are you sure you want to disconnect (y/n)?"
        if ($answer.ToLower() -eq "y") {
            Set-Variable -Name DefaultvCDNSXconnection -value $null -scope Global
            write-host "Succesfully disconnected!"
        }
    }
}

function Get-vCDNSXOrg {

    if (!$DefaultvCDNSXconnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $OrgResponse = Invoke-vCDNSXRestMethod -method get -URI "/api/org"
        $OrgGuid = $OrgResponse.xml.OrgList.org.href.substring($OrgResponse.xml.OrgList.org.href.LastIndexOf('/')+1)
        $OrgName = ($OrgResponse.xml).OrgList.Org.name
        $OrgHref = $OrgResponse.xml.OrgList.org.href
        $OrgAPI = $OrgResponse.xml.OrgList.org.href.Substring(($OrgResponse.xml.OrgList.org.href.IndexOf($DefaultvCDNSXconnection.server)+($DefaultvCDNSXconnection.server).Length))
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

    if (!$DefaultvCDNSXconnection) {
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
    
    if (!$DefaultvCDNSXconnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $OrgVdcGuid = $DefaultvCDNSXconnection.OrgVdcGuid
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

function Get-vCDNSXOrgVDCVM {

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false)]
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter( Mandatory=$false)] 
        #VM/Vapp object matches VmName
        [string]$VMName
    )
    
    if (!$DefaultvCDNSXconnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $OrgVdcGuid = $DefaultvCDNSXconnection.OrgVdcGuid
        $OrgVdcVMResponse = Invoke-vCDNSXRestMethod -method get -URI "/api/query?type=vm&filter=vdc==https://vcd01.z01.hypergrid.nl/api/vdc/$($OrgVdcGuid)"
    }

    $OrgVdcVMReturn = @()
    foreach ($OrgVdcVMObject in $OrgVdcVMResponse.xml.QueryResultRecords.VMRecord) {
        [System.Uri]$VMuri = $OrgVdcVMObject.href
        $OrgVdcVMObjectResponse = Invoke-vCDNSXRestMethod -method get -URI $VMuri.LocalPath
        
        $OrgVdcVMObjectReturn = [PSCustomObject]@{
            VmName = $OrgVdcVMObject.name
            VmHref = $OrgVdcVMObject.href
            VmStatus = $OrgVdcVMObject.status
            VmVcdId = $OrgVdcVMObjectResponse.xml.Vm.id
        }
        $OrgVdcVMReturn += $OrgVdcVMObjectReturn
    }
    if ($VMName) {$OrgVdcVMReturn = $OrgVdcVMReturn | Where-Object {$_.VmName -match $VMName}}
    $OrgVdcVMReturn
}


function Get-vCDNSXIpset {

    param (
        [Parameter(Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false)] 
        #IPSet object matches IpSetName
        [string]$IpSetName
    )
    
    if (!$DefaultvCDNSXconnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $OrgVdcGuid = $DefaultvCDNSXconnection.OrgVdcGuid
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
        [Parameter(Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false)] 
        #MacSet object matches MacSetName
        [string]$MacSetName
    )
    
    if (!$DefaultvCDNSXconnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $OrgVdcGuid = $DefaultvCDNSXconnection.OrgVdcGuid
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
        [Parameter(Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false)] 
        #Service object matches ServiceName
        [string]$ServiceName
    )
    
    if (!$DefaultvCDNSXconnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $OrgVdcGuid = $DefaultvCDNSXconnection.OrgVdcGuid
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
        [Parameter(Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false)] 
        #ServiceGroup object matches ServiceGroupName
        [string]$ServiceGroupName
    )
    
    if (!$DefaultvCDNSXconnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $OrgVdcGuid = $DefaultvCDNSXconnection.OrgVdcGuid
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
        [Parameter(Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false)] 
        #SecurityGroup object matches SecurityGroupName
        [string]$SecurityGroupName
    )
    
    if (!$DefaultvCDNSXconnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $OrgVdcGuid = $DefaultvCDNSXconnection.OrgVdcGuid
        $SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method get -URI "/network/services/securitygroup/scope/$($OrgVdcGuid)"
    }

    $SecurityGroupXMLObjectReturn = @()
    foreach ($SecurityGroupXMLObject in $SecurityGroupObjResponse.xml.list.securitygroup) {

        $SecurityGroupPSObject = [PSCustomObject]@{
            SecurityGroupName = $SecurityGroupXMLObject.name
            SecurityGroupMember = $SecurityGroupXMLObject.member
            SecurityGroupExcludeMember = $SecurityGroupXMLObject.ExcludeMember
            SecurityGroupGuid = $SecurityGroupXMLObject.objectId
        }
        $SecurityGroupXMLObjectReturn += $SecurityGroupPSObject
    }
    if ($SecurityGroupName) {$SecurityGroupXMLObjectReturn = $SecurityGroupXMLObjectReturn | Where-Object {$_.SecurityGroupName -match $SecurityGroupName}}
    $SecurityGroupXMLObjectReturn 
}

function Get-vCDNSXSecurityTag{

    param (
        [Parameter(Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid,
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false)] 
        #Securitytag object matches SecuritytagName
        [string]$SecuritytagName
    )
    
    if (!$DefaultvCDNSXconnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $OrgVdcGuid = $DefaultvCDNSXconnection.OrgVdcGuid
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
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false)] 
        #Security Tag GUID
        [string]$SecuritytagGuid
    )
    
    if (!$DefaultvCDNSXconnection) {
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
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)] 
        #Name of the IpSet object
        $IpSetName,
        [Parameter(Mandatory=$false)] 
        #Value of the IpSet object
        [string]$IpSetValue,
        [Parameter(Mandatory=$false)] 
        #ipset description
        [string]$Description,
        [Parameter(Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid
    )

    begin {
        $IpSetObjReturn = @()
    }
    process {
        foreach ($IpSetObjName in $IpSetName) {
            
            if ($IpSetValue) {
                [string] $IpSetBody = '<ipset><description>’ + $description + ‘</description><name>’ + $IpSetObjName + ‘</name><value>’ + $IpSetValue + ‘</value><inheritanceAllowed>true</inheritanceAllowed></ipset>'
            } else {
                [string] $IpSetBody = '<ipset><description>’ + $description + ‘</description><name>’ + $IpSetObjName + ‘</name><inheritanceAllowed>true</inheritanceAllowed></ipset>'
            }

            if (!$DefaultvCDNSXconnection) {
                Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
            } else {
                $OrgVdcGuid = $DefaultvCDNSXconnection.OrgVdcGuid
                $IpSetObjResponse = Invoke-vCDNSXRestMethod -method post -URI "/network/services/ipset/$($OrgVdcGuid)" -body $IpSetBody
            }
            if ($IpSetObjResponse.Headers) {Write-host -ForegroundColor Yellow "Successfully created IpSet Object $($IpSetObjName)"}
            $IpSetObjReturn += Get-vCDNSXIpset -OrgVdcGuid $OrgVdcGuid | Where-Object {$_.IpSetName -eq $IpSetObjName}
        }
    }

    end {
        $IpSetObjReturn
    }
}

function New-vCDNSXMacSet {

    param (
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)] 
        #Name of the MacSet object
        [string]$MacSetName,
        [Parameter(Mandatory=$false)] 
        #Value of the MacSet object
        [string]$MacSetValue,
        [Parameter(Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$Description,
        [Parameter(Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid
    )
 
    begin {
        $MacSetObjReturn = @()
    }
    process {
        foreach ($MacSetObjName in $MacSetName) {
            
            if ($IpSetValue) {
                [string] $MacSetBody = '<macset><description>’ + $description + ‘</description><name>’ + $MacSetObjName + ‘</name><value>’ + $MacSetValue + ‘</value><inheritanceAllowed>true</inheritanceAllowed></macset>'
            } else {
                [string] $MacSetBody = '<macset><description>’ + $description + ‘</description><name>’ + $MacSetObjName + ‘</name><inheritanceAllowed>true</inheritanceAllowed></macset>'
            }
        }

    
    if (!$DefaultvCDNSXconnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        $OrgVdcGuid = $DefaultvCDNSXconnection.OrgVdcGuid
        $MacSetObjResponse = Invoke-vCDNSXRestMethod -method post -URI "/network/services/macset/$($OrgVdcGuid)" -body $MacSetBody
    }
    if ($MacSetObjResponse.Headers) {Write-host -ForegroundColor Yellow "Successfully created MacSet Object $($MacSetName)"}
    $MacSetObjReturn += Get-vCDNSXMacSet -OrgVdcGuid $OrgVdcGuid | Where-Object {$_.MacSetName -eq $MacSetName}
    }

    end {
        $MacSetObjReturn
    }

}

function New-vCDNSXSecurityGroup {

    param (
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)] 
        #Name of the SecurityGroup object
        [string]$SecurityGroupName,
        [Parameter(Mandatory=$false)] 
        #Description
        [string]$Description,
        [Parameter(Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid
    )

    begin {
        $SecurityGroupObjReturn = @()
    }

    process {

        foreach ($SecurityGroupObjName in $SecurityGroupName) {
            [string] $SecurityGroupBody = '<securitygroup><description>’ + $description + ‘</description><name>’ + $SecurityGroupObjName + ‘</name><scope><id>globalroot-0</id><objectTypeName>GlobalRoot</objectTypeName><name>Global</name></scope></securitygroup>'
        }
        
        if (!$DefaultvCDNSXconnection) {
            Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
        } else {
            $OrgVdcGuid = $DefaultvCDNSXconnection.OrgVdcGuid
            $SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method post -URI "/network/services/securitygroup/bulk/$($OrgVdcGuid)" -body $SecurityGroupBody
        }
        if ($SecurityGroupObjResponse.Headers) {Write-host -ForegroundColor Yellow "Successfully created SecurityGroup Object $($SecurityGroupName)"}
        $SecurityGroupObjReturn += Get-vCDNSXSecurityGroup -SecurityGroupName $SecurityGroupName
    }
    

    end {
        $SecurityGroupObjReturn
    } 
}

function New-vCDNSXSecurityTag {

    param (
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)] 
        #Name of the SecurityTag object
        [string]$SecurityTagName,
        [Parameter(Mandatory=$false)] 
        #Description
        [string]$Description,
        [Parameter(Mandatory=$false)] 
        #Vdc Organization GUID
        [string]$OrgVdcGuid
    )

    begin {
        $SecurityTagObjReturn = @()
    }

    process {

        foreach ($SecurityTagObjName in $SecurityTagName) {
            [string] $SecurityTagBody = '<securityTag><description>’ + $description + ‘</description><name>’ + $SecurityTagObjName + ‘</name><isUniversal>false</isUniversal><extendedAttributes></extendedAttributes></securityTag>'
        }

        if (!$DefaultvCDNSXconnection) {
            Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
        } else {
            $OrgVdcGuid = $DefaultvCDNSXconnection.OrgVdcGuid
            $SecurityTagObjResponse = Invoke-vCDNSXRestMethod -method post -URI "/network/services/securitytags/tag/scope/$($OrgVdcGuid)" -body $SecurityTagBody
        }
        if ($SecurityTagObjResponse.Headers) {Write-host -ForegroundColor Yellow "Successfully created SecurityTag Object $($SecurityTagName)"}
        $SecurityTagObjReturn += Get-vCDNSXSecurityTag -OrgVdcGuid $OrgVdcGuid | Where-Object {$_.SecurityTagName -eq $SecurityTagName}
    }

    end {    
        $SecurityTagObjReturn
    }
}

function Add-vCDNSXSecurityGroupStaticMembers {

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)]
        #Name of the SecurityGroup object
        [string]$SecurityGroupGuid,
        [Parameter(Mandatory=$false)] 
        #include vCD VM object
        [array]$IncludeVMobject,
        [Parameter(Mandatory=$false)] 
        #include vCD IpSet object
        [array]$IncludeIpSetobject,
        [Parameter(Mandatory=$false)] 
        #include vCD MacSet object
        [array]$IncludeMacSetobject,
        [Parameter(Mandatory=$false)] 
        #include vCD MacSet object
        [array]$IncludeSecurityTagobject,
        [Parameter(Mandatory=$false)] 
        #exclude vCD VM object
        [array]$ExcludeVMobject,
        [Parameter(Mandatory=$false)] 
        #exclude vCD IpSet object
        [array]$ExcludeIpSetobject,
        [Parameter(Mandatory=$false)] 
        #exclude vCD VM object
        [array]$ExcludeMacSetobject,
        [Parameter(Mandatory=$false)] 
        #exclude vCD VM object
        [array]$ExcludeSecurityTagobject
    )

    begin {$OrgVdcGuid = $DefaultvCDNSXconnection.OrgVdcGuid}

    process {
        #create body base section
        $SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method get -URI "/network/services/securitygroup/scope/$($OrgVdcGuid)"
        $SecGroupInfo = $SecurityGroupObjResponse.xml.list.securitygroup | Where-Object {$_.objectId -eq $SecurityGroupGuid}
        [string] $body = "<securitygroup><objectId>$($SecGroupInfo.objectId)</objectId><objectTypeName>$($SecGroupInfo.objectTypeName)</objectTypeName><vsmUuid>$($SecGroupInfo.vsmUuid)</vsmUuid><type><typeName>$($SecGroupInfo.type.typeName)</typeName></type><name>$($SecGroupInfo.name)</name><scope><id>$($SecGroupInfo.scope.id)</id><objectTypeName>$($SecGroupInfo.scope.objectTypeName)</objectTypeName><name>$($SecGroupInfo.scope.name)</name></scope><clientHandle></clientHandle><extendedAttributes></extendedAttributes>"  
        
        #create body member section
        if ($IncludeVMobject) {
            foreach ($VMobject in $IncludeVMobject) {
                [string]$body += "<member><objectId>$($VMobject.VmVcdId)</objectId><type><typeName>VirtualMachine</typeName></type><name>$($VMobject.VmName)</name><clientHandle></clientHandle></member>"
            }
        }

        if ($IncludeIpSetobject) {
            foreach ($IpSetobject in $IncludeIpSetobject) {
                [string]$body += "<member><objectId>$($IpSetobject.IpSetGuid)</objectId><type><typeName>IPSet</typeName></type><name>$($IpSetobject.IpSetName)</name><clientHandle></clientHandle></member>"
            }
        }

        if ($IncludeMacSetobject) {
            foreach ($MacSetobject in $IncludeMacSetobject) {
                [string]$body += "<member><objectId>$($MacSetobject.MacsetGuid)</objectId><type><typeName>MACSet</typeName></type><name>$($MacSetobject.MacsetName)</name><clientHandle></clientHandle></member>"
            }
        }

        if ($IncludeSecurityTagobject) {
            foreach ($SecurityTagobject in $IncludeSecurityTagobject) {
                [string]$body += "<member><objectId>$($SecurityTagobject.SecuritytagGuid)</objectId><type><typeName>SecurityTag</typeName></type><name>$($SecurityTagobject.SecuritytagName)</name><clientHandle></clientHandle></member>"
            }
        }

        if ($ExcludeVMobject) {
            foreach ($VMobject in $ExcludeVMobject) {
                [string]$body += "<excludeMember><objectId>$($VMobject.VmVcdId)</objectId><type><typeName>VirtualMachine</typeName></type><name>$($VMobject.VmName)</name><clientHandle></clientHandle></excludeMember>"
            }
        }

        if ($ExcludeIpSetobject) {
            foreach ($IpSetobject in $ExcludeIpSetobject) {
                [string]$body += "<excludeMember><objectId>$($IpSetobject.IpSetGuid)</objectId><type><typeName>IPSet</typeName></type><name>$($IpSetobject.IpSetName)</name><clientHandle></clientHandle></excludeMember>"
            }
        }

        if ($ExcludeMacSetobject) {
            foreach ($MacSetobject in $ExcludeMacSetobject) {
                [string]$body += "<excludeMember><objectId>$($MacSetobject.MacsetGuid)</objectId><type><typeName>MACSet</typeName></type><name>$($MacSetobject.MacsetName)</name><clientHandle></clientHandle></excludeMember>"
            }
        }

        if ($ExcludeSecurityTagobject) {
            foreach ($SecurityTagobject in $ExcludeSecurityTagobject) {
                [string]$body += "<excludeMember><objectId>$($SecurityTagobject.SecuritytagGuid)</objectId><type><typeName>SecurityTag</typeName></type><name>$($SecurityTagobject.SecuritytagName)</name><clientHandle></clientHandle></excludeMember>"
            }
        }

        #complete body
        [string]$body += "</securitygroup>"

        if (!$DefaultvCDNSXconnection) {
            Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
        } else {
         
            write-host $body
            $SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method put -URI "/network/services/securitygroup/bulk/$($SecurityGroupGuid)" -body $body
            if ($SecurityGroupObjResponse.Headers) {
                $SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method get -URI "/network/services/securitygroup/$($SecurityGroupGuid)"
            }
        }

        $SecurityGroupObjReturn = @()
        foreach ($SecurityGroupXMLObject in $SecurityGroupObjResponse.xml.securitygroup) {

            $SecurityGroupPSObject = [PSCustomObject]@{
                SecurityGroupName = $SecurityGroupXMLObject.name
                SecurityGroupMember = $SecurityGroupXMLObject.member
                SecurityGroupExcludeMember = $SecurityGroupXMLObject.excludeMember
                SecurityGroupGuid = $SecurityGroupXMLObject.objectId
            }
            $SecurityGroupObjReturn += $SecurityGroupPSObject
        }    
    }

    end {$SecurityGroupObjReturn}
}

function Remove-vCDNSXSecurityGroupStaticMember {

    param (
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$true)]
        #Name of the SecurityGroup object
        [string]$SecurityGroupGuid,
        [Parameter(Mandatory=$false)] 
        #include vCD VM object
        [array]$IncludeVMobject,
        [Parameter(Mandatory=$false)] 
        #include vCD IpSet object
        [array]$IncludeIpSetobject,
        [Parameter(Mandatory=$false)] 
        #include vCD MacSet object
        [array]$IncludeMacSetobject,
        [Parameter(Mandatory=$false)] 
        #include vCD MacSet object
        [array]$IncludeSecurityTagobject #,
        #[Parameter(Mandatory=$false)] 
        #exclude vCD VM object
        #[array]$ExcludeVMobject,
        #[Parameter(Mandatory=$false)] 
        #exclude vCD IpSet object
        #[array]$ExcludeIpSetobject,
        #[Parameter(Mandatory=$false)] 
        #exclude vCD VM object
        #[array]$ExcludeMacSetobject,
        #[Parameter(Mandatory=$false)] 
        #exclude vCD VM object
        #[array]$ExcludeSecurityTagobject
    )
    
    if (!$DefaultvCDNSXconnection) {
        Write-Error "Not connected to a (default) vCloud Director server, connect using Connect-vCDNSXAPI cmdlet"
    } else {
        if ($IncludeVMobject) {$IncludeVMobject | ForEach-Object {$SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method del -URI "/network/services/securitygroup/$($SecurityGroupGuid)/members/$($_.VmVcdId)"}}
        if ($IncludeIpSetobject) {$IncludeIpSetobject | ForEach-Object {$SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method del -URI "/network/services/securitygroup/$($SecurityGroupGuid)/members/$($_.IpSetGuid)"}}
        if ($IncludeMacSetobject) {$IncludeMacSetobject | foreach-object {$SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method del -URI "/network/services/securitygroup/$($SecurityGroupGuid)/members/$($_.MacsetGuid)"}}
        if ($IncludeSecurityTagobject) {$IncludeSecurityTagobject | ForEach-Object {$SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method del -URI "/network/services/securitygroup/$($SecurityGroupGuid)/members/$($_.SecuritytagGuid)"}}
        #if ($ExcludeVMobject) {$ExcludeVMobject| ForEach-Object {$SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method del -URI "/network/services/securitygroup/$($SecurityGroupGuid)/excludeMember/$($_.VmVcdId)"}}
        #if ($ExcludeIpSetobject) {$ExcludeIpSetobject| ForEach-Object {$SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method del -URI "/network/services/securitygroup/$($SecurityGroupGuid)/excludeMember/$($_.IpSetGuid)"}}
        #if ($ExcludeMacSetobject) {$ExcludeMacSetobject| ForEach-Object {$SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method del -URI "/network/services/securitygroup/$($SecurityGroupGuid)/excludeMember/$($_.MacsetGuid)"}}
        #if ($ExcludeSecurityTagobject) {$ExcludeSecurityTagobject| ForEach-Object {$SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method del -URI "/network/services/securitygroup/$($SecurityGroupGuid)/excludeMember/$($_.SecuritytagGuid)"}}
    }

    if ($SecurityGroupObjResponse.Headers) {
        $SecurityGroupObjResponse = Invoke-vCDNSXRestMethod -method get -URI "/network/services/securitygroup/$($SecurityGroupGuid)"
        $SecurityGroupXMLObjectReturn = @()
        foreach ($SecurityGroupXMLObject in $SecurityGroupObjResponse.xml.securitygroup) {

            $SecurityGroupPSObject = [PSCustomObject]@{
                SecurityGroupName = $SecurityGroupXMLObject.name
                SecurityGroupMember = $SecurityGroupXMLObject.member
                SecurityGroupExcludeMember = $SecurityGroupXMLObject.ExcludeMember
                SecurityGroupGuid = $SecurityGroupXMLObject.objectId
            }
            $SecurityGroupXMLObjectReturn += $SecurityGroupPSObject
        }
    }
    if ($SecurityGroupName) {$SecurityGroupXMLObjectReturn = $SecurityGroupXMLObjectReturn | Where-Object {$_.SecurityGroupName -match $SecurityGroupName}}
    $SecurityGroupXMLObjectReturn 
}