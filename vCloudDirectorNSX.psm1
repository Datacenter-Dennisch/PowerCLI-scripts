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
        [Parameter (Mandatory=$true,ParameterSetName="BasicAuth")]
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
        if ( -not $ValidateCertificate) {
            #allow untrusted certificate presented by the remote system to be accepted
            #[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
        $headerDictionary = @{}
        $base64cred = [system.convert]::ToBase64String([system.text.encoding]::ASCII.Getbytes("$($cred.GetNetworkCredential().username)@$($cred.GetNetworkCredential().Domain):$($cred.GetNetworkCredential().password)"))
        $headerDictionary.add("Authorization", "Basic $Base64cred")
    }
    else {

        #ensure we were either called with a connection or there is a defaultConnection (user has
        #called connect-nsxserver)
        #Little Grr - $connection is a defined variable with no value so we cant use test-path
        if ($connection -eq $null) {

            #Now we need to assume that DefaultvCDNSXConnection does not exist...
            if ( -not (test-path variable:global:DefaultvCDNSXConnection) ) {
                throw "Not connected.  Connect to vCloud Director with Connect-vCDServer first."
            }
            else {
                Write-Debug "$($MyInvocation.MyCommand.Name) : Using default connection"
                $connection = $DefaultvCDNSXConnection
            }
        }

        if ( -not $connection.ValidateCertificate ) {
            #allow untrusted certificate presented by the remote system to be accepted
            #[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }

        $cred = $connection.credential
        $server = $connection.Server
        $port = $connection.Port
        $protocol = $connection.Protocol

    }

    

    if ( $extraHeader ) {
        foreach ($header in $extraHeader.GetEnumerator()) {
            write-debug "$($MyInvocation.MyCommand.Name) : Adding extra header $($header.Key ) : $($header.Value)"
            if ( $pscmdlet.ParameterSetName -eq "ConnectionObj" ) {
                $headerDictionary = $connection.Headers
                if ( $connection.DebugLogging ) {
                    Add-Content -Path $Connection.DebugLogfile -Value "$(Get-Date -format s)  Extra Header being added to following REST call.  Key: $($Header.Key), Value: $($Header.Value)"
                }
            } else {
                switch ($vCDversion) {
                    "v8.2" {$headerDictionary.add("accept", "application/*+xml;version=27.0")}
                    "v9.0" {$headerDictionary.add("accept", "application/*+xml;version=29.0")}
                    "v9.1" {$headerDictionary.add("accept", "application/*+xml;version=30.0")}
                    "v9.5" {$headerDictionary.add("accept", "application/*+xml;version=31.0")}
                    "v9.7" {$headerDictionary.add("accept", "application/*+xml;version=32.0")}
                    "v10.0" {$headerDictionary.add("accept", "application/*+xml;version=33.0")}
                }
            }
        }
    }


    $FullURI = "$($protocol)://$($server):$($Port)$($URI)"
    write-debug "$($MyInvocation.MyCommand.Name) : Method: $method, URI: $FullURI, Body: `n$($body )"
    
    if ( $pscmdlet.ParameterSetName -eq "BearerAuth" ) {
        if ( $connection.DebugLogging ) {
            Add-Content -Path $Connection.DebugLogfile -Value "$(Get-Date -format s)  REST Call to NSX-T Manager via invoke-restmethod : Method: $method, URI: $FullURI, Body: `n$($body)"
        }
    }
    write-host $headerDictionary 
    #do rest call
    try {
        if ( $PsBoundParameters.ContainsKey('Body')) {
            $response = invoke-restmethod -method $method -headers $headerDictionary -uri $FullURI -body $body -TimeoutSec $Timeout -SkipCertificateCheck -ResponseHeadersVariable responseHeaders
        } else {
            $response = invoke-restmethod -method $method -headers $headerDictionary -uri $FullURI -TimeoutSec $Timeout -SkipCertificateCheck -ResponseHeadersVariable responseHeaders
        }
    }
    catch {
        #Get response from the exception
        $return = $_.exception.response
     }
    switch ( $response ) {
        { $_ -is [xml] } { $FormattedResponse = "`n$($response.outerxml | Format-Xml)" }
        { $_ -is [System.String] } { $FormattedResponse = $response }
        #{ $_ -is [json] } { $FormattedResponse = $response }
        default { $formattedResponse = "Response type unknown" }
    }
    $FormattedResponse = $response 

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
        xml     = $response.xml
        Session = $response.Session
        Headers    = $responseHeaders
    }
    #Return
    $return
}


function Connect-vCSNSXAPI {

param (
        [Parameter (Mandatory=$true)]
            #vCloud Director ip address or FQDN
            [string]$Server,
        [Parameter (Mandatory=$true)]
            #TCP Port on -server to connect to
            [int]$Port="443",
        [Parameter (Mandatory=$true)]
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
    $username = "$($cred.GetNetworkCredential().username)"+"@"+"$($TenantID)"
    $vCDcredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)

    
    try {
        $response = Invoke-vCDNSXRestMethod -server $Server -port $port -protocol $Protocol -cred $vCDcredential -method post -URI "/api/sessions" -vCDversion v10.0
    }
    catch {

        Throw "Unable to connect to vCloud Director at $Server.  $_"
    }
    
    $headers = @{}
    $headers.add("accept", $return.Headers.'Content-Type')

    $ConnectionObj = [PSCustomObject]@{
        Server = $Server
        Port = $Port
        Protocol = $Protocol
        Authentication = "Bearer"
        BearerAccessToken = $response.Headers.'X-VMWARE-VCLOUD-ACCESS-TOKEN'
        Headers = @{accept=$response.Headers.'Content-Type'}
    }
    Set-Variable -Name DefaultvCDConnection -value $ConnectionObj -scope Global
    $Response
}
