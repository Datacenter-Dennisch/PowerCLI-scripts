function Write-Log
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        [string]$Path='D:\Security scripts\Logs\debug.log',
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level="Info",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoClobber
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process
    {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
            }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
            }

        else {
            # Nothing to see here yet.
            }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
                }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
                }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
                }
            }
        
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End
    {
    }
}


function Connect-LogInsightServer{

    param(
        [Parameter(Position=0,mandatory=$true,parametersetname='pscred')]
        [Parameter(Position=0,mandatory=$true,parametersetname='psuserpwd')]
        [String]$Server,
        [Parameter(Position=1,mandatory=$true,parametersetname='pscred')]
        [PSCredential]$Credentials,
        [Parameter(Position=2,mandatory=$true,parametersetname='psuserpwd')]
        [string]$Username,
        [Parameter(Position=3,mandatory=$true,parametersetname='psuserpwd')]
        [string]$Password,
        [Parameter(Position=4,mandatory=$true,parametersetname='pscred')]
        [Parameter(Position=4,mandatory=$true,parametersetname='psuserpwd')]
        [Validateset("ActiveDirectory","local")]
        [string]$Provider,
        [Parameter(Position=5,parametersetname='reconnect')]
        [ValidateSet($false,$true)]
        $reconnnect = $false,
        [Parameter(Position=6,parametersetname='reconnect')]
        [psobject]$ConnectionPS = $Global:DefaultPSLogInsightserver
    )
 
    process {
        if ($PSCmdlet.ParameterSetName -eq "pscred") {
            $restcallPS = new-object -type psobject -Property @{
                username = $Credentials.UserName
                password = $Credentials.GetNetworkCredential().Password
                provider = $Provider
            }
            $restcallJSON = $restcallPS | convertto-json
        } elseif ($PSCmdlet.ParameterSetName -eq "psuserpwd") {
            $restcallPS = new-object -type psobject -Property @{
                username = $UserName
                password = $Password
                provider = $Provider
            }
            $restcallJSON = $restcallPS | convertto-json
            $SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
            $Credentials = New-Object System.Management.Automation.PSCredential ($UserName, $SecPassword)
        } elseif ($PSCmdlet.ParameterSetName -eq "reconnect") {
            $Credentials = $ConnectionPS.Credentials
            $Provider = $ConnectionPS.Provider
            $restcallPS = new-object -type psobject -Property @{
                username = $Credentials.UserName
                password = $Credentials.GetNetworkCredential().Password
                provider = $Provider
            }
            
            
            #$restcallPS = new-object -type psobject -Property @{
            #    username = $ConnectionPS.Credentials.UserName
            #    password = $ConnectionPS.Credentials.GetNetworkCredential().Password
            #    provider = $ConnectionPS.Provider
            #}
            
            $Server = $ConnectionPS.Server 
            
            $restcallJSON = $restcallPS | convertto-json
        } else {
            Write-Error "Could not construct credentials."
            $restcallJSON = $null
        }

        if ($restcallJSON) {
            $protocol = "https"
            $BaseURI = $protocol + "://" + $Server + "/api/v1"
            $URI = $BaseURI + "/sessions"
            if ($reconnnect) {write-host "reconnection Loginsight server"}
            try {
                $response = Invoke-RestMethod -Uri $URI  -Method post -Body $restcallJSON -ContentType "application/json"
            }
            catch {
                $_.Exception.Message
            }
            if ($response) {
                $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                $headers.Add("Authorization", "Bearer "+($response.sessionId))
                if (!$reconnect) {write-host -ForegroundColor Yellow "Succesfully connected to VMware Loginsight server at $Server"}

                $DefaultPSLogInsightserver = New-Object -type psobject -Property @{
                    Server = $Server
                    BaseURI = $BaseURI 
                    Header = $headers
                    TTL = $response.ttl
                    TTLexpires = ([DateTimeOffset]::Now.ToUnixTimeSeconds() + $response.ttl)
                    Credentials = $Credentials
                    Provider = $Provider
                }
                Set-Variable -Name "DefaultPSLogInsightserver" -Value $DefaultPSLogInsightserver -Scope global
            }
        }
    }
}

function Disconnect-LogInsightServer {
    param(
        [psobject] $ConnectionPS = $Global:DefaultPSLogInsightserver,
        [bool] $Confirm = $true
    )

    Process {
        $server = $ConnectionPS.Server
        if ($Confirm -eq $true) {
            $title    = "Disconnect Loginsight server"
            $question = "Do you want to disconnect server ""$($server)""?"
            $choices  = '&Yes', '&No'

            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
            if ($decision -eq 0) {
                Remove-Variable -name "DefaultPSLogInsightserver" -Scope global
                write-host "Succesfully disconnected from Loginsight server $($server) "
            } 
        } else {
            Remove-Variable -name "DefaultPSLogInsightserver" -Scope global
            write-host "Succesfully disconnected from Loginsight server $($server)"
        }
    }
}

$daysofdata = 30 
$epochnow = (Get-Date -UFormat %s).Split(".")[0]
$epochnow = $epochnow - 3600
$epochdaysofdata = $epochnow - ($daysofdata * (3600 * 24))


add-type @"
 using System.Net;
 using System.Security.Cryptography.X509Certificates;
 public class TrustAllCertsPolicy : ICertificatePolicy {
 public bool CheckValidationResult(
 ServicePoint srvPoint, X509Certificate certificate,
 WebRequest request, int certificateProblem) {
 return true;
 }
 }
"@

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

$VRNIFQDN = "https://vrni.domain.local"
$LoginsightFQDN = "vrli.domain.local"
$NSXvMgrIp = "nsxvmgr.domain.local"
if (!$apiKey) {
    do {
        $GlobalCred = Get-Credential -Message "Enter admin credentials $site"
        $username = $GlobalCred.UserName
        $password = $GlobalCred.GetNetworkCredential().Password
        $domaintype = "LDAP"
        $domain = "domain.local"

        $jsonCredentials = @{username=$username;password=$password;domain=@{domain_type=$domaintype;value="$domain"}} | ConvertTo-Json

        $url = $VRNIFQDN +"/api/ni/auth/token"
        $apiKey = Invoke-RestMethod $url -Method POST -Body $jsonCredentials -ContentType 'application/json'
    } until  ($apiKey)
}
$authVal = "NetworkInsight " + $apiKey.token


if (!$Global:DefaultPSLogInsightserver) {
    do {
        write-log -Message "No connection with LogInsight detected, continueing with logging in" -Level Warn
        if (!$GlobalCred) {$GlobalCred = Get-Credential -Message "Please Enter Loginsight credentials"}
        Connect-LogInsightServer -Server $LoginsightFQDN -Credentials $GlobalCred -Provider ActiveDirectory | out-null
        if (!$Global:DefaultPSLogInsightserver) {$GlobalCred = $null}
    } until ($Global:DefaultPSLogInsightserver)
    Write-log -message "Connection with LogInsight manager ""$($Global:DefaultPSLogInsightserver.Server)"" established" -Level Info
} else {
    Write-log -message "Connection with LogInsight manager ""$($Global:DefaultPSLogInsightserver.Server)"" already established" -Level info
}

if (!$DefaultNSXConnection) {
    write-log -Message "No connection with NSX-v manager detected, continueing with logging in" -Level Warn
    do {
        if (!$GlobalCred) {$GlobalCred = Get-Credential -Message "Please Enter NSX/vCenter credentials"}
        Connect-NsxServer -NsxServer $NSXvMgrIp -Credential $GlobalCred -VICredential $GlobalCred | Out-Null
        if (!$DefaultNSXConnection) {$GlobalCred = $null}
    } until ($DefaultNSXConnection)
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" established" -Level Info
} else {
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" already established" -Level info
}


function Get-VRNI-VMsByService {
    param (
        [Parameter(Position=0,mandatory=$true,parametersetname='Portname')]
        [string]$PortName,
        [Parameter(Position=0,mandatory=$true,parametersetname='PortNumber')]
        [int]$PortNumber,
        [Parameter(Position=1,mandatory=$true,parametersetname='PortNumber')]
        [ValidateSet("tcp","udp")]
        [string]$Protocol
    )
    if ($PSCmdlet.ParameterSetName -eq "Portname") {
        $query  = "list (destination vm) of flow where port name = $PortName"
    }
    if ($PSCmdlet.ParameterSetName -eq "PortNumber") {
        $query  = "list (destination vm) of flow where port = $PortNumber and protocol = $Protocol"
    }
    
    $jsonbody = @{query=$query;size=1000;time_range= @{start_time=[int]$epochdaysofdata;end_time=[int]$epochnow}} | ConvertTo-Json
    $url = $VRNIFQDN +"/api/ni/search/ql"
    $returnjson = Invoke-RestMethod $url -Method POST -ContentType 'application/json' -Headers @{"AUTHORIZATION"=$authVal} -Body $jsonbody
    $entitylist = $returnjson.entity_list_response.results

    $jsonbody = @{entity_ids=$entitylist} | ConvertTo-Json
    $url = $site +"/api/ni/entities/fetch"
    $ServerNameList = (Invoke-RestMethod $url -Method post -ContentType 'application/json' -Headers @{"AUTHORIZATION"=$authVal} -Body $jsonbody).results.entity.name
    $VMList = @()
    $ServerNameList.foreach({$VMList += get-vm -name $_}) 

    return $VMList 
}


function Get-VRNI-ConnectedVMs {
    param (
        [Parameter(Position=0,mandatory=$true,parametersetname='SourceVM')]
        [string]$SourceVmName,
        [Parameter(Position=0,mandatory=$true,parametersetname='DestinationVM')]
        [string]$DestinationVmName
    )
    if ($PSCmdlet.ParameterSetName -eq "SourceVM") {
        $query  = "list (destination vm) of flow where Source VM = '$SourceVmName'" 
    }
    if ($PSCmdlet.ParameterSetName -eq "DestinationVM") {
        $query  = "list (source vm) of flow where Destination VM = '$DestinationVmName'" 
    }

    #execute VRNI query to retrieve VRNI entity list
    $jsonbody = @{query=$query;size=1000;time_range= @{start_time=[int]$epochdaysofdata;end_time=[int]$epochnow}} | ConvertTo-Json
    $url = $VRNIFQDN +"/api/ni/search/ql"
    $returnjson = Invoke-RestMethod $url -Method POST -ContentType 'application/json' -Headers @{"AUTHORIZATION"=$authVal} -Body $jsonbody
    $entitylist = $returnjson.entity_list_response.results

    #execute VRNI Fetch to retrieve servername list
    $jsonbody = @{entity_ids=$entitylist} | ConvertTo-Json
    $url = $VRNIFQDN +"/api/ni/entities/fetch"
    $ConnectedVMServerNameList = (Invoke-RestMethod $url -Method post -ContentType 'application/json' -Headers @{"AUTHORIZATION"=$authVal} -Body $jsonbody).results.entity.name

    #convert servername list to usable VM objects.
    $ConnectedVMList = @()
    $ConnectedVMServerNameList.foreach({$ConnectedVMList += get-vm -name $_}) 

    return $ConnectedVMList 
}

$DomaincontrollerVMlist = Get-VRNI-VMsByService -PortName ldap
$DNSVMlist = Get-VRNI-VMsByService -PortName dns
$NTPVMlist = Get-VRNI-VMsByService -PortName ntp
$SNMPVMlist = Get-VRNI-VMsByService -portname snmp
$genericserverVMlist = $DomaincontrollerVMlist + $DNSVMlist + $NTPVMlist + $SNMPVMlist

$VMobject = get-vm | Out-GridView -PassThru

$DestinationVMs = Get-VRNI-ConnectedVMs -SourceVmName $VMobject.name
$CorrectedDestinationVMs = $DestinationVMs.Where({$genericserverVMlist.id -notcontains $_.id})
