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
            $BaseURI = $protocol + "://" + $Server + ":9543/api/v2"
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

function Get-LoginsightNSXtEvents {
    
    param (
        [psobject] $ConnectionPS = $Global:DefaultPSLogInsightserver,
        [string] $textfilter,
        [string] $ruleid,
        [int32] $limit,
        [ValidateSet("1m","6m","1h","6h","12h","24h","7d")]
        [string] $TimeStamp
    )

    Process {
        if (([DateTimeOffset]::Now.ToUnixTimeSeconds()) -gt $ConnectionPS.TTLexpires) {
            Connect-LogInsightServer -reconnnect $true
            sleep 3
        }
        $URI = $ConnectionPS.BaseURI + "/events"
        if ($PSboundparameters.Containskey('textfilter')) {
            $URI += "/text/"+$textfilter
        } elseif ($PSboundparameters.Containskey('ruleid')) {
            $URI += "/com.vmware.nsxt:vmw_nsxt_firewall_ruleid/"+$ruleid
        } else {
            $URI += "/text/FIREWALL-PKTLOG"
        }
        if ($TimeStamp) {
            $currentime = [DateTimeOffset]::Now.ToUnixTimeMilliSeconds()
            Switch ($TimeStamp) {
                1m {$searchtime = $currentime - 60000}
                6m {$searchtime = $currentime - 360000}
                1h {$searchtime = $currentime - 3600000}
                6h {$searchtime = $currentime - 21600000}
                12h {$searchtime = $currentime - 43100000} 
                24h {$searchtime = $currentime - 86400000}
                7d {$searchtime = $currentime - 604800000}  
            }
            $URI += "/timestamp/>$($searchtime)"
        }
        
        $URI += "?content-pack-fields=com.vmware.nsxt"
        if ($limit) {$URI += "&limit=$($limit)&timeout=120000"}
        $URI = [uri]::EscapeUriString($URI)
        write-host "Executing .. $URI"
        try {
            $response = Invoke-WebRequest -Uri $URI -Method get -Headers $ConnectionPS.Header -ContentType "application/json"
        }
        catch {
            $_.Exception.Message
        }
        if ($response) {
            $completed = ($response.Content | ConvertFrom-Json).complete
            if (!$completed) {Write-Log -Message "Query could not be executed completely" -Level Warn}
            $events = ($response.Content | ConvertFrom-Json).events
            $eventcount = $events.count
            write-log -Message "Returning $($eventcount) events"

            if ($events) {
                $PsEvents = @()
                $progress =0 
                foreach ($event in $events) {
                    $progress ++
                    Write-Progress -Activity "converting Loginsight output to scriptable PowerShell objects" -status "completed events $($progress) / $($eventcount)" -PercentComplete (($progress/$eventcount)*100)
                    #write-host $event.fields.name
                    $vmwnsxfirewallruleidspec = $event.fields.Where({$_.name -eq "com.vmware.nsxt:vmw_nsxt_firewall_ruleid"}) 
                    $vmwnsxfirewallsrcspec = $event.fields.Where({$_.name -eq "com.vmware.nsxt:vmw_nsxt_firewall_src"}) 
                    $vmwnsxfirewalldstspec = $event.fields.Where({$_.name -eq "com.vmware.nsxt:vmw_nsxt_firewall_dst"}) 
                    $vmwnsxfirewallportspec = $event.fields.Where({$_.name -eq "com.vmware.nsxt:vmw_nsxt_firewall_dst_port"}) 
                    $vmwnsxfirewallprotocolspec = $event.fields.Where({$_.name -eq "com.vmware.nsxt:vmw_nsxt_firewall_protocol"}) 
                    $vmwnsxfirewallActionspec = $event.fields.Where({$_.name -eq "com.vmware.nsxt:vmw_nsxt_firewall_action"}) 
                    $eventitem = New-Object psobject -Property @{
                        vmwnsxfirewallruleid = $event.text.Substring($vmwnsxfirewallruleidspec.startPosition, $vmwnsxfirewallruleidspec.length)
                        vmwnsxfirewallsrc = $event.text.Substring($vmwnsxfirewallsrcspec.startPosition, $vmwnsxfirewallsrcspec.length)
                        vmwnsxfirewalldst = $event.text.Substring($vmwnsxfirewalldstspec.startPosition, $vmwnsxfirewalldstspec.length)
                        vmwnsxfirewallprotocol = $event.text.Substring($vmwnsxfirewallprotocolspec.startPosition, $vmwnsxfirewallprotocolspec.length)
                        vmwnsxfirewallport = $event.text.Substring($vmwnsxfirewallportspec.startPosition, $vmwnsxfirewallportspec.length)
                        vmwnsxfirewallaction = $event.text.Substring($vmwnsxfirewallActionspec.startPosition, $vmwnsxfirewallActionspec.length)
                    }
                    $PsEvents += $eventitem
                }
                return $PsEvents
            } else {
                
            }
        }
    }
}

function Enum-PSLoginsightevent {

    param(
        [Parameter(Position=0,mandatory=$true,ValueFromPipeline=$True)]
        [psobject]$PsEvents,
        [Parameter(Position=1,mandatory=$false)]
        [psobject]$AllsecurityGroupsMemberOverview
    )

    process {
        if (!$global:DefaultVIServer) {
            Write-Error "Not connected to vCenter"
        } else {
            
            write-host "retrieving VM information"
            $VMoverview = Get-View -ViewType "VirtualMachine" 

            $ReturnOutput = @()
            if (!$NoDNSRecordlist) {$NoDNSRecordlist = @()}
            write-host "Enumerating PSevents"
            foreach ($PsEventItem in $PsEvents) {
    
                $Sourcevm = $VMoverview.where({$_.guest.Net.ipconfig.IpAddress.ipaddress -contains $PsEventItem.vmwnsxfirewallsrc})
                $Sourcevmname = $Sourcevm.name
                $SourceSGNames,$SourceDNSname = $null
                if ($Sourcevmname) {
                    $SourceSGNames = ($AllsecurityGroupsMemberOverview.where({$_.VirtualMachines.display_name -eq $Sourcevm.name})).SecurityGroup.display_name
                } else {
                    $SourceSGNames = ($AllsecurityGroupsMemberOverview.where({$_.IPAddresses -eq $PsEventItem.vmwnsxfirewallsrc})).SecurityGroup.display_name
                }

                if ($NoDNSRecordlist -notcontains $PsEventItem.vmwnsxfirewallsrc) {
                    try {$SourceDNSname =([system.net.dns]::GetHostByAddress($PsEventItem.vmwnsxfirewallsrc)).hostname}
                    catch {
                        write-host "no DNS record for $($PsEventItem.vmwnsxfirewallsrc)"
                        $NoDNSRecordlist += $PsEventItem.vmwnsxfirewallsrc
                    } 
                }
            

                $Destinationvm = $VMoverview.where({$_.guest.Net.ipconfig.IpAddress.ipaddress -contains $PsEventItem.vmwnsxfirewalldst})
                $Destinationvmname = $Destinationvm.Name
                $DestinationSGNames,$DestinationDNSname = $null
                if ($Destinationvmname) {
                    $DestinationSGNames = ($AllsecurityGroupsMemberOverview.where({$_.VirtualMachines.display_name -eq $Destinationvm.name})).SecurityGroup.display_name
                } else {
                    $DestinationSGNames = ($AllsecurityGroupsMemberOverview.where({$_.IPAddresses -eq $PsEventItem.vmwnsxfirewalldst})).SecurityGroup.display_name
                }
                if ($NoDNSRecordlist -notcontains $PsEventItem.vmwnsxfirewalldst) {
                        try {$DestinationDNSname = ([system.net.dns]::GetHostByAddress($PsEventItem.vmwnsxfirewalldst)).hostname}
                        catch {
                            write-host "no DNS record for $($PsEventItem.vmwnsxfirewalldst)"
                            $NoDNSRecordlist += $PsEventItem.vmwnsxfirewalldst
                        }
                    }
            
                $ReturnItem = [pscustomobject][ordered]@{
                    ruleid = $PsEventItem.vmwnsxfirewallruleid
                    vmwnsxfirewallsrc = $PsEventItem.vmwnsxfirewallsrc
                    sourceVMname = $Sourcevmname -join ","
                    sourceDNSname = $SourceDNSname
                    sourceSGname = $SourceSGNames -join ","
                    vmwnsxfirewalldst = $PsEventItem.vmwnsxfirewalldst
                    destinationVMname = $Destinationvmname -join ","
                    destinationDNSname = $DestinationDNSname
                    destinationSGName = $DestinationSGNames -join ","
                    protocol = $PsEventItem.vmwnsxfirewallprotocol
                    port = $PsEventItem.vmwnsxfirewallport
                    action = $PsEventItem.vmwnsxfirewallaction 
                    legit = "NULL"
                }
                $ReturnOutput += $ReturnItem 
            }
            return $ReturnOutput
        }
    }
}

$VRLIFDQN = "vrli.ssc.lan"
$NSXtMgrFQDN = "w01nsx03.ssc.lan"

if (!$Global:DefaultPSLogInsightserver) {
    do {
        if (!$globalcred) {$globalcred = Get-Credential -Message "Please Enter Loginsight credentials"}
        $result = Connect-LogInsightServer -Server $VRLIFDQN -Credentials $globalcred -Provider ActiveDirectory 
        if ($result -contains "Unauthorized") {
            write-log -Message "$($VRLIFDQN) - User Unauthorized to login to LogInsight server" -Level Warn
            $globalcred = $null
        }
    } until ($Global:DefaultPSLogInsightserver)
    write-log -Message "$($VRLIFDQN) - User successfully loggd in to LogInsight server" -Level Info
}

if ($global:DefaultNsxtServers.Name -ne $NSXtMgrFQDN) {
    write-log -Message "No connection with NSX-v manager detected" -Level Warn
    do {
        Connect-NsxtServer -Server $NSXtMgrFQDN -Credential $globalcred 
    } while ($global:DefaultNsxtServers.Name -ne $NSXtMgrFQDN)
    Write-log -message "Connection with NSX-t manager ""$($global:DefaultNsxtServers.Name)"" established" -Level Info
} else {
    Write-log -message "Connection with NSX-t manager ""$($global:DefaultNsxtServers.Name)"" already established" -Level info
}


#retrieve NSX-T security Policies
$NSXDFWSecurityPolicyproxy = Get-NsxtPolicyService -name com.vmware.nsx_policy.infra.domains.security_policies
$TargetSecurityPolicy = $NSXDFWSecurityPolicyproxy.list("default").results| select id,display_name | Out-GridView -OutputMode Single -Title "Selecteer NSX-T Security policy"

#retrieve NSX-T security Policy firewall rules
$NSXDFWFirewalrulesyproxy = Get-NsxtPolicyService -name com.vmware.nsx_policy.infra.domains.security_policies.rules
$Targetrules = $NSXDFWFirewalrulesyproxy.list("default",$TargetSecurityPolicy.id).results | select display_name, rule_id , tag, action, disabled, logged | Out-GridView -Title "Select DFW rules to view Loginsight data" -PassThru 

#retrieve and filter NSXt Security Groups
$NSXSecurityGroupProxy = Get-NsxtPolicyService -name com.vmware.nsx_policy.infra.domains.groups
$enumSecurityGroups = $NSXSecurityGroupProxy.list("default").results.where({$_.display_name -match "env_|infraSvc|appl_|tier|provider|consumer"})


if (!$AllsecurityGroupsMemberOverview) {
    $NSXSecurityGroupMemberVMProxy =  Get-NsxtPolicyService -name com.vmware.nsx_policy.infra.domains.groups.members.virtual_machines
    $NSXSecurityGroupMemberIPProxy =  Get-NsxtPolicyService -name com.vmware.nsx_policy.infra.domains.groups.members.ip_addresses
    $AllsecurityGroupsMemberOverview = @()
    $SecurityGroupCount = $enumSecurityGroups.Count
    $counter = 0
    ForEach ($SecurityGroupsItem in $enumSecurityGroups) {
        $counter++
        Write-Progress -Activity "Enumerating Security Group Members" -Status "Working on $($SecurityGroupsItem.display_name)" -PercentComplete (($counter/$SecurityGroupCount)*100)
        $securityGroupmemberVMs = $NSXSecurityGroupMemberVMProxy.list("default", $SecurityGroupsItem.id).results
        $securityGroupmemberIps = $NSXSecurityGroupMemberIPProxy.list("default", $SecurityGroupsItem.id).results

        $AllsecurityGroupsMemberOverviewItem = New-Object psobject -Property @{
            SecurityGroup = $SecurityGroupsItem 
            VirtualMachines = $securityGroupmemberVMs
            IPAddresses = $securityGroupmemberIps
        }
        $AllsecurityGroupsMemberOverview += $AllsecurityGroupsMemberOverviewItem
    }
}


#select from here and run partially
$date = get-date -Format yyyy_MM_dd
$PsEventsOutput = @()

foreach ($Targetrule in $Targetrules) {
    if ($Targetrule.logged -and !$Targetrule.disabled) {
        Write-Log -Message "NSX-T DFW Rule $($Targetrule.rule_id) - $($Targetrule.display_name) - Retrieving logs" -Level info
        do {
            $textfilter = $Targetrule.tag
            if ($textfilter) {
                $PsEvents = Get-LoginsightNSXtEvents -TimeStamp 7d -textfilter $textfilter -limit 10000
            } else {
                $PsEvents = Get-LoginsightNSXtEvents -TimeStamp 7d -ruleid $Targetrule.rule_id -limit 10000
            }
        } while ($PsEvents -match "error")

        if ($PsEvents) {
            #dedup $PsEvents
            #$PsEvents = ($PsEvents |Group-Object vmwnsxfirewallsrc, vmwnsxfirewalldst).foreach({$_.group[0]})
            $PsEventsdedupped = ($PsEvents |Group-Object vmwnsxfirewallruleid,vmwnsxfirewallsrc, vmwnsxfirewalldst, vmwnsxfirewallprotocol,vmwnsxfirewallport).foreach({$_.group[0]})        #,vmwnsxfirewallprotocol,vmwnsxfirewallport,vmwnsxfirewallsrc, vmwnsxfirewalldst
            $PsEventsOutput +=  Enum-PSLoginsightevent -PsEvents $PsEventsdedupped -AllsecurityGroupsMemberOverview $AllsecurityGroupsMemberOverview
        }
    } else {
        Write-Log -Message "NSX-T DFW Rule $($Targetrule.rule_id) - $($Targetrule.display_name) - Logging or rule is disabled" -Level Warn
    }
}

$PsEventsOutput | Out-GridView

