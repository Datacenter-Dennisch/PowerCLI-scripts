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

function Get-LoginsightNSXEvents {
    
    param (
        [psobject] $ConnectionPS = $Global:DefaultPSLogInsightserver,
        [string] $textfilter,
        [string] $ruleid,
        [int32] $limit 
    )

    Process {
        if (([DateTimeOffset]::Now.ToUnixTimeSeconds()) -gt $ConnectionPS.TTLexpires) {Connect-LogInsightServer -reconnnect $true}
        $URI = $ConnectionPS.BaseURI + "/events/text/dfwpktlogs"
        if ($textfilter) {$URI += "/text/"+$textfilter}
        if ($ruleid) {$URI += "/ruleid/"+$ruleid}
        $URI += "?content-pack-fields=com.vmware.nsx-v"
        if ($limit) {$URI += "&limit=$($limit)"}
        write-host $URI
        try {
            $response = Invoke-WebRequest -Uri $URI  -Method get -Headers $ConnectionPS.Header
        }
        catch {
            $_.Exception.Message
        }
        if ($response) {
            $events = ($response.Content | ConvertFrom-Json).events
            $PsEvents = @()
            foreach ($event in $events) {
                #write-host $event.fields.name
                $vmwnsxfirewallruleidspec = $event.fields.Where({$_.name -eq "com.vmware.nsx-v:vmw_nsx_firewall_ruleid"}) 
                $vmwnsxfirewallsrcspec = $event.fields.Where({$_.name -eq "com.vmware.nsx-v:vmw_nsx_firewall_src"}) 
                $vmwnsxfirewalldstspec = $event.fields.Where({$_.name -eq "com.vmware.nsx-v:vmw_nsx_firewall_dst"}) 
                $vmwnsxfirewallprotocolspec = $event.fields.Where({$_.name -eq "com.vmware.nsx-v:vmw_nsx_firewall_dst_port"}) 
                $vmwnsxfirewallportspec = $event.fields.Where({$_.name -eq "com.vmware.nsx-v:vmw_nsx_firewall_protocol"}) 
                $vmwnsxfirewallportspec = $event.fields.Where({$_.name -eq "com.vmware.nsx-v:vmw_nsx_firewall_protocol"}) 
                $vmwnsxfirewallActionspec = $event.fields.Where({$_.name -eq "com.vmware.nsx-v:vmw_nsx_firewall_action"}) 
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
        }
    }
}

function Enum-PSLoginsightevent {

    param(
        [Parameter(Position=0,mandatory=$true,ValueFromPipeline=$True)]
        [psobject]$PsEvents
    )

    process {
        if (!$global:DefaultVIServer) {Write-Error "Not connected to vCenter"}
        $ReturnOutput = @()
        if (!$NoDNSRecordlist) {$NoDNSRecordlist = @()}

        foreach ($PsEventItem in $PsEvents) {
    
            $Sourcevmname = $VMoverview.where({$_.IpAddresses-contains $PsEventItem.vmwnsxfirewallsrc}).VmName
            if (!$Sourcevmname) {
                try {$Sourcevmname =([system.net.dns]::GetHostByAddress($PsEventItem.vmwnsxfirewallsrc)).hostname}
                catch {
                    write-host "no DNS record for $($PsEventItem.vmwnsxfirewallsrc)"
                    $NoDNSRecordlist += $PsEventItem.vmwnsxfirewallsrc
                } 
            }
   
            $Destinationvmname = $VMoverview.where({$_.IpAddresses-contains $PsEventItem.vmwnsxfirewalldst}).VmName
            if (!$Destinationvmname) {
                try {$Destinationvmname = ([system.net.dns]::GetHostByAddress($PsEventItem.vmwnsxfirewalldst)).hostname}
                catch {
                    write-host "no DNS record for $($PsEventItem.vmwnsxfirewalldst)"
                    $NoDNSRecordlist += $PsEventItem.vmwnsxfirewalldst
                }
            }

            $ReturnItem = New-Object psobject -Property @{
                vmwnsxfirewallruleid = $PsEventItem.vmwnsxfirewallruleid
                vmwnsxfirewallsrc = $PsEventItem.vmwnsxfirewallsrc
                sourceVMname = $Sourcevmname
                vmwnsxfirewalldst = $PsEventItem.vmwnsxfirewalldst
                destinationVMname = $Destinationvmname
                vmwnsxfirewallprotocol = $PsEventItem.vmwnsxfirewallprotocol
                vmwnsxfirewallport = $PsEventItem.vmwnsxfirewallport
                vmwnsxfirewallaction = $PsEventItem.vmwnsxfirewallaction 
            }
            $ReturnOutput += $ReturnItem 
        }
        return $ReturnOutput
    }
}


if (!$Global:DefaultPSLogInsightserver) {
    do {
        $vrlicred = Get-Credential -Message "Please Enter Loginsight credentials"
        Connect-LogInsightServer -Server "vrli.ssc.lan" -Credentials $vrlicred -Provider ActiveDirectory 
    } until ($Global:DefaultPSLogInsightserver)
}
    
$Targetrule = Get-NsxFirewallRule | Out-GridView -Title "Select DFW rule to view data" -PassThru
$LogTag = $Targetrule.tag
$ruleid = $Targetrule.id

$PsEvents = Get-LoginsightNSXEvents -ruleid $ruleid 

#dedup $PsEvents
$PsEvents = ($PsEvents |Group-Object vmwnsxfirewallsrc, vmwnsxfirewalldst,vmwnsxfirewallprotocol,vmwnsxfirewallport).foreach({$_.group[0]})

$PsEvents = $PsEvents | Enum-PSLoginsightevent
$PsEvents | Out-GridView



