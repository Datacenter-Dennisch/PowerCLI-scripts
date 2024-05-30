$host.ui.RawUI.WindowTitle = “NSX  Migration Script powered by Dennis Lefeber (ITQ) - vViking.nl”

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

if (!$DefaultNSXConnection) {
    
    do {
        $Credential = Get-Credential
        $NSXvMgrIp = "nsxvmgr.vviking.local"
        Write-log -message "Connecting to NSX-v manager ""$($NSXvMgrIp)"" " -Level Info
        $null = Connect-NsxServer -NsxServer $NSXvMgrIp -Credential $Credential -VICredential $Credential
    } while (!$DefaultNSXConnection)
    $GlobalCredential = $Credential
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" established" -Level Info
} else {
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" already established" -Level info
}

$VIServers = $("Destination_vCenter_Server-FQDN")
foreach ($VIServer in $VIServers) {
    if ($global:DefaultVIServers.Name -notcontains $VIServer ) {
        Write-log -message "Connecting to vCenter Server ""$($VIServer)""" -Level Info
        do {
            if (!$GlobalCredential) {$Credential = Get-Credential} else {$Credential = $GlobalCredential}
            $null = Connect-VIServer -Server $VIServer -Credential $Credential
        } until ($global:DefaultVIServer.Name -contains $VIServer )
        $GlobalCredential = $Credential
        Write-log -message "Connection with vCenter Server ""$($VIServer)"" established" -Level Info
    } else {
        Write-log -message "Connection with vCenter Server""$($VIServer)"" already established" -Level info
    }
}

$NSXTServers = $("<NSXTMANAGER-FQDN>")
foreach ($NSXTServer in $NSXTServers) {
    if ($global:DefaultNSXtServers.name -notcontains $NSXTServer ) {
        Write-log -message "Connecting to NSX-T Manager ""$($NSXTServer)""." -Level Info
        do {
            if (!$GlobalCredential) {$Credential = Get-Credential} else {$Credential = $GlobalCredential}
            $null = Connect-NSXTServer -Server $NSXTServer -Credential $Credential
        } until ($global:DefaultNSXtServers.name -contains $NSXTServer )
        $GlobalCredential = $Credential
        Write-log -message "Connection with NSX-T Manager ""$($NSXTServer)"" established" -Level Info
    } else {
        Write-log -message "Connection with NSX-T Manager ""$($NSXTServer)"" already established" -Level info
    }
}

#retrieve NSX Security Groups
write-log -Message "Retrieving NSX Security Group information" -Level Info
$AllNSXVSecGroups = Get-NsxSecurityGroup
write-log -Message "Retrieving NSX Security Group information: Completed" -Level Info

write-log -Message "Retrieving NSX Firewall rulebase information" -Level Info
$AllNSXDFWSections =  Get-NsxFirewallSection
$AllNSXVDFWrulebase = $AllNSXDFWSections | Get-NsxFirewallRule
write-log -Message "Retrieving NSX Firewall rulebase information: Completed" -Level Info

write-log -Message "Retrieving NSX IpSet information" -Level Info
$AllIpSetObjects = Get-NsxIpSet
write-log -Message "Retrieving NSX IpSet information: Completed" -Level Info

function Add-NSXT_migration_nsgroup_ipaddresses {
    Param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [pscustomobject]$migSecGrouplist,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$displayname,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ipaddresses
    )

    Begin {
        $ExistinIPAddresses = $migSecGrouplist.where({$_.display_name -eq "test2"}).ipaddresses
        if ($ExistinIPAddresses) {
            $newIPAddresses = $ExistinIPAddresses,$ipaddresses -join ","
        } else {
            $newIPAddresses = $ipaddresses
        }
        $migSecGrouplist.where({$_.display_name -eq $displayname}) | %{$_.iPAddresses = $newIPAddresses}
        Return $migSecGrouplist
    }
}

function Add-NSXT_migration_nsgroup_criteria {
    Param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [pscustomobject]$migSecGrouplist,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$displayname="test2",
        [Parameter(Mandatory=$true)]
        [ValidateSet('VirtualMachine','Segment','SegmentPort')]
        [string]$membertype,
        [Parameter(Mandatory)]
        [ValidateSet('Tag','Name','OSName','ComputerName')]
        [string]$key,
        [Parameter(Mandatory=$true)]
        [ValidateSet('EQUALS','CONTAINS','STARTSWITH','ENDSWITH','NOTEQUALS')]
        [string]$Operator,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$value
    )

    Begin {
        if ($migSecGrouplist.where({$_.display_name -eq $displayname}).criteria.count -le 4) {
            $newcriteria = [pscustomobject][ordered]@{
                membertype = $membertype 
                key = $key
                operator  = $operator
                value = $value
            }
            $migSecGrouplist.where({$_.display_name -eq $displayname}) | %{$_.criteria += $newcriteria}
        } else {
            write-log "Migration Security group $($displayname) contains more than 5 criteria, which isn't supported" -Level warn
        }
        Return $migSecGrouplist
    }
}

function New-NSXT_migration_nsgroup {
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$displayname
    )

    Begin {
        $migSecGrouplistitem = [pscustomobject][ordered]@{
            display_name = $displayname
            description = "Created by DFW migration script"
            iPAddresses = $null
            criteria = @()
            member = @()
        }
        return $migSecGrouplistitem
    }
}

$migSecGrouplist = @()
#$migSecGrouplist += New-NSXT_migration_NSGROUP -displayname test1
#$migSecGrouplist = Add-NSXT_migration_nsgroup_ipaddresses -migSecGrouplist $migSecGrouplist -displayname "test2" -ipaddresses 1.2.3.4
#$migSecGrouplist = Add-NSXT_migration_nsgroup_criteria -migSecGrouplist $migSecGrouplist -displayname "test2" -membertype VirtualMachine -key Tag -Operator EQUALS -value "test2"

$WarningDFWMigList = @()
$migDFWrulebase = @()
$migSecGrouplist = @()
foreach ($DFWrule in $AllNSXVDFWrulebase[8]) {
    $DFWrulename = "$($DFWrule.name.replace(" ","_"))"

    $migDFWrulesource = @()
    foreach ($dfwsrcobj in $DFWrule.sources.source) {
        
        switch ($dfwsrcobj.type) {
            SecurityGroup {
                $migDFWruleSourceItem += $AllNSXVSecGroups.where({$_.objectId -eq $dfwsrcobj.value}) 
            }
            IPSet {
                $IpSetobj = $AllIpSetObjects.where({$_.objectId -eq $dfwsrcobj.value})
                if ($migSecGrouplist.name -notcontains "$($DFWrulename)-Source" ) {
                    $migSecGrouplist += New-NSXT_migration_NSGROUP -displayname "$($DFWrule.name)-SourceList"
                    $migSecGrouplist = Add-NSXT_migration_nsgroup_ipaddresses -migSecGrouplist $migSecGrouplist -displayname "$($DFWrulename)-Source" -ipaddresses $($IpSetobj.value)
                } else {
                    $migSecGrouplist = Add-NSXT_migration_nsgroup_ipaddresses -migSecGrouplist $migSecGrouplist -displayname "$($DFWrulename)-Source" -ipaddresses $IpSetobj.value
                }
            }
            VirtualMachine {}
            VirtualWire {}
            Network {}
            DistributedVirtualPortgroup {}
            Default {
                #write-log -Message "DFW rule id $($DFWrule.id) (""$($DFWrule.name)""): Sourceobject ""$($dfwsrcobj.name)"" of type ""$($dfwsrcobj.type)"" is not supported on NSX-T}" -Level Warn
                $WarningDFWMigList += "DFW rule id $($DFWrule.id) (""$($DFWrule.name)""): contains invalid source object ""$($dfwsrcobj.name)"" of type ""$($dfwsrcobj.type)""."
            }
        }
        $migDFWrulesource += $migDFWruleSourceItem
    }
    foreach ($dfwdstobj in $DFWrule.destinations.destination) {

    }

}
    

foreach ($MigrationDetailsItem in $MigrationDetails) {
    foreach ($secgroup in $MigrationDetailsItem.Source_Sec_groups) {
        $secgroup = Get-NsxSecurityGroup -objectId $secgroup.objectId
        $AllIpSetObjects = Get-NsxIpSet
        $secgroupIpsetIpv4Object = $AllIpSetObjects.Where({$_.name -eq "ref_ipv4_$($secgroup.name)"})
        $secgroupIpsetIpv6Object = $AllIpSetObjects.Where({$_.name -eq "ref_ipv6_$($secgroup.name)"})

        #check if security group reference IPset ipv4 object exist, if not: create one
        if (!$secgroupIpsetIpv4Object) {
            $secgroupIpsetIpv4Object = New-NsxIpSet -Name "ref_ipv4_$($secgroup.name)" -Description "NSX V2T Reference object"
            write-log -Message "$($secgroup.name) : Reference IpSet Object does not exist, created new IpSet Object ""$($secgroupIpsetIpv4Object.name)"" " -Level Info
        } else {
            write-log -Message "$($secgroup.name) : Reference IpSet Object  ""$($secgroupIpsetIpv4Object.name)"" already exists " -Level info
        }

        #check if security group reference IPset ipv6 object exist, if not: create one
        if (!$secgroupIpsetIpv6Object) {
            $secgroupIpsetIpv6Object = New-NsxIpSet -Name "ref_Ipv6_$($secgroup.name)" -Description "NSX V2T Reference object"
            write-log -Message "$($secgroup.name) : Reference IpSet Object does not exist, created new IpSet Object ""$($secgroupIpsetIpv6Object.name)"" " -Level Info
        } else {
            write-log -Message "$($secgroup.name) : Reference IpSet Object  ""$($secgroupIpsetIpv6Object.name)"" already exists " -Level info
        }

        #check if reference IPset ipv4 object is member of security group
        if ($secgroup.member.objectid -notcontains $secgroupIpsetIpv4Object.objectid) {
            Add-NsxSecurityGroupMember -SecurityGroup $secgroup -Member $secgroupIpsetIpv4Object 
            write-log -Message "$($secgroup.name) : Added Reference IpSet Object ""$($secgroupIpsetIpv4Object.name)"" as a member " -Level Info
            $secgroup = Get-NsxSecurityGroup -objectId $secgroup.objectId
        }

        #check if reference IPset ipv6 object is member of security group
        if ($secgroup.member.objectid -notcontains $secgroupIpsetIpv6Object.objectid) {
            Add-NsxSecurityGroupMember -SecurityGroup $secgroup -Member $secgroupIpsetIpv6Object 
            write-log -Message "$($secgroup.name) : Added Reference IpSet Object ""$($secgroupIpsetIpv6Object.name)"" as a member " -Level Info
            $secgroup = Get-NsxSecurityGroup -objectId $secgroup.objectId
        }

        foreach ($IP in $MigrationDetailsItem.VM_object.Guest.IPAddress) {
            $IP = [ipaddress]$IP

            switch ($IP.AddressFamily) {
            
             "InterNetwork" {
                    if ($secgroupIpsetIpv4Object.value -notmatch $IP) {
                        $secgroupIpsetIpv4Object = Get-NsxIpSet -objectId $secgroupIpsetIpv4Object.objectid
                        Add-NsxIpSetMember -IPAddress $IP -IPSet $secgroupIpsetIpv4Object | Out-Null
                        write-log -Message "$($secgroupIpsetIpv4Object.name) : Added IP ""$($IP)"" " -Level Info
                    } else {
                        write-log -Message "$($secgroupIpsetIpv4Object.name) : IP ""$($IP)"" was already added " -Level Info
                    }
                }
            "InterNetworkv6" {
                    if ($secgroupIpsetIpv6Object.value -notmatch $IP) {
                        $secgroupIpsetIpv6Object = Get-NsxIpSet -objectId $secgroupIpsetIpv6Object.objectid
                        Add-NsxIpSetMember -IPAddress $IP.ToString() -IPSet $secgroupIpsetIpv6Object | Out-Null
                        write-log -Message "$($secgroupIpsetIpv6Object.name) : Added IP ""$($IP)"" " -Level Info
                    } else {
                        write-log -Message "$($secgroupIpsetIpv6Object.name) : IP ""$($IP)"" was already added " -Level Info
                    }
                }
            }
        }
    }
}



$nsxtsecgroupproxy = Get-NsxtGlobalManagerService -name com.vmware.nsx_global_policy.global_infra.domains.groups

foreach ($MigrationDetailsItem in $MigrationDetails) {
    $nsxtglobalsecuritygroup = $nsxtsecgroupproxy.list("default").results
    $destinationsecgroupname = ($MigrationDetailsItem.Destination_L3_tag_name).Replace("ST-","SG-")
        
    #check if NSX-T Security Group for Applications exists and create on if none exists.
    if ($nsxtglobalsecuritygroup.display_name -notcontains $destinationsecgroupname) {

        $nsxtsecgroupspec = $nsxtsecgroupproxy.help.patch.group.Create()
        $nsxtsecgroupspec.display_name = $destinationsecgroupname 

        $nsxtsecgroupidspec = $nsxtsecgroupproxy.Help.patch.group_id.Create()
        $nsxtsecgroupidspec = $destinationsecgroupname

        $nsxtsecgroupexpressionspec = $nsxtsecgroupproxy.help.patch.group.expression.Element.condition.Create()
        $nsxtsecgroupexpressionspec.member_type = "VirtualMachine"
        $nsxtsecgroupexpressionspec.key = "Tag" 
        $nsxtsecgroupexpressionspec.value =  $MigrationDetailsItem.Destination_L3_tag_name
        $nsxtsecgroupexpressionspec.operator = "EQUALS"
        $nsxtsecgroupspec.expression.add($nsxtsecgroupexpressionspec) | Out-Null

        $nsxtsecgroupproxy.patch("default",$nsxtsecgroupidspec,$nsxtsecgroupspec)
        Write-Log -Message "$($destinationsecgroupname): NSX-T Security group created" -Level info
    } else {
        Write-Log -Message "$($destinationsecgroupname): NSX-T Security group already exists" -Level info
    }

        
    $nsxtDFWsecuritypolicyproxy = Get-NsxtGlobalManagerService -name com.vmware.nsx_global_policy.global_infra.domains.security_policies
    $nsxtDFWsecuritypolicy = ($nsxtDFWsecuritypolicyproxy.list("default").results.where({$_.display_name -eq ""}))

    $nsxtDFWsecuritypolicyproxy.help.update.security_policy.rules.Element.Create()
    $nsxtDFWsecuritypolicyrulesproxy = Get-NsxtGlobalManagerService -name com.vmware.nsx_global_policy.global_infra.domains.security_policies.rules

    #check if firewall rule for application isolation exists and create one if none exists.
    if ($nsxtDFWsecuritypolicyproxy.list("default", $nsxtDFWsecuritypolicy.id).results.display_name -notcontains $destinationsecgroupname) {
        $nsxtDFWsecuritypolicyspec = $nsxtDFWsecuritypolicyproxy.help.update.security_policy.Documentation
        
        #create rules variable
        $nsxtDFWsecuritypolicyrulespec = $nsxtDFWsecuritypolicyproxy.help.update.security_policy.rules.Element.Create()
       
        $nsxtDFWsecuritypolicyrulespec.disabled = "false"
        $nsxtDFWsecuritypolicyrulespec.action = "REJECT"
        $nsxtDFWsecuritypolicyrulespec.display_name = $destinationsecgroupname
        $nsxtDFWsecuritypolicyrulespec.id = $destinationsecgroupname.Replace(" ","_")
        $nsxtDFWsecuritypolicyrulespec.tag = $destinationsecgroupname
        $nsxtDFWsecuritypolicyrulespec.logged = "true"
        #$nsxtDFWsecuritypolicyrulespec.sequence_number = $item.SequenceNr
        $nsxtDFWsecuritypolicyrulespec.source_groups = $destinationsecgroupname
        $nsxtDFWsecuritypolicyrulespec.sources_excluded = "false"
        $nsxtDFWsecuritypolicyrulespec.destination_groups = $destinationsecgroupname
        $nsxtDFWsecuritypolicyrulespec.destinations_excluded = "TRUE"
        $nsxtDFWsecuritypolicyrulespec.services = "ANY" 
        $nsxtDFWsecuritypolicyrulespec.scope = $destinationsecgroupname

        $nsxtDFWsecuritypolicyspec.rules.add($nsxtDFWsecuritypolicyrulespec) | out-null
        $nsxtDFWsecuritypolicyproxy.update("default",$nsxtDFWsecuritypolicy.id ,$nsxtDFWsecuritypolicyspec)

    }

}

$Error[0].Exception.ServerError.data
