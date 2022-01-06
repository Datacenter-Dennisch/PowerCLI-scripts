
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
    $NSXvMgrIp = "NSXMGR01.vViking.nl"
    Write-log -message "Connecting to NSX-v manager ""$(NSXvMgrIp)"" " -Level Info
    do {
        $Credential = Get-Credential
        $null = Connect-NsxServer -NsxServer $NSXvMgrIp -Credential $Credential -VICredential $Credential
    } while (!$DefaultNSXConnection)
    $GlobalCredential = $Credential
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" established" -Level Info
} else {
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" already established" -Level info
}

write-log -Message "Retrieving NSX-disabled vSphere clusters" -Level Info
$NSXDFWEnabledClusters = @()
foreach ($vSphereCluster in get-cluster -Server NSXvMgrIp) {
    if (($vSphereCluster | Get-NsxClusterStatus).where({$_.featureId -eq "com.vmware.vshield.firewall" -and $_.installed -eq "false"})) {
        $NSXDFWEnabledClusters += $vSphereCluster
    }
}
write-log -Message "Retrieving NSX-disabled vSphere clusters: Completed" -Level Info
$NSXDFWEnabledClusters = $NSXDFWEnabledClusters | Out-GridView -OutputMode Multiple

write-log -Message "Retrieving NSX-disabled vSphere cluster virtual machines" -Level Info
$vMobjects = $NSXDFWEnabledClusters | get-vm
$vMobjects = ($vMobjects | Get-NsxSecurityTagAssignment).VirtualMachine

$vMobjects += (Get-NsxFirewallExclusionListMember)
write-log -Message "Retrieving NSX-disabled vSphere cluster virtual machines: Completed" -Level Info

write-log -Message "Retrieving NSX IpSet information" -Level Info
$AllIpSetObjects = Get-NsxIpSet
write-log -Message "Retrieving NSX IpSet information: Completed" -Level Info

foreach ($VMobj in $vMobjects) {
    #retrieve Vm IPv4 information
    $VMIps = $VMobj.Guest.IPAddress
    $VMIpv4s = @()
    foreach ($VMIp in $VMIps) {
         if (([ipaddress]$VMIp).AddressFamily -eq "InterNetwork") {$VMIpv4s += $VMIp}
    }

    #retrieve Reference IPSet object name
    $RefIpSetObjName = "IPSet:VM-$($VMobj.name)"

    #check or creating reference IP Set Object per VM
    write-log -Message "$($VMobj) - Checking Reference IP Set object" -Level Info
    if (!($AllIpSetObjects.where({$_.name -eq $RefIpSetObjName}))) {
        write-log -Message "$($RefIpSetObjName ) - Creating IP Set object" -Level Info
        $RefIpSetObj = New-NsxIpSet -Name $RefIpSetObjName -IPAddress $VMIpv4s -Description "Automatically created for NSX-V2T migration" 
        $AllIpSetObjects = Get-NsxIpSet
        write-log -Message "$($RefIpSetObjName) - Creating IP Set object: Completed" -Level Warn
    } else {
        write-log -Message "$($RefIpSetObjName) - Existing IP Set object retrieved" -Level Info
        $RefIpSetObj = $AllIpSetObjects.where({$_.name -eq $RefIpSetObjName})
        #check IP member
        foreach ($VMIpv4 in $VMIpv4s) {
            if ($RefIpSetObj.value -match $VMIpv4) {
                write-log -Message "NSX IpSet obj $($RefIpSetObj.name) contains IP Address $($VMIpv4)" -level info
            } else {
                write-log -Message "NSX IpSet obj $($RefIpSetObj.name) does not contain IP Address $($VMIpv4), adding.." -level warn
                $null = $RefIpSetObj | Add-NsxIpSetMember -IPAddress $VMIpv4
                $RefIpSetObj = Get-NsxIpSet -objectId $RefIpSetObj.objectId
            }
        }
    }
    write-log -Message "$($VMobj) - Checking Reference IP Set object: Completed" -Level Info

    write-log -Message "$($VMobj) - Retrieving VM NSX Security Group membership" -Level Info
    $VMSecGroupmemberships = $VMobj | Get-NsxSecurityGroup

    foreach ($VMSecGroupmembership in $VMSecGroupmemberships) {
        write-log -Message "$($VMobj) - Checking NSX SecGroup Membership ""$($VMSecGroupmembership.name)" -Level Info
        if ($VMSecGroupmembership.member.objectId -notcontains $RefIpSetObj.objectid) {
            write-log -Message "$($VMobj) - Adding NSX Ip Set $($RefIpSetObj.name) to NSX SecGroup ""$($VMSecGroupmembership.name)""." -Level Info
            $VMSecGroupmembership | Add-NsxSecurityGroupMember -Member $RefIpSetObj
            write-log -Message "$($VMobj) - Adding NSX Ip Set $($RefIpSetObj.name) to NSX SecGroup ""$($VMSecGroupmembership.name)"" : completed" -Level Warn
        } else {
            write-log -Message "$($VMobj) - NSX Ip Set $($RefIpSetObj.name) already member of NSX SecGroup ""$($VMSecGroupmembership.name)"" : completed" -Level Info
        }
        write-log -Message "$($VMobj) - Checking NSX SecGroup Membership ""$($VMSecGroupmembership.name): Completed" -Level Info
    }
}


