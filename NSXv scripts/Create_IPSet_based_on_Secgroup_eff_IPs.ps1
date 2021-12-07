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
    Write-log -message "Connecting to NSX-v manager ""nsxvmgr.vviking.nl""." " -Level Info
    do {
        $Credential = Get-Credential
        $NSXvMgrIp = "nsxvmgr.vviking.nl"
        $null = Connect-NsxServer -NsxServer $NSXvMgrIp -Credential $Credential -VICredential $Credential
    } while (!$DefaultNSXConnection)
    $GlobalCredential = $Credential
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" established" -Level Info
} else {
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" already established" -Level info
}

$Secgroups = Get-NsxSecurityGroup  | out-gridview -passthru

foreach ($Secgroup in $Secgroups) {
    $linuxSgIps = $Secgroup | Get-NsxSecurityGroupEffectiveIpAddress 

    $IpMember = $()
    foreach ($linuxSgIp in $linuxSgIps.IpAddress) {
        $checkip = [ipaddress]$linuxSgIp
        if ($checkip.AddressFamily -eq "InterNetwork") {$IpMember += @($linuxSgIp)}
    }
    $IpMember = ($IpMember |Group-Object).foreach({$_.group[0]})

    write-host "$($IpMember.count) Ipv4's found for security group $($Secgroup.name)"

    $Ipsetobj = Get-NsxIpSet -name "IP_$($Secgroup.name)"
    if (!$Ipsetobj) {
        $IpSetobj = New-NsxIpSet "IP_$($Secgroup.name)" -IPAddress $IpMember
        Write-Log -Message "Creating new IPSet object: ""$($IpSetobj.name)""." -Level Info
        #$Secgroup | Add-NsxServiceGroupMember -Member $IpSetobj
        Write-Log -Message "Adding IPSet object: ""$($IpSetobj.name)"" to Security Group ""$($Secgroup.name)""." -Level Info
    } else {
        $NewIps = (Compare-Object -ReferenceObject $IpMember -DifferenceObject $Ipsetobj.value.split(",")).where({$_.Sideindicator -eq "<="}).inputobject
        if ($NewIps) {
            $Ipsetobj = $Ipsetobj | Add-NsxIpSetMember -IPAddress $NewIps
            Write-Log -Message "Adding IP addresses to IPSet object: ""$($IpSetobj.name)"": $NewIps." -Level Info
            $Ipsetobj = Get-NsxIpSet -name "IP_$($Secgroup.name)"
        }
        
        $RemoveIps = (Compare-Object -ReferenceObject $IpMember -DifferenceObject $Ipsetobj.value.split(",")).where({$_.Sideindicator -eq "=>"}).inputobject
        if ($RemoveIps) {
            $Ipsetobj = $Ipsetobj | remove-NsxIpSetMember -IPAddress $RemoveIps
            Write-Log -Message "Removing IP addresses from IPSet object: ""$($IpSetobj.name)"":$RemoveIps" -Level Warn

            $Ipsetobj = Get-NsxIpSet -name "IP_$($Secgroup.name)"
        }
    }

}

