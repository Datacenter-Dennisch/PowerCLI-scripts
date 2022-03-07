
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

$SSHModule = "Posh-SSH"
if (!(get-module -name $SSHModule)) {
    Do {
        if (get-module -Name Posh-SSH -ListAvailable) {
            try {
                Write-log -Message "Importing PowerShell Module ""$($SSHModule)"" into current PS-Session." -Level Info
                Import-Module -Name Posh-SSH -MinimumVersion 3.0.0
            } 
            catch {
                Write-log -Message "Module ""$($SSHModule)"" does not exist, installing from Internet" -Level Warn
                try {        
                    Install-Module -Name Posh-SSH -RequiredVersion 3.0.0
                }
                catch {
                    Write-log -Message "Installation Error: manually install $SSHModule to continue" -Level Error
                }
            }
        }

    } until (get-module -name $SSHModule)
} else {
    write-log -Message "PowerShell Module $SSHModule already loaded" -Level Info
}

[string]$vCenterFQDN = "vCenter.vViking.nl"
[string]$vCenterUsername = "Administrator@vsphere.local"
[string]$vCenterPassword = "VMware1!"

[string]$userName = 'tempuser' #local user which will be used for temp SSH sesssion
[string]$userPassword = 'NSXM1Gr@t10n' #temp password for temp SSH user
[securestring]$secStringPassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
[pscredential]$credObject = New-Object System.Management.Automation.PSCredential ($userName, $secStringPassword)

if (!$global:DefaultViServer) {
    do {
        $Null = Connect-VIServer -Server $vCenterFQDN -User $vCenterUsername -Password $vCenterPassword 
    } until ($global:DefaultViServer)
    Write-Log -Message "Successfully connected to vCenter server $vCenterFQDN" -Level Info 
} else {
    Write-Log -Message "Using existing vCenter Connection: $($global:DefaultViServer.Name)" -Level Info
}

$cluster = get-cluster | out-gridview -PassThru -Title "Select vSphere cluster"
$vmhosts = $cluster | get-vmhost | Out-GridView -PassThru -Title "Select vSphere ESXi host to remove AMShelpr VIB from"

$counter = 0
foreach ($vmhost in $vmhosts) {
    $counter ++
    write-progress -activity "removing VUBs from vmhost $($vmhost.name)" -PercentComplete ($counter/$vmhosts.count*100)
    $VMhostSSHService = (Get-VMHostService -VMHost $vmhost).where({$_.key -eq "TSM-SSH"})
    if ($VMhostSSHService.Running -eq $False) {
        write-log -Message "$($vmhost.name): starting SSH deamon" -Level Info
        $null = Start-VMHostService $VMhostSSHService -Confirm:$false
    }

    $esxcli = get-esxcli -vmhost $vmhost -v2 
    write-log -Message "$($vmhost.name): creating local temp user" -Level Info
    $null = $esxcli.system.account.add.Invoke(@{id=$userName;password=$userPassword;passwordconfirmation=$userPassword;description="temporarily SSH user"})
    $null = $esxcli.system.permission.set.invoke(@{id=$username;role="Admin"})
    
    write-log -Message "$($vmhost.name): connecting with SSH" -Level Info
    $SSHsessionid = New-SSHSession -ComputerName $vmhost.name -Credential $credObject -AcceptKey 

    write-log -Message "$($vmhost.name): removing amscli VIB " -Level Info
    $return = Invoke-SSHCommand -Command "esxcli software vib remove -n amscli" -SessionId $SSHsessionid.SessionId
    Write-Log -Message "$($vmhost.name): return output" -Level Info 

      write-log -Message "$($vmhost.name): removing amshelprcli VIB " -Level Info
    $return = Invoke-SSHCommand -Command "esxcli software vib remove -n amshelprcli" -SessionId $SSHsessionid.SessionId
    Write-Log -Message "$($vmhost.name): return output" -Level Info 

    write-log -Message "$($vmhost.name): removing amshelpr VIB " -Level Info
    $return = Invoke-SSHCommand -Command "esxcli software vib remove -n amshelpr" -SessionId $SSHsessionid.SessionId
    Write-Log -Message "$($vmhost.name): return output" -Level Info 

    write-log -Message "$($vmhost.name): disconnecting SSH session" -Level Info
    $null = Remove-SSHSession -SessionId $SSHsessionid.SessionId

    write-log -Message "$($vmhost.name): removing temp local SSH user" -Level Info
    $null = $esxcli.system.account.remove.Invoke(@{id=$userName})

    if ($VMhostSSHService.Running -eq $False) {
        write-log -Message "$($vmhost.name): stopping SSH deamon" -Level Info

        $null = Stop-VMHostService $VMhostSSHService -Confirm:$false
    }
}

$counter = 0
foreach ($vmhost in $vmhosts) {
    $counter ++
    write-progress -activity "rebooting vmhost $($vmhost.name)" -PercentComplete ($counter/$vmhosts.count*100)

    Set-VMHost -VMHost $vmhost -State Maintenance -VsanDataMigrationMode EnsureAccessibility -RunAsync -Confirm:$False | Out-Null

    do {
        Write-Log -Message "$($vmhost.name): Host entering maintance mode ($((get-vm -Location $vmhost).count) VMs remaining)" -Level Info
        sleep 15
    } until ((get-vmhost -Name $vmhost).ConnectionState -eq "Maintenance")
    Write-Log -Message "$($vmhost.name): Host is in Maintance mode" -Level Info

    Write-Log -Message "$($vmhost.name): Reboot initiated" -Level Info
    Restart-VMHost -VMHost $vmhost -confirm:$false -Reason "Rebooting due removal AMS* VIBs" -RunAsync | Out-Null

    Write-Log -Message "$($vmhost.name): Shutting down host" -Level Info
    do {
        sleep 15
        $ServerState = (get-vmhost $vmhost).ConnectionState
    } until ($ServerState -ne "NotResponding")
    Write-Log -Message "$($vmhost.name): Host down" -Level Info

    do {
        sleep 15
        $ServerState = (get-vmhost $vmhost).ConnectionState
    } while ($ServerState -ne "NotResponding")
    Write-Log -Message "$($vmhost.name): Rebooting host " -Level Info

    do {
        sleep 15
        $ServerState = (get-vmhost $vmhost).ConnectionState
        Write-Log -Message "$($vmhost.name): Waiting for host reboot" -Level Info
    } while ($ServerState -ne "Maintenance")
    Write-Log -Message "$($vmhost.name): Host rebooted - Exiting maintenance mode" -Level Info

    Set-VMhost $CurrentServer -State Connected | Out-Null
    Write-Log -Message "$($vmhost.name): Reboot completed" -Level Info
}
