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
    write-log -Message "No connection with NSX-v manager detected" -Level Warn
    do {
        $NSXvMgrIp = "nsxmanager.vviking.local"
        $NSXvMgrUsername = read-host "enter nsx admin account name"
        $NSXvMgrPwd = read-host "enter password" -AsSecureString
        $NSXvMgrCred = New-Object System.Management.Automation.PSCredential($NSXvMgrUsername, $NSXvMgrPwd)   
        Connect-NsxServer -NsxServer $NSXvMgrIp -Credential $NSXvMgrCred -VICredential $NSXvMgrcred
    } while (!$DefaultNSXConnection)
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" established" -Level Info
} else {
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" already established" -Level info
}

$SSHModule = "Posh-SSH"
Do {
    try {
        Import-Module $SSHModule Import-Module $SSHModule -MinimumVersion 3.0.0
    } 
    catch {
        Write-Host "Module ""$($SSHModule)"" does not exist, installing"
        try {        
            Install-Module -Name Posh-SSH -RequiredVersion 3.0.0
        }
        catch {
            Write-log -Message "Installation Error: manually install $SSHModule to continue"
        }
    }

} until (get-module -name $SSHModule)

$NSXDFWEnabledClusters = @()
$NSXDFWEnabledVMHosts = @()

foreach ($vSphereCluster in get-cluster) {
    if (($vSphereCluster | Get-NsxClusterStatus).where({$_.featureId -eq "com.vmware.vshield.firewall" -and $_.installed -eq "true"})) {
        $NSXDFWEnabledClusters += $vSphereCluster
        $NSXDFWEnabledVMHosts += $vSphereCluster | get-vmhost
    }
}

[string]$userName = 'tempuser' #local user which will be used for temp SSH sesssion
[string]$userPassword = 'NSXM1Gr@t10n' #temp password for temp SSH user
[securestring]$secStringPassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
[pscredential]$credObject = New-Object System.Management.Automation.PSCredential ($userName, $secStringPassword)

foreach ($NSXDFWEnabledVMHost in $NSXDFWEnabledVMHosts[39]) {

    $VMhostSSHService = (Get-VMHostService -VMHost $NSXDFWEnabledVMHost).where({$_.key -eq "TSM-SSH"})
    if ($VMhostSSHService.Running -eq $False) {
        write-log -Message "$($NSXDFWEnabledVMHost.name): starting SSH deamon" -Level Info
        $null = Start-VMHostService $VMhostSSHService -Confirm:$false
    }

    $esxcli = get-esxcli -vmhost $NSXDFWEnabledVMHost -v2 
    write-log -Message "$($NSXDFWEnabledVMHost.name): creating local temp user" -Level Info
    $null = $esxcli.system.account.add.Invoke(@{id=$userName;password=$userPassword;passwordconfirmation=$userPassword;description="temporarily user for setting NSX DFW filters to export version 1000"})
    $null = $esxcli.system.permission.set.invoke(@{id=$username;role="Admin"})
    
    write-log -Message "$($NSXDFWEnabledVMHost.name): connecting with SSH" -Level Info
    $SSHsessionid = New-SSHSession -ComputerName $NSXDFWEnabledVMHost.name -Credential $credObject -AcceptKey 

    write-log -Message "$($NSXDFWEnabledVMHost.name): retrieving filternames " -Level Info
    $return = Invoke-SSHCommand -Command "vsipioctl getfilters | grep ""Filter Name"" | grep ""sfw.2""" -SessionId $SSHsessionid.SessionId
    
    if ($return.output -ne "") {
        $filternames = $return.Output.ForEach({$_.split(":")[1]})
    
        write-log -Message "$($NSXDFWEnabledVMHost.name): retrieving exportversions from filternames " -Level Info
        foreach ($filtername in $filternames) {
            $return = Invoke-SSHCommand -Command "vsipioctl getexportversion -f$($filtername)" -SessionId $SSHsessionid.SessionId
            $Exportversion = ($return.Output.split(":")[1]).Substring(1)
            write-log -Message "$($NSXDFWEnabledVMHost.name): exportversions for filtername $($filtername) is $($Exportversion)" -Level Info
            if ($Exportversion -ne 1000) {
                do {
                    write-log -Message "$($NSXDFWEnabledVMHost.name): changing export version to 1000 for filter$($filtername)" -Level Info
                    $return = Invoke-SSHCommand -Command "vsipioctl setexportversion -f$($filtername) -e 1000" -SessionId $SSHsessionid.SessionId
                    $return = Invoke-SSHCommand -Command "vsipioctl getexportversion -f$($filtername)" -SessionId $SSHsessionid.SessionId
                    $Exportversion = ($return.Output.split(":")[1]).Substring(1)
                } until ($Exportversion -eq 1000)
            }
        
        }
    } else {
            write-log -Message "$($NSXDFWEnabledVMHost.name): no filters available" -Level Warn
    }

    write-log -Message "$($NSXDFWEnabledVMHost.name): disconnecting SSH session" -Level Info
    $null = Remove-SSHSession -SessionId $SSHsessionid.SessionId

    write-log -Message "$($NSXDFWEnabledVMHost.name): removing temp local SSH user" -Level Info
    $null = $esxcli.system.account.remove.Invoke(@{id=$userName})

    if ($VMhostSSHService.Running -eq $False) {
        write-log -Message "$($NSXDFWEnabledVMHost.name): stopping SSH deamon" -Level Info
        $null = Stop-VMHostService $VMhostSSHService -Confirm:$false
    }
}

