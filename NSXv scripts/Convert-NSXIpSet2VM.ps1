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
        [string]$Path='D:\Security scripts\Logs\debug1.log',
        
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

function New-IPv4toBin ($ipv4)
    {
        $BinNum = $ipv4 -split '\.' | ForEach-Object {[System.Convert]::ToString($_,2).PadLeft(8,'0')}
        return $binNum -join ""
    }

function Test-IPinIPRange ($Address,$Lower,$Mask) {

    #if ($Address -match "/") {$Address = $Address.Split("/")[0] }
    #if ($Address -match "-") {$Address = $Address.Split("-")[0] }
    $checkip = [ipaddress]$Address
    if ($checkip.AddressFamily -eq "InterNetwork") {

        [Char[]]$a = (New-IPv4toBin $Lower).ToCharArray()
        if ($mask -like "*.*")  {
                [Char[]]$b = (New-IPv4toBin $Mask).ToCharArray()
        } else {
            [Int[]]$array = (1..32)
            for ($i=0;$i -lt $array.length;$i++) {
                if($array[$i] -gt $mask){$array[$i]="0"}else{$array[$i]="1"}
            }
            [string]$mask = $array -join ""
            [Char[]]$b = $mask.ToCharArray()
        }
        [Char[]]$c = (New-IPv4toBin $Address).ToCharArray()
        $res = $true
        for($i=0;$i -le $a.length;$i++) {
            if ($a[$i] -ne $c[$i] -and $b[$i] -ne "0") {$res = $false }
        }
    }
    return $res
}

Function Get-IPRange {
param (
  [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)][IPAddress]$lower,
  [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)][IPAddress]$upper
)
  # use lists for speed
  $IPList = [Collections.ArrayList]::new()
  $null = $IPList.Add($lower)
  $i = $lower

  # increment ip until reaching $upper in range
  while ( $i -ne $upper ) { 
    # IP octet values are built back-to-front, so reverse the octet order
    $iBytes = [BitConverter]::GetBytes([UInt32] $i.Address)
    [Array]::Reverse($iBytes)

    # Then we can +1 the int value and reverse again
    $nextBytes = [BitConverter]::GetBytes([UInt32]([bitconverter]::ToUInt32($iBytes,0) +1))
    [Array]::Reverse($nextBytes)

    # Convert to IP and add to list
    $i = [IPAddress]$nextBytes
    $null = $IPList.Add($i)
  }

  return $IPList
}

# retrieve VM objects with only Ipv4 addresses .. patience 
write-log -Message "Retrieving VM IPv4 addresses" -Level Info
$AllVmObj = get-vm
$AllVmIpv4Obj = @()
if (!$AllVmIpv4Obj) {
    $AllVmIpv4Obj = @()
    $Counter = 0
    foreach ($VMobj in $AllVmObj) {
        $Counter ++
        write-progress -Activity "retreiving VM information" -Status "filtering IPv4 addresses" -PercentComplete (($counter/$AllVmObj.count)*100)
        $VmObjIPs = $VMobj.Guest.IPAddress
        $VmObjIPv4s = @()
        foreach ($VmObjIP in $VmObjIPs) {

            $checkip = [ipaddress]$VmObjIP
            if ($checkip.AddressFamily -eq "InterNetwork") {$VmObjIPv4s += $VmObjIP}
        }
        $Vmobjexport = [pscustomobject][ordered]@{
            VmObj = $VMobj
            Ipv4addresses = $VmObjIPv4s
        }
        $AllVmIpv4Obj += $Vmobjexport
    }
}
write-log -Message "Retrieving VM object IPv4 addresses: completed" -Level Info


#make NSX IpSet object selection
$IpSetObjSelection = Get-NsxIpSet | Out-GridView -OutputMode Multiple -Title "Select NSX IpSet objects"

$export = @()
$Counter = 0
write-log -Message "Converting IpSet object to VM objects" -Level Info
#run foreach for each individual NSX IpSet object
foreach ($IpSetObj in $IpSetObjSelection ) {
    $Counter ++
    write-progress -Activity "retreiving VM information" -Status "Converting IpSet object ""$($IpSetObj.name)"" to VM objects" -PercentComplete (($counter/$IpSetObjSelection.count)*100)
    #retrieve IP members from NSX IpSet object 
    $IpSetObjIpAddresses = $IpSetObj.value.split(",")

    $IpSetVmObj = @()
    #retrieve Vm-objects for each IP member
    foreach ($IpSetObjIpAddress in $IpSetObjIpAddresses) {
        #retrieve  VM-object for IP address
        if ($IpSetObjIpAddress -notmatch "/" -and $IpSetObjIpAddress -notmatch "-") { 
            foreach ($VmIpv4Obj in $AllVmIpv4Obj) {
                foreach ($IPs in $VmIpv4Obj.Ipv4addresses) {
                    $test = Test-IPinIPRange -Address $IPs -Lower $IpSetObjIpAddress -Mask 32
                    if ($test) {$IpSetVmObj += $VmIpv4Obj}
                }
            }
        }
        #retrieve VM-objects for IP Subnet (based on CIDR)
        if ($IpSetObjIpAddress -match "/") { 
            foreach ($VmIpv4Obj in $AllVmIpv4Obj) {
                foreach ($IPs in $VmIpv4Obj.Ipv4addresses) {
                    $test = Test-IPinIPRange -Address $IPs -Lower $IpSetObjIpAddress.split("/")[0] -Mask $IpSetObjIpAddress.split("/")[0]
                    if ($test) {$IpSetVmObj += $VmIpv4Obj}
                }
            }
        }
        #retrieve VM-objects for IP Range
        if ($IpSetObjIpAddress -match "-") {
            $IpSetObjIpAddresslower = $IpSetObjIpAddress.split("-")[0]
            $IpSetObjIpAddressupper = $IpSetObjIpAddress.split("-")[1]
            $IpRange = Get-IPRange -lower $IpSetObjIpAddresslower -upper $IpSetObjIpAddressupper
            foreach ($IpRangeAddress in $IpRange) {
                foreach ($VmIpv4Obj in $AllVmIpv4Obj) {
                    foreach ($IPs in $VmIpv4Obj.Ipv4addresses) {
                            $test = Test-IPinIPRange -Address $IPs -Lower $IpRangeAddress.ToString() -Mask 32
                    }
                    if ($test) {$IpSetVmObj += $VmIpv4Obj}
                }
            }
        }
    }

    #remove duplicate Virtual Machine objects
    $IpSetVmObj = ($IpSetVmObj|Group-Object VmObj).foreach({$_.group[0]}) 

    #create new pscustomobject for IpSet and VM object information.
    $exportitem = [pscustomobject][ordered]@{
        IpSetobj = $IpSetObj.name 
        VMobj = $IpSetVmObj.VmObj.name -join ","
    }   
    $export += $exportitem
}
write-log -Message "Converting IpSet object to VM objects: completed" -Level Info
$export | Out-GridView
