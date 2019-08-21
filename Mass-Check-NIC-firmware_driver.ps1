$vmhosts = get-cluster | Out-GridView -PassThru| Get-VMHost

$results = @()
foreach ($vmhost in $vmhosts) {
    $esxcli = $vmhost | Get-EsxCli -v2
    $vmnic0 = $esxcli.network.nic.get.invoke(@{nicname="vmnic0"})
    
    $nics = $esxcli.network.nic.list.Invoke()
    $nicresults = @()
    foreach ($nic in $nics) {
        $vmnic = $esxcli.network.nic.get.invoke(@{nicname=$nic.name})
        $resultpernic = New-Object PSobject -Property @{
            name = $vmnic.name
            firmwareversion = $vmnic.DriverInfo.FirmwareVersion
            driver = $vmnic.DriverInfo.Driver
            driverversion = $vmnic.DriverInfo.Version
        }
    $nicresults += $resultpernic
    }
    $resultperhost = New-Object PSobject -Property @{
        hostname = $vmhost.Name
        NICinfo = $nicresults
    }
    $results += $resultperhost
}

#$results.NICinfo.where({$_.name -eq "vmnic0"})
$results.NICinfo
