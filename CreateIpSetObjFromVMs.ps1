$VMs = Get-VM

$SpoofguardPolicy = Get-NsxSpoofguardPolicy
[PSCustomObject]$Connection=$defaultNSXConnection

$CreateIpSetObjList = @()
foreach ($VM in $VMs) {
    #check if VM is template
    if ($VM.ExtensionData.Config.Template -eq $false -and $VM.PowerState -eq "PoweredOn") {
        $IPSetObj = Get-NsxIpSet -Name "vm_$($VM.name)"
        if (!$IPSetObj) {
            write-host -ForegroundColor Yellow "No IP-Set object detected for $($VM.name)"
            $VMIpAddresses =  $VM.ExtensionData.Guest.IpAddress
            if (!$VMIpAddresses) {
                write-host -ForegroundColor Yellow "No IpAdress detected throught VM tools for $($VM.name)"
                $VMArpIpAddresses = (Get-NsxSpoofguardNic -SpoofguardPolicy $SpoofguardPolicy -VirtualMachine $VM | select detectedIpAddress).detectedIpAddress.ipAddress
                if ($VMArpIpAddresses) {
                    write-host "$($VM.name) detected the following IpAddresses through ARP: $VMArpIpAddresses"
                    $VMIpAddresses = $VMArpIpAddresses
                } else {
                    write-host -ForegroundColor Red "No IpAdress detected throught ARP and VMTools for $($VM.name)"
                }

            } else {
                write-host "$($VM.name) detected the following IpAddresses through VM tools: $VMIpAddresses"
            }
        } else {
            write-host -ForegroundColor Yellow "$($IPSetObj.name) already exists."
        }
    } else {
        write-host "$($VM.name) is a VM-Template, skipping"
    }
    if ($VMIpAddresses) {
        $CreateIpSetObj = [PSCustomobject]@{
            IpSetObjName = "vm_$($VM.name)"
            IPSetObjValue = $VMIpAddresses
            IPSetObjDescr = "Automatically created through PowerNSX scripting"
        }
        $CreateIpSetObjlist  += $CreateIpSetObj 
    }
}

$NewIpSetObj = $CreateIpSetObjList | Out-GridView -PassThru -Title "select IpSet objects to create" | % {New-NsxIpSet -Name $_.IpSetObjName -Description $_.IPSetObjDescr -IPAddress $_.IPSetObjValue}


