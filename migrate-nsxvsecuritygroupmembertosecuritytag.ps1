$AllNSXSecurityGroups = Get-NsxSecurityGroup 
$AllNSXSecurityTags = Get-NsxSecurityTag
$AllVMs = get-vm


$SecGroups = $AllNSXSecurityGroups | Out-GridView -OutputMode Multiple
$dryrun = $false

foreach ($secgroup in $SecGroups) {
    $secgroup = get-nsxsecuritygroup -objectId $secgroup.objectId
    #validate existence of corresponding NSX Security Tag
    $SecgroupST = $AllNSXSecurityTags.where({$_.name -eq $secgroup.name})
    if (!$SecgroupST) {
        if (!$dryrun) {
            $SecgroupST = New-NsxSecurityTag -Name $secgroup.name
            Add-NsxSecurityGroupMember $secgroup -Member $SecgroupST
            $secgroup = get-nsxsecuritygroup -objectId $secgroup.objectId
            write-log -Message "Creating NSX Security tag $($SecgroupST.name)"
            write-log -Message "Adding NSX Security tag $($SecgroupST.name) to security group  $($SecgroupST.name)"
        } else {
            write-log -Message "Creating NSX Security tag $($SecgroupST.name) -- ## DRYRun ##"
            write-log -Message "Adding NSX Security tag $($SecgroupST.name) to security group  $($SecgroupST.name) -- ## DRYRun ##"
        }
        $AllNSXSecurityTags = Get-NsxSecurityTag
    } else {
        write-host "$($secgroup.name) - st: $($SecgroupST.name)"
    }

    foreach ($secgroupmember in $secgroup.member) {
        
        #check if ipset is VM ..add to st when available
        if ($secgroupmember.type.typename -eq "IPSet") {
            write-host "$($secgroup.name) - IPSet: $($secgroupmember.name)"
            $SourceIps =  (Get-NsxIpSet -objectId $secgroupmember.objectId).value
            foreach ($SourceIp in $SourceIps) {
                $VMObj = $AllVMs.where({$_.ExtensionData.Guest.Net.IpAddress -eq $SourceIp})
                if ($VMObj) {
                    write-host "$($secgroup.name) - found VM based on IP : $($VMObj.name)"
                } else { 
                    $VMObj = $AllVMs.where({$_.name -eq $secgroupmember.name.split("_")[1]})
                    if ($VMObj) {
                        write-host "$($secgroup.name) - found VM based on name : $($VMObj.name)"
                    }
                }

                if ($VMObj) {
                    $Tagassignment = $SecgroupST | Get-NsxSecurityTagAssignment
                    if ($Tagassignment.VirtualMachine.Id -notcontains $VMobj.id) {
                        if (!$dryrun) {
                            $Tagassignment = New-NsxSecurityTagAssignment -ApplyToVm -VirtualMachine $VMobj -SecurityTag $SecgroupST 
                            write-log -Message "assigning NSX Security tag $($SecgroupST.name) to VM $($VMobj.name)"
                            $Tagassignment = $SecgroupST | Get-NsxSecurityTagAssignment
                        } else {
                            write-log -Message "assigning NSX Security tag $($SecgroupST.name) to VM $($VMobj.name) -- ## DRYRun ##"
                        }
                    }
                    if ($Tagassignment.VirtualMachine.Id -contains $VMobj.id) {
                        if (!$dryrun) {
                            Remove-NsxSecurityGroupMember -SecurityGroup $secgroup -Member $secgroupmember
                            write-host -ForegroundColor Yellow "removed $($secgroupmember.name) from security group $($secgroup.name)"
                        } else {
                            write-host -ForegroundColor Yellow "removed $($secgroupmember.name) from security group $($secgroup.name) -- ## DRYRUN ##"
                        }
                    } else {
                        write-host -ForegroundColor red "$($secgroup.name) - VM $($VMobj.name) not attached to security tag $($SecgroupST.name)"
                    }
                    $secgroup = get-nsxsecuritygroup -objectId $secgroup.objectId
                } else {
                    write-host -ForegroundColor red "$($secgroup.name) - IPSet $($secgroupmember.name) value $($SourceIp) is not a related to a VM"
                }
            }
        } 
        if ($secgroupmember.type.typename -eq "VirtualMachine") {
            write-host "$($secgroup.name) - VM object member: $($secgroupmember.name)"
            $VMObj = $AllVMs.where({$_.id -eq "VirtualMachine-$($secgroupmember.objectid)"})
            $Tagassignment = $SecgroupST | Get-NsxSecurityTagAssignment
            if ($Tagassignment.VirtualMachine.Id -notcontains $VMobj.id) {
                if (!$dryrun) {
                    $Tagassignment =  New-NsxSecurityTagAssignment -ApplyToVm -VirtualMachine $VMobj -SecurityTag $SecgroupST 
                    write-log -Message "assigning NSX Security tag $($SecgroupST.name) to VM $($VMobj.name)"
                    $Tagassignment = $SecgroupST | Get-NsxSecurityTagAssignment
                } else {
                    write-log -Message "assigning NSX Security tag $($SecgroupST.name) to VM $($VMobj.name) -- ## DRYRun ##"
                }
            }
            $Tagassignment = $SecgroupST | Get-NsxSecurityTagAssignment
            if ($Tagassignment.VirtualMachine.Id -contains $VMobj.id) {
                if (!$dryrun) {
                    Remove-NsxSecurityGroupMember -SecurityGroup $secgroup -Member $secgroupmember
                    write-host -ForegroundColor Yellow "removed $($secgroupmember.name) from security group $($secgroup.name)"
                } else {
                    write-host -ForegroundColor Yellow "removed $($secgroupmember.name) from security group $($secgroup.name) -- ## DRYRUN ##"
                }
            }
            $secgroup = get-nsxsecuritygroup -objectId $secgroup.objectId
        }
    }
}