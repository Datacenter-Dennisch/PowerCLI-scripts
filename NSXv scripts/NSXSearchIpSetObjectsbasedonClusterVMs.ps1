 $VMs = get-cluster | Out-GridView -PassThru -Title "select cluster" | get-vm
 $allIpSetObjects = Get-NsxIpSet
 
 $IPSetObjs = @()
 foreach ( $VM in $VMs) {
    $IpSetObjName = "vm_$($VM)"
    $IpSetObj =  $allIpSetObjects | ? {$_.name -eq "vm_$($VM.Name)"}
    If ($IpSetObj) {
        $IPSetObjs += $IPSetObj
    } else {
        write-host -foregroundcolor yellow "No IPset Obj for $($VM.name)"
    }
}

$SecGroup = Get-NsxSecurityGroup | Out-GridView -PassThru -Title "Select Security Group to add IPset Objects to"
Add-NsxSecurityGroupMember -SecurityGroup $SecGroup -Member  $IPSetObjs
