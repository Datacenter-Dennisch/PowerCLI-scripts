$toremoveipset = Get-NsxIpSet

$allSg = Get-NsxSecurityGroup
$allSgmembers = $allSg.member.where({$_.objectTypeName -eq "IPSet"})
$allSgmembers.count
$allSgmembers = ($allSgmembers |Group-Object objectid).foreach({$_.group[0]})

$fwruleipset = @()
$fwruleipset += $allSgmembers.objectid


$allfwrules = Get-NsxFirewallRule
foreach ($allfwrule in $allfwrules){
    $allfwrulesources = $allfwrule.sources.source | where {$_.type -eq "IPSet"}
    $allfwruledest = $allfwrule.destinations.destination  | where {$_.type -eq "IPSet"}
    $fwruleipset += $allfwrulesources.value
    $fwruleipset += $allfwruledest.value
}

$fwruleipset = ($fwruleipset |Group-Object).foreach({$_.group[0]})


foreach ( $fwruleipsetobj in $fwruleipset) {
   $toremoveipset = $toremoveipset.where({$_.objectid -ne $fwruleipsetobj})
}

#$toremoveipset | Remove-NsxIpSet -Confirm:$false
