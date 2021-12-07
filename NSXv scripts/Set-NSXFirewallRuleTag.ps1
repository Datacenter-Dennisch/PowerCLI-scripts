$DFwsection = Get-NsxFirewallSection | Out-GridView -PassThru
$dfwrules = Get-NsxFirewallRule -Section $DFwsection
foreach ($DFWruleId in $dfwrules.id) {
    $DFWrule =  Get-NsxFirewallRule -RuleId $DFWruleId
    $tagname = "$($DFWrule.destinations.destination.name)_exception" 
    
    #$_DFWrule = $DFWrule.CloneNode($true)
    if (Invoke-XpathQuery -Node $DFWrule -query 'descendant::tag' -QueryMethod SelectSingleNode) {
        $DFWrule.tag = $tagname
    } else {
        Add-XmlElement -xmlRoot $DFWrule -xmlElementName tag -xmlElementText $tagname
    }
    
    $DFWrule | Set-NsxFirewallRule -logged:$true
}