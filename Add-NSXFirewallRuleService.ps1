$xmlrule = Get-NsxFirewallRule | Out-GridView -PassThru
$serviceselection = Get-NsxService | Out-GridView -OutputMode Multiple
$xmlservice = @()


$xmldoc = [xml]$xmlrule.outerxml
#$xmldoc = $xmlrule.ParentNode.OuterXml
$xmldocrule = $xmldoc.SelectNodes("rule")
$xmldocruleservices = $xmldocrule.SelectNodes("services")
foreach ($service in $serviceselection) {
    $servicename = $service.name
    [system.xml.xmlelement]$xmlitem = $xmldoc.CreateElement("service")
    Add-XmlElement -xmlRoot $xmlitem -xmlElementName "value" -xmlElementText $service.objectId
    $xmldocruleservices.AppendChild($xmlitem)
}
[PSCustomObject]$Connection=$defaultNSXConnection
$sectionId = $xmlrule.ParentNode.Id
$RuleId = $xmlrule.id
$generationNumber = $xmlrule.ParentNode.generationnumber
$uri = "/api/4.0/firewall/globalroot-0/config/layer3sections/$sectionId/rules/$Ruleid"
$IfMatchHeader = @{"If-Match"=$generationNumber}

[system.xml.xmlelement] $rule = $xmldoc.rule

try {
    $response = Invoke-NsxWebRequest -method put -Uri $uri -body $rule.OuterXml -extraheader $IfMatchHeader -connection $connection
    [xml]$ruleElem = $response.Content
    Get-NsxFirewallRule -RuleId $ruleElem.rule.id
}
catch {
    throw "Failed to modify the specified rule.  $_"
}

