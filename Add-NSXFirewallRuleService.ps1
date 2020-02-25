function Add-NsxFirewallRuleService {

    <#
    .SYNOPSIS
    Add a service to a NSX Distributed Firewall Rule.

    .DESCRIPTION
    An NSX Distributed Firewall Rule defines a typical 5 tuple rule and is
    enforced on each hypervisor at the point where the VMs NIC connects to the
    portgroup or logical switch.

    This cmdlet adds one or more service objects to a firewall rule object returned from Get-NsxFirewallRule.

    .EXAMPLE
    $fwrule = Get-NsxFirewallRule -Ruleid 1007 
    $service = Get-NsxService -name "HTTP" -LocalOnly
    Add-NsxFirewallRuleService -FirewallRule $fwrule -Service $service

    Adds "HTTP" service to NSX Distributed Firewall rule id 1007

    #>

    param (

        [Parameter (Mandatory=$true,ValueFromPipeline=$true)]
            # DFW rule as returned by Get-NsxFirewallRule / New-NsxFirewallRule
            [ValidateScript({ ValidateFirewallRule $_ })]
            [System.Xml.XmlElement]$FirewallRule,
        [Parameter (Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [System.Xml.XmlElement]$Service,
        [Parameter (Mandatory=$false)]
            #PowerNSX Connection object.
            [ValidateNotNullOrEmpty()]
            [PSCustomObject]$Connection=$defaultNSXConnection
    )

    begin {}

    process {
        $sectionId = $xmlrule.ParentNode.Id
        $RuleId = $xmlrule.id
        $generationNumber = $xmlrule.ParentNode.generationnumber

        $xmldoc = [xml]$FirewallRule.outerxml
        $xmldocrule = $xmldoc.SelectNodes("rule")
        $xmldocruleservices = $xmldocrule.SelectNodes("services")
        foreach ($serviceitem in $serviceselection) {
            [system.xml.xmlelement]$xmlitem = $xmldoc.CreateElement("service")
            Add-XmlElement -xmlRoot $xmlitem -xmlElementName "value" -xmlElementText $serviceitem.objectId
            $xmldocruleservices.AppendChild($xmlitem)
        }
        
        $uri = "/api/4.0/firewall/globalroot-0/config/layer3sections/$sectionId/rules/$Ruleid"
        $IfMatchHeader = @{"If-Match"=$generationNumber}

        try {
            $response = Invoke-NsxWebRequest -method put -Uri $uri -body $xmldoc.ruleOuterXml -extraheader $IfMatchHeader -connection $connection
            [xml]$ruleElem = $response.Content
            Get-NsxFirewallRule -RuleId $ruleElem.rule.id
        }
        catch {
            throw "Failed to modify the specified rule.  $_"
        }
    }

    end {}
}