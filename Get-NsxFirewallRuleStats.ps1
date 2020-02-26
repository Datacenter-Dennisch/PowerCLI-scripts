function Get-NsxFirewallRuleStats {

    <#
    .SYNOPSIS
    Retrieves the statistics for a specified NSX Distributed Firewall Rule.

    .DESCRIPTION
    An NSX Distributed Firewall Rule defines a typical 5 tuple rule and is
    enforced on each hypervisor at the point where the VMs NIC connects to the
    portgroup or logical switch.

    Additionally, the 'applied to' field allow additional flexibility about
    where (as in VMs, networks, hosts etc) the rule is actually applied.

    This cmdlet retrieves the specified NSX Distributed Firewall Rule.  It is
    also effective used in conjunction with an NSX firewall section as
    returned by Get-NsxFirewallSection being passed on the pipeline to retrieve
    all the rules defined within the given section.

    .EXAMPLE
    PS C:\> Get-NsxFirewallRule -name default | Get-NsxFirewallRuleStats

    #>

    param (

        [Parameter (Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
            [string]$Id,
        [Parameter (Mandatory=$False)]
            #PowerNSX Connection object
            [ValidateNotNullOrEmpty()]
            [PSCustomObject]$Connection=$defaultNSXConnection

    )


    process {
        $URI = "/api/4.0/firewall/stats/rules/$Id"
        $response = invoke-nsxrestmethod -method "get" -uri $URI -connection $connection
        if ( $response.ruleStats ){
                $response.ruleStats
        }
    }
}