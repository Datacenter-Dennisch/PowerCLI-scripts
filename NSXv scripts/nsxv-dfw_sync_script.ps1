# This script can be used to sync a DFW section between NSXv instances.

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
        [string]$Path="$($env:TEMP)\logs\PSScriptDebug.log",
        
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

function Clone-NsxSecurityGroup {

    [CmdletBinding()]
    param (

        [Parameter (Mandatory = $true, ValueFromPipeline = $true)]
        #Source Security Group
        [ValidateNotNullOrEmpty()]
        $orgSecurityGroup,
        [Parameter (Mandatory = $false)]
        #Scope of object.  For universal object creation, use the -Universal switch.
        [ValidateScript( {
                if ($_ -match "^globalroot-0$|universalroot-0$|^edge-\d+$") {
                    $True
                }
                else {
                    Throw "$_ is not a valid scope. Valid options are: globalroot-0 | universalroot-0 | edge-id"
                }
            })]
        [string]$scopeId = "globalroot-0",
        
        [Parameter (Mandatory = $false)]
        #Return only an object ID, not the full object.
        [switch]$ReturnObjectIdOnly = $false,
        [Parameter (Mandatory = $False)]
        #PowerNSX Connection object
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Connection = $defaultNSXConnection
    )

    begin {
        if ( (-not $Universal) -and ( $ActiveStandbyDeployment) ) {
            throw "SecurityGroup must be of universal scope for Active Standby flag to be specified."
        }
    }
    process {
        #Create the XMLRoot
        [System.XML.XMLDocument]$xmlDoc = New-Object System.XML.XMLDocument
        [System.XML.XMLElement]$xmlRoot = $XMLDoc.CreateElement("securitygroup")
        $xmlDoc.appendChild($xmlRoot) | Out-Null

        Add-XmlElement -xmlRoot $xmlRoot -xmlElementName "name" -xmlElementText $orgSecurityGroup.name
        if ($orgSecurityGroup.description) {Add-XmlElement -xmlRoot $xmlRoot -xmlElementName "description" -xmlElementText $orgSecurityGroup.description}
        
        if ( $orgSecurityGroup.member ) {

            foreach ( $Member in $orgSecurityGroup.member) {
                            
                
                switch ($Member.objectTypeName) 
                {
                    "IPSet" {
                        $OrgNSXIPSetObj = $AllDestinationNSXIPSetObjects.where({$_.name -eq $Member.name})
                        if ( $OrgNSXIPSetObj ) {
                            write-log -Message "$($OrgNSXIPSetObj.name) - $($OrgNSXIPSetObj.objectid) - existing NSX IPSet object found." -Level info
                            Add-XmlElement -xmlRoot $xmlMember -xmlElementName "objectId" -xmlElementText $OrgNSXIPSetObj.objectId
                        } else {
                            write-log -Message "$($Member.name) - Cloning NSX IPset object" -Level Info
                            $RefNSXIPSetObj = $AllSourceNSXIPSetObjects.where({$_.objectId -eq $Member.objectId})
                            if ( $RefNSXIPSetObj ) {
                                $OrgNSXIPSetObj = Clone-NsxIpSet -OrgIpSet $RefNSXIPSetObj -ReturnObjectIdOnly
                                write-log -Message "$($RefNSXIPSetObj.name) with objectId $($OrgNSXIPSetObj) - NSX IPSet object created." -Level info
                                if ($OrgNSXIPSetObj) {
                                    $AllDestinationNSXIPSetObjects = Get-NsxIpSet -LocalOnly
                                    [System.XML.XMLElement]$xmlMember = $XMLDoc.CreateElement("member")
                                    $xmlroot.appendChild($xmlMember) | Out-Null
                                    Add-XmlElement -xmlRoot $xmlMember -xmlElementName "objectId" -xmlElementText $OrgNSXIPSetObj
                                }
                            } else {
                                write-log -message "$($Member.name) - no detail/data found on destination NSX Manager, cannot continue" -Level Error
                            }
                        }
                    }
                    "SecurityGroup" {
                        #checking if security group already exists on destination NSX Manager
                        $OrgNSXSecurityGroup = $AllDestinationNSXSecurityGroups.where({$_.name -eq $member.name})
                        if ( $OrgNSXSecurityGroup ) {
                            write-log -Message "$($OrgNSXSecurityGroup.name) - existing NSX Security Group found." -Level info
                            Add-XmlElement -xmlRoot $xmlMember -xmlElementName "objectId" -xmlElementText $OrgNSXSecurityGroup.objectId
                        } else {
                            write-log -Message "$($Member.name) - Cloning NSX IPset object" -Level Info
                            $RefNSXSecurityGroup = $AllSourceNSXSecurityGroups.where({$_.objectId -eq $Member.objectId})
                            if ( $RefNSXSecurityGroup ) {
                                $OrgNSXSecurityGroup = Clone-NsxSecurityGroup -orgSecurityGroup $RefNSXSecurityGroup -ReturnObjectIdOnly 
                                if ($OrgNSXSecurityGroup) {
                                    $AllDestinationNSXSecurityGroups = Get-NsxSecurityGroup -LocalOnly
                                    [System.XML.XMLElement]$xmlMember = $XMLDoc.CreateElement("member")
                                    $xmlroot.appendChild($xmlMember) | Out-Null
                                    Add-XmlElement -xmlRoot $xmlMember -xmlElementName "objectId" -xmlElementText $OrgNSXSecurityGroup
                                }
                                Add-XmlElement -xmlRoot $xmlMember -xmlElementName "objectId" -xmlElementText $OrgNSXSecurityGroup
                            } else {
                                write-log -message "$($Member.name) - no detail/data found on destination NSX Manager, cannot continue" -Level Error
                            }
                        }
                    }
                    default {
                        write-log -message "$($Member.name) - no detail/data found on destination NSX Manager, cannot continue" -Level Error
                    }   
                }
            }
        }

        #if ( $excludeMember ) {
        #    foreach ( $Member in $ExcludeMember) {
        #        [System.XML.XMLElement]$xmlMember = $XMLDoc.CreateElement("excludeMember")
        #        $xmlroot.appendChild($xmlMember) | Out-Null
        #
        #        #This is probably not safe - need to review all possible input types to confirm.
        #        if ($Member -is [System.Xml.XmlElement] ) {
        #            Add-XmlElement -xmlRoot $xmlMember -xmlElementName "objectId" -xmlElementText $member.objectId
        #        }
        #        else {
        #           Add-XmlElement -xmlRoot $xmlMember -xmlElementName "objectId" -xmlElementText $member.ExtensionData.MoRef.Value
        #        }
        #    }
        #}
        
        #Do the post
        $body = $xmlroot.OuterXml
        if ( $universal ) { $scopeId = "universalroot-0" }
        $URI = "/api/2.0/services/securitygroup/bulk/$($scopeId.ToLower())"
        $response = Invoke-NsxWebRequest -method "post" -URI $URI -body $body -connection $connection
        write-log -Message "$($orgSecurityGroup.name) - Created NSX Security Group Object with id $($response.content)" 

        if ( $ReturnObjectIdOnly) {
            $response.content
        }
        else {
            Get-NsxSecurityGroup -objectId $response.content -Connection $connection
        }
}
end {}
}

function Clone-NsxIpSet {
    

    [CmdletBinding()]
    param (

        [Parameter (Mandatory = $true)]
        #Name of the IpSet.
        [ValidateNotNullOrEmpty()]
        $OrgIpSet,
        [Parameter (Mandatory = $false)]
        #Scope of object.  For universal object creation, use the -Universal switch.
        [ValidateScript( {
                if ($_ -match "^globalroot-0$|universalroot-0$|^edge-\d+$") {
                    $True
                }
                else {
                    Throw "$_ is not a valid scope. Valid options are: globalroot-0 | universalroot-0 | edge-id"
                }
            })]
        [string]$scopeId = "globalroot-0",
        [Parameter (Mandatory = $false)]
        #Return the objectid as a string rather than the whole XML object.
        [switch]$ReturnObjectIdOnly = $false,
        [Parameter (Mandatory = $False)]
        #PowerNSX Connection object
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Connection = $defaultNSXConnection
    )

    begin {}
    process {

        #Create the XMLRoot
        [System.XML.XMLDocument]$xmlDoc = New-Object System.XML.XMLDocument
        [System.XML.XMLElement]$xmlRoot = $XMLDoc.CreateElement("ipset")
        $xmlDoc.appendChild($xmlRoot) | Out-Null
        #$OrgIpSet = Get-NsxIpSet -Name $OrgIpSet.name

        
        if ( $OrgIpSet ) {
            Add-XmlElement -xmlRoot $xmlRoot -xmlElementName "name" -xmlElementText $OrgIpSet.name
            Add-XmlElement -xmlRoot $xmlRoot -xmlElementName "description" -xmlElementText $OrgIpSet.description
            Add-XmlElement -xmlRoot $xmlRoot -xmlElementName "value" -xmlElementText $OrgIpSet.Value
        }
        
        if ( ( $OrgIpSet.inheritanceAllowed -eq "True" ) -and ( -not ( $universal ) ) ) {
            Add-XmlElement -xmlRoot $xmlRoot -xmlElementName "inheritanceAllowed" -xmlElementText "True"
        }

        #Do the post
        if ( $universal ) { $scopeId = "universalroot-0" }
        $body = $xmlroot.OuterXml
        $URI = "/api/2.0/services/ipset/$($scopeId.ToLower())"
        $response = Invoke-NsxWebRequest -method "post" -URI $URI -body $body -connection $connection
        write-log -Message "$($OrgIpSet.name) - Created NSX IPSet Object with id $($response.content)" 

        if ( $ReturnObjectIdOnly) {
            $response.content
        } else {
            Get-NsxIpSet -objectId $response.content -Connection $connection
        }
    }
    end {}
}

function Clone-NsxService {

   

    [CmdletBinding()]
    param (

        [Parameter (Mandatory = $true)]
        #Input of the NSX Service.
        [ValidateNotNullOrEmpty()]
        $OrgNSXService, 
        [Parameter (Mandatory = $false)]
        #Scope of object.  For universal object creation, use the -Universal switch.
        [ValidateScript( {
                if ($_ -match "^globalroot-0$|universalroot-0$|^edge-\d+$") {
                    $True
                }
                else {
                    Throw "$_ is not a valid scope. Valid options are: globalroot-0 | universalroot-0 | edge-id"
                }
            })]
        [string]$scopeId = "globalroot-0",
        [Parameter (Mandatory = $false)]
        #Create the Service as Universal object.
        [switch]$Universal = $false,
        [Parameter (Mandatory = $false)]
        [switch]$ReturnObjectIdOnly = $false,
        [Parameter (Mandatory = $False)]
        #PowerNSX Connection object
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Connection = $defaultNSXConnection
    )

    begin {

       
    }
    process {

        #Create the XMLRoot
        [System.XML.XMLDocument]$xmlDoc = New-Object System.XML.XMLDocument
        [System.XML.XMLElement]$xmlRoot = $XMLDoc.CreateElement("application")
        $xmlDoc.appendChild($xmlRoot) | Out-Null

        Add-XmlElement -xmlRoot $xmlRoot -xmlElementName "name" -xmlElementText $OrgNSXService.name
        if ( $OrgNSXService.description ) {Add-XmlElement -xmlRoot $xmlRoot -xmlElementName "description" -xmlElementText $OrgNSXService.description}

        #Create the 'element' element ??? :)
        [System.XML.XMLElement]$xmlElement = $XMLDoc.CreateElement("element")
        $xmlRoot.appendChild($xmlElement) | Out-Null

        Add-XmlElement -xmlRoot $xmlElement -xmlElementName "applicationProtocol" -xmlElementText $OrgNSXService.element.applicationProtocol
        if ( $OrgNSXService.element.value ) {
            Add-XmlElement -xmlRoot $xmlElement -xmlElementName "value" -xmlElementText $OrgNSXService.element.value
        }
        if ( $OrgNSXService.element.sourcePort ) {
            Add-XmlElement -xmlRoot $xmlElement -xmlElementName "sourcePort" -xmlElementText $OrgNSXService.element.sourcePort 
        }
        if ( ( $OrgNSXService.inheritanceAllowed  ) -and ( -not ( $universal ) ) ) {
            Add-XmlElement -xmlRoot $xmlRoot -xmlElementName "inheritanceAllowed" -xmlElementText "True"
        }

        #Do the post
        $body = $xmlroot.OuterXml
        if ( $universal ) { $scopeId = "universalroot-0" }
        $URI = "/api/2.0/services/application/$($scopeId.tolower())"
        $response = Invoke-NsxWebRequest -method "post" -URI $URI -body $body -connection $connection
        write-log -Message "$($OrgNSXService.name) - Created NSX Service  Object with id $($response.content)" 
        if ( $ReturnObjectIdOnly) {
            $response.content
        }
        else {
            Get-NsxService -objectId $response.content -Connection $connection
        }
    }
    end {}
}

function Clone-NsxServiceGroup {

    [CmdletBinding()]
    param (
        [Parameter (Mandatory = $true)]
        #Input of the NSX Service.
        [ValidateNotNullOrEmpty()]
        $OrgNSXServiceGroup, 
        [Parameter (Mandatory = $false)]
        #Scope of object.  For universal object creation, use the -Universal switch.
        [ValidateScript( {
                if ($_ -match "^globalroot-0$|universalroot-0$|^edge-\d+$") {
                    $True
                }
                else {
                    Throw "$_ is not a valid scope. Valid options are: globalroot-0 | universalroot-0 | edge-id"
                }
            })]
        [string]$scopeId = "globalroot-0",
        [Parameter (Mandatory = $false)]
        #Create the Service Group as Universal object.
        [switch]$Universal = $false,
        [Parameter (Mandatory = $false)]
        [switch]$ReturnObjectIdOnly = $false,
        [Parameter (Mandatory = $False)]
        #PowerNSX Connection object
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Connection = $defaultNSXConnection
    )

    begin {

    }

    process {

        #Create the XMLRoot
        [System.XML.XMLDocument]$xmlDoc = New-Object System.XML.XMLDocument
        [System.XML.XMLElement]$xmlRoot = $XMLDoc.CreateElement("applicationGroup")
        $xmlDoc.appendChild($xmlRoot) | Out-Null

        Add-XmlElement -xmlRoot $xmlRoot -xmlElementName "name" -xmlElementText $OrgNSXServiceGroup.name
        if ( $OrgNSXServiceGroup.description ) {Add-XmlElement -xmlRoot $xmlRoot -xmlElementName "description" -xmlElementText $OrgNSXServiceGroup.description}

        if ( ( $OrgNSXServiceGroup.inheritanceAllowed ) -and ( -not ( $universal ) ) ) {
            Add-XmlElement -xmlRoot $xmlRoot -xmlElementName "inheritanceAllowed" -xmlElementText "True"
        }

        if ( $universal ) { $scopeId = "universalroot-0" }

        $body = $xmlroot.OuterXml

        $uri = "/api/2.0/services/applicationgroup/$($scopeId.ToLower())"
        $response = Invoke-NsxWebRequest -URI $uri -method "post" -body $body -connection $connection
        write-log -Message "$($OrgNSXServiceGroup.name) - Created NSX Service Group Object with id $($response.content)" 

        if ( $OrgNSXServiceGroup.member ) {

            foreach ( $Member in $OrgNSXServiceGroup.member) {
              
                #checking if service object already exists on destination NSX Manager
                $MemberOrgNSXServiceObject = $AllDestinationNSXServiceObjects.where({$_.name -eq $member.name})
                if ( $MemberOrgNSXServiceObject ) {
                    write-log -Message "$($MemberOrgNSXServiceObject.name) - existing NSX service object found." -Level info
                    $URI = "/api/2.0/services/applicationgroup/$($response.content)/members/$($MemberOrgNSXServiceObject.objectId)"
                    $null = Invoke-NsxWebRequest -method "PUT" -URI $URI -connection $connection
                } else {
                    write-log -Message "$($Member.name) - Cloning NSX service object" -Level Info
                    $MemberReferenceNSXServiceObject = $AllSourceNSXServiceObjects.where({$_.Objectid -eq $Member.Objectid})
                    if ( $MemberReferenceNSXServiceObject ) {
                        $MemberOrgNSXServiceObject = Clone-NsxService -OrgNSXService $MemberReferenceNSXServiceObject -ReturnObjectIdOnly 
                        if ($MemberOrgNSXServiceObject) {
                            $AllDestinationNSXServiceObjects = Get-NsxService -LocalOnly
                            $URI = "/api/2.0/services/applicationgroup/$($response.content)/members/$($MemberOrgNSXServiceObject)"
                            #write-log -Message "Executing REST API call $URI method PUT" -Level Info
                            $null = Invoke-NsxWebRequest -method "PUT" -URI $URI -connection $connection 
                        }
                    } else {
                        write-log -message "$($Member.name) - no detail/data found on destination NSX Manager, cannot continue" -Level Error
                    }
                }
            }
        }

        if ( $ReturnObjectIdOnly) {
            $response.content
        }
        else {
            Get-NsxServiceGroup -objectId $response.content -Connection $connection
        }
    }

    end {}
}

Function ValidateIPRange {

    Param (
        [Parameter (Mandatory = $true)]
        [object]$argument
    )
    if ( ($argument -as [string]) -and ($argument -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") ) {
        $true
    }
}

Function ValidateIPPrefix {

    Param (
        [Parameter (Mandatory = $true)]
        [object]$argument
    )
    if ( ($argument -as [string]) -and ($argument -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/([0-9]|[1-2][0-9]|3[0-2])?$") ) {
        $true
    }
}


Function ValidateFirewallRuleSourceDest {

    Param (
        [Parameter (Mandatory = $true)]
        [object]$argument
    )

    #Same requirements for SG membership except for bare IPAddress.
    if ( $argument -as [ipaddress] ) {
        $true
    }
    elseif ( ValidateIPRange -argument $argument ) {
        $true
    }
    elseif ( ValidateIPPrefix -argument $argument ) {
        $true
    }
    else {
        ValidateSecurityGroupMember $argument
    }
}

Function ValidateFirewallRule {

    Param (
        [Parameter (Mandatory = $true)]
        [object]$argument
    )

    #Check if it looks like a DFW rule
    if ($argument -is [System.Xml.XmlElement] ) {

        if ( -not ( $argument | Get-Member -Name id -MemberType Properties )) {
            throw "Specified firewall rule XML element does not contain an id property."
        }

        if ( -not ( $argument | Get-Member -Name action -MemberType Properties)) {
            throw "Specified firewall rule XML element does not contain an action property."
        }
        if ( -not ( $argument | Get-Member -Name appliedToList -MemberType Properties)) {
            throw "Specified firewall rule XML element does not contain an appliedToList property."
        }

        #Validate that the rule has a parent node that we can use to update it if required.
        try {
            $ParentSection = Invoke-XpathQuery -query "parent::section" -QueryMethod SelectSingleNode -Node $argument
            $null = $Parentsection.HasAttribute("id") -as [int]
            $null = $argument.HasAttribute("id")
        }
        catch {
            Throw "Unable to retrieve rule and section details from the specified Firewall Rule.  Specify a valid rule and try again."
        }

        $true
    }
    else {
        throw "Argument must be a firewall rule XML element as returned by Get-NsxFirewallRule"
    }
}

Function ValidateFirewallRuleMember {
    #Distinct from ValidateFirewallRuleMemberObject in that it checks for an arg that is a valid firewallrule member object, OR a string to match against the value of one.

    Param (
        [Parameter (Mandatory = $true)]
        [object]$argument
    )

    #Same requirements for Firewall Rule SourceDest except for string match on name as well.
    If ( $argument -is [string] ) {
        $True
    }
    else {
        ValidateFirewallRuleSourceDest -argument $argument
    }
}

Function ValidateFirewallRuleMemberObject {

    #Distinct from ValidateFirewallRuleMember in that it checks for an arg that looks like the appropriate return object from get-nsxfirewallrulemember.

    Param (
        [Parameter (Mandatory = $true)]
        [object]$argument
    )

    #Same requirements for Firewall Rule SourceDest except for string match on name as well.
    If ( $argument -is [pscustomobject] ) {
        if ( -not ( $argument | Get-Member -Name RuleId -MemberType Properties)) {
            throw "Specified argument is not a valid FirewallRuleMember object."
        }
        if ( -not ( $argument | Get-Member -Name SectionId -MemberType Properties)) {
            throw "Specified argument is not a valid FirewallRuleMember object."
        }
        if ( -not ( $argument | Get-Member -Name MemberType -MemberType Properties)) {
            throw "Specified argument is not a valid FirewallRuleMember object."
        }
        if ( -not ( $argument | Get-Member -Name Name -MemberType Properties)) {
            throw "Specified argument is not a valid FirewallRuleMember object."
        }
        if ( -not ( $argument | Get-Member -Name Value -MemberType Properties)) {
            throw "Specified argument is not a valid FirewallRuleMember object."
        }
        if ( -not ( $argument | Get-Member -Name Type -MemberType Properties)) {
            throw "Specified argument is not a valid FirewallRuleMember object."
        }
        $true
    }
    else {
        throw "Specified argument is not a valid FirewallRuleMember object."
    }
}

function Add-NsxSourceDestNode {

    param (
        [system.xml.xmlelement]$Rule,
        [ValidateSet ("sources", "destinations", IgnoreCase = $false)]
        [string]$NodeType,
        [string]$negated
    )

    #Create the parent sources element
    $XmlDoc = $Rule.OwnerDocument
    [System.XML.XMLElement]$xmlNode = $XMLDoc.CreateElement($NodeType)
    $Rule.AppendChild($xmlNode) | Out-Null

    #The excluded attribute indicates negation
    $xmlNegated = $xmlDoc.createAttribute("excluded")
    $xmlNode.Attributes.Append($xmlNegated) | Out-Null
    $xmlNegated.value = $Negated
}

function Add-NsxSourceDestMember {

    #Internal function - Handles building the source/dest xml node for a given object.
    # Updates NB 05/17 -> Modified for Add-NSxFirewallRuleMember cmdlet use.
    #   - Accepts rule (rather than doc) object now
    #   - Returns modified rule, rather than just the source/dest node.
    #   - Renamed to reflect 'member' terminology
    #   - Removed negation logic (moved back to new-rule due to logic not being applicable to individual member instances, function to be duplicated in set-rule cmdlet to allow flipping of negation (and other functions))
    param (

        [Parameter (Mandatory = $true)]
        [ValidateSet ("source", "destination", IgnoreCase = $false)]
        [string]$membertype,
        [object[]]$memberlist,
        [System.Xml.XmlElement]$rule
    )

    # Get Doc object from passed rule
    $xmlDoc = $rule.OwnerDocument

    # Get SrcDestNode parent element.  Have to use xpath here as the elem may be empty and powershell unhelpfully turns that into a string for us :|
    if ( $membertype -eq "Source" ) {
        [System.Xml.XmlElement]$xmlSrcDestNode = Invoke-XpathQuery -query "child::sources" -QueryMethod SelectSingleNode -Node $rule
    }
    else {
        [System.Xml.XmlElement]$xmlSrcDestNode = Invoke-XpathQuery -query "child::destinations" -QueryMethod SelectSingleNode -Node $rule
    }

    #Loop the memberlist and create appropriate element in the srcdest node.
    foreach ($member in $memberlist) {
        if ( ( $member -as [ipaddress]) -or ( ValidateIPRange -argument $member ) -or ( ValidateIPPrefix -argument $member ) ) {
            Write-Debug "$($MyInvocation.MyCommand.Name) : Building source/dest node for $member"
        }
        else {
            Write-Debug "$($MyInvocation.MyCommand.Name) : Building source/dest node for $($member.name)"
        }
        #Build the return XML element and append to our srcdestnode
        [System.XML.XMLElement]$xmlMember = $XMLDoc.CreateElement($memberType)
        $xmlSrcDestNode.appendChild($xmlMember) | Out-Null

        if ( ( $member -as [ipaddress]) -or ( ValidateIPRange -argument $member ) -or ( ValidateIPPrefix -argument $member ) ) {
            #Item is v4 or 6 address
            Write-Debug "$($MyInvocation.MyCommand.Name) : Object $member is an ipaddress"
            Add-XmlElement -xmlRoot $xmlMember -xmlElementName "value" -xmlElementText $member
            Add-XmlElement -xmlRoot $xmlMember -xmlElementName "type" -xmlElementText "Ipv4Address"
        }
        elseif ( $member -is [system.xml.xmlelement] ) {

            Write-Debug "$($MyInvocation.MyCommand.Name) : Object $($member.name) is specified as xml element"
            #XML representation of NSX object passed - ipset, sec group or logical switch
            #get appropritate name, value.
            Add-XmlElement -xmlRoot $xmlMember -xmlElementName "value" -xmlElementText $member.objectId
            Add-XmlElement -xmlRoot $xmlMember -xmlElementName "name" -xmlElementText $member.name
            Add-XmlElement -xmlRoot $xmlMember -xmlElementName "type" -xmlElementText $member.objectTypeName

        }
        else {

            Write-Debug "$($MyInvocation.MyCommand.Name) : Object $($member.name) is specified as supported powercli object"
            #Proper PowerCLI Object passed
            #If passed object is a NIC, we have to do some more digging
            if (  $member -is [VMware.VimAutomation.ViCore.Interop.V1.VirtualDevice.NetworkAdapterInterop] ) {

                Write-Debug "$($MyInvocation.MyCommand.Name) : Object $($member.name) is vNic"
                #Naming based on DFW UI standard
                Add-XmlElement -xmlRoot $xmlMember -xmlElementName "name" -xmlElementText "$($member.parent.name) - $($member.name)"
                Add-XmlElement -xmlRoot $xmlMember -xmlElementName "type" -xmlElementText "Vnic"

                $vmUuid = ($member.parent | Get-View).config.instanceuuid
                $MemberMoref = "$vmUuid.$($member.id.substring($member.id.length-3))"
                Add-XmlElement -xmlRoot $xmlMember -xmlElementName "value" -xmlElementText $MemberMoref
            }
            else {
                #any other accepted PowerCLI object, we just need to grab details from the moref.
                Add-XmlElement -xmlRoot $xmlMember -xmlElementName "name" -xmlElementText $member.name
                Add-XmlElement -xmlRoot $xmlMember -xmlElementName "type" -xmlElementText $member.extensiondata.moref.type
                Add-XmlElement -xmlRoot $xmlMember -xmlElementName "value" -xmlElementText $member.extensiondata.moref.value
            }
        }
    }
}

function ConvertTo-NsxApiSectionType {
    switch ( $args[0] ) {
        "LAYER3" { "layer3sections" }
        "LAYER2" { "layer2sections" }
        "L3REDIRECT" { "layer3redirectsections" }
        default { $args[0] }
    }
}

function New-NsxServiceNode {

    #Internal function - Handles building the appliedto xml node for a given object.

    param (

        [object[]]$itemlist,
        [System.XML.XMLDocument]$xmlDoc

    )

    [System.XML.XMLElement]$xmlReturn = $XMLDoc.CreateElement("services")

    foreach ($item in $itemlist) {
        # Check to see if a protocol AND port are specified
        if ( ($item -is [string]) -and ($item -match "/") ) {
            $itemSplit = $item -split "/"
            [System.XML.XMLElement]$xmlItem = $XMLDoc.CreateElement("service")
            Add-XmlElement -xmlRoot $xmlItem -xmlElementName "protocolName" -xmlElementText $itemSplit[0].ToUpper()
            Add-XmlElement -xmlRoot $xmlItem -xmlElementName "destinationPort" -xmlElementText $itemSplit[1]
            Write-Debug "$($MyInvocation.MyCommand.Name) : Building service node for $($item)"
        }
        # Otherwise we assume its just a Protocol with no port specified
        elseif ($item -is [string]) {
            [System.XML.XMLElement]$xmlItem = $XMLDoc.CreateElement("service")
            Add-XmlElement -xmlRoot $xmlItem -xmlElementName "protocolName" -xmlElementText $item.ToUpper()
            Write-Debug "$($MyInvocation.MyCommand.Name) : Building service node for $($item)"
        }
        # or its either an XML object, or a collection of objects (already verified as XML objects through validation script)
        elseif ( ( $item -is [System.Xml.XmlElement] ) -or ( $item -is [System.Object] ) ) {
            foreach ( $serviceitem in $item ) {
                [System.XML.XMLElement]$xmlItem = $XMLDoc.CreateElement("service")
                Add-XmlElement -xmlRoot $xmlItem -xmlElementName "value" -xmlElementText $serviceItem.objectId
                $xmlReturn.appendChild($xmlItem) | Out-Null
                Write-Debug "$($MyInvocation.MyCommand.Name) : Building service node for $($item.name)"
            }
        }

        $xmlReturn.appendChild($xmlItem) | Out-Null
    }

    $xmlReturn
}

function New-NsxAppliedToListNode {

    #Internal function - Handles building the appliedto xml node for a given object.

    param (

        [object[]]$itemlist,
        [System.XML.XMLDocument]$xmlDoc,
        [switch]$ApplyToDFW,
        [switch]$ApplyToAllEdges

    )

    [System.XML.XMLElement]$xmlReturn = $XMLDoc.CreateElement("appliedToList")
    #Iterate the appliedTo passed and build appliedTo nodes.
    #$xmlRoot.appendChild($xmlReturn) | out-null

    foreach ($item in $itemlist) {
        Write-Debug "$($MyInvocation.MyCommand.Name) : Building appliedTo node for $($item.name)"
        #Build the return XML element
        [System.XML.XMLElement]$xmlItem = $XMLDoc.CreateElement("appliedTo")

        if ( $item -is [system.xml.xmlelement] ) {

            Write-Debug "$($MyInvocation.MyCommand.Name) : Object $($item.name) is specified as xml element"

            if ( (Invoke-XpathQuery -QueryMethod SelectSingleNode -Node $item -query 'descendant::edgeSummary')) {

                Write-Debug "$($MyInvocation.MyCommand.Name) : Object $($item.name) is an edge object"

                if ( $ApplyToAllEdges ) {
                    #Apply to all edges is default off, so this means the user asked for something stupid
                    throw "Cant specify Edge Object in applied to list and ApplyToAllEdges simultaneously."
                }

                #We have an edge, and edges have the details we need in their EdgeSummary element:
                Add-XmlElement -xmlRoot $xmlItem -xmlElementName "value" -xmlElementText $item.edgeSummary.objectId
                Add-XmlElement -xmlRoot $xmlItem -xmlElementName "name" -xmlElementText $item.edgeSummary.name
                Add-XmlElement -xmlRoot $xmlItem -xmlElementName "type" -xmlElementText $item.edgeSummary.objectTypeName

            }
            else {

                #Something specific passed in applied to list, turn off Apply to DFW.
                $ApplyToDFW = $false

                #XML representation of NSX object passed - ipset, sec group or logical switch
                #get appropritate name, value.
                Add-XmlElement -xmlRoot $xmlItem -xmlElementName "value" -xmlElementText $item.objectId
                Add-XmlElement -xmlRoot $xmlItem -xmlElementName "name" -xmlElementText $item.name
                Add-XmlElement -xmlRoot $xmlItem -xmlElementName "type" -xmlElementText $item.objectTypeName
            }
        }
        else {

            #Something specific passed in applied to list, turn off Apply to DFW.
            $ApplyToDFW = $false

            Write-Debug "$($MyInvocation.MyCommand.Name) : Object $($item.name) is specified as supported powercli object"
            #Proper PowerCLI Object passed
            #If passed object is a NIC, we have to do some more digging
            if (  $item -is [VMware.VimAutomation.ViCore.Interop.V1.VirtualDevice.NetworkAdapterInterop] ) {

                Write-Debug "$($MyInvocation.MyCommand.Name) : Object $($item.name) is vNic"
                #Naming based on DFW UI standard
                Add-XmlElement -xmlRoot $xmlItem -xmlElementName "name" -xmlElementText "$($item.parent.name) - $($item.name)"
                Add-XmlElement -xmlRoot $xmlItem -xmlElementName "type" -xmlElementText "Vnic"

                $vmUuid = ($item.parent | Get-View).config.instanceuuid
                $MemberMoref = "$vmUuid.$($item.id.substring($item.id.length-3))"
                Add-XmlElement -xmlRoot $xmlItem -xmlElementName "value" -xmlElementText $MemberMoref
            }
            else {
                #any other accepted PowerCLI object, we just need to grab details from the moref.
                Add-XmlElement -xmlRoot $xmlItem -xmlElementName "name" -xmlElementText $item.name
                Add-XmlElement -xmlRoot $xmlItem -xmlElementName "type" -xmlElementText $item.extensiondata.moref.type
                Add-XmlElement -xmlRoot $xmlItem -xmlElementName "value" -xmlElementText $item.extensiondata.moref.value
            }
        }

        $xmlReturn.appendChild($xmlItem) | Out-Null
    }

    if ( $ApplyToDFW ) {

        [System.XML.XMLElement]$xmlAppliedTo = $XMLDoc.CreateElement("appliedTo")
        $xmlReturn.appendChild($xmlAppliedTo) | Out-Null
        Add-XmlElement -xmlRoot $xmlAppliedTo -xmlElementName "name" -xmlElementText "DISTRIBUTED_FIREWALL"
        Add-XmlElement -xmlRoot $xmlAppliedTo -xmlElementName "type" -xmlElementText "DISTRIBUTED_FIREWALL"
        Add-XmlElement -xmlRoot $xmlAppliedTo -xmlElementName "value" -xmlElementText "DISTRIBUTED_FIREWALL"
    }

    if ( $ApplyToAllEdges ) {

        [System.XML.XMLElement]$xmlAppliedTo = $XMLDoc.CreateElement("appliedTo")
        $xmlReturn.appendChild($xmlAppliedTo) | Out-Null
        Add-XmlElement -xmlRoot $xmlAppliedTo -xmlElementName "name" -xmlElementText "ALL_EDGES"
        Add-XmlElement -xmlRoot $xmlAppliedTo -xmlElementName "type" -xmlElementText "ALL_EDGES"
        Add-XmlElement -xmlRoot $xmlAppliedTo -xmlElementName "value" -xmlElementText "ALL_EDGES"
    }

    $xmlReturn
}


#$AllDestinationNSXSecurityGroups = Get-NsxSecurityGroup -LocalOnly
#$AllDestinationNSXIPSetObjects = Get-NsxIpSet -LocalOnly
#$orgSecurityGroup = $SourceNSXSecurityGroup
#Clone-NsxSecurityGroup -orgSecurityGroup $SourceNSXSecurityGroup
#$DFWRuleServiceObjectReference = $AllSourceNSXServiceObjects.where({$_.objectid -eq $DFWRuleServiceGroupObjectReference.member.objectId}) 
#Clone-NsxService -OrgNSXService $DFWRuleServiceObjectReference -ReturnObjectIdOnly
#$OrgNSXServiceGroup = $DFWRuleServiceGroupObjectReference
#Clone-NsxServiceGroup -OrgNSXServiceGroup $DFWRuleServiceGroupObjectReference -ReturnObjectIdOnly



$nsxvmgrlist = @(
    [pscustomobject]@{fqdn="nsxmgr.vviking.local";env="test-environment"} 
)


#connecting to Source NSX Manager.

$NSXvMgrFQDN = ($nsxvmgrlist | Out-GridView -Title "Select Source NSX-V Manager" -PassThru).fqdn

#when connected to a rogue NSXv Manager then disconnect, to start fresh
if ($DefaultNSXConnection -and ($DefaultNSXConnection.server -ne $NSXvMgrFQDN)) {
    Write-Log -Message "$($DefaultNSXConnection.server) - Disconnecting PowerNSX"
    Disconnect-NsxServer
}

if ($DefaultNSXConnection.server -ne $NSXvMgrFQDN) {
    Write-log -message "$($NSXvMgrFQDN) - Connecting PowerNSX to NSX-v manager." -Level Info
    do {
        $NSXCredential = Get-Credential -Message "Enter NSX credentials"
        sleep 1

        try {        
            Connect-NsxServer -NsxServer $NSXvMgrFQDN -Credential $NSXCredential -DisableVIAutoConnect 
        } 
        catch {}
    } while (!$DefaultNSXConnection)
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" established" -Level Info
} else {
    Write-log -message "already connected to $($DefaultNSXConnection.Server)" -Level warn
}

#retrieve all NSX DFW related objected
write-log -Message "$($DefaultNSXConnection.Server) - retrieving firewall security objects " -Level Info
$AllSourceDFWSections = Get-NsxFirewallSection
$AllSourceNSXSecurityGroups = Get-NsxSecurityGroup -LocalOnly
$AllSourceNSXIPSetObjects = Get-NsxIpSet -LocalOnly
$AllSourceNSXServiceObjects = Get-NsxService -LocalOnly
$AllSourceNSXServiceGroups = Get-NsxServiceGroup -LocalOnly

#making a selection of DFW sections to replicate
$DFWSectionSourceSelection = $AllSourceDFWSections | Out-GridView -OutputMode Multiple

#disconnect NSXv Manager to be able to connect to the destination NSXv Manager
Disconnect-NsxServer

#connecting to Destination NSX Manager.
$NSXvMgrFQDN = ($nsxvmgrlist | Out-GridView -Title "Select Source NSX-V Manager" -PassThru).fqdn
if ($DefaultNSXConnection.server -ne $NSXvMgrFQDN) {
    Write-log -message "$($NSXvMgrFQDN) - Connecting PowerNSX to NSX-v manager." -Level Info
    do {
        $NSXCredential = Get-Credential -Message "Enter NSX credentials"
        sleep 1

        try {        
            Connect-NsxServer -NsxServer $NSXvMgrFQDN -Credential $NSXCredential -DisableVIAutoConnect 
        } 
        catch {}
    } while (!$DefaultNSXConnection)
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" established" -Level Info
} else {
    Write-log -message "already connected to $($DefaultNSXConnection.Server)" -Level warn
}



$AllDestinationNSXDFWSections = Get-NsxFirewallSection
$AllDestinationNSXSecurityGroups = Get-NsxSecurityGroup -LocalOnly
$AllDestinationNSXIPSetObjects = Get-NsxIpSet -LocalOnly
$AllDestinationNSXServiceObjects = Get-NsxService -LocalOnly
$AllDestinationNSXServiceGroups = Get-NsxServiceGroup -LocalOnly
$dryrun = $false

#replicating NSX DFW rules
foreach ($DFWSectionSourceSelectionItem in $DFWSectionSourceSelection) {
    $destinationDFWSection = $null
    #check if section exist, otherwise create on.
    if ($AllDestinationNSXDFWSections.SelectNodes("/firewallConfiguration").count -eq 1 ) {
        write-log -Message "NSX DFW only contains the default section, creating a new one" -Level Warn
        $destinationDFWSection = New-NsxFirewallSection -Name $DFWSectionSourceSelectionItem.name 
    } else {
        $destinationDFWSection = $AllDestinationNSXDFWSections.where({$_.name -eq $DFWSectionSourceSelectionItem.name})
        if (!$destinationDFWSection) {
            write-log -Message "No existing DFW section found, creating a new one." -Level Warn
            $destinationDFWSection = New-NsxFirewallSection -Name $DFWSectionSourceSelectionItem.name 
        }
    }

    write-log "DFW section $($DFWSectionSourceSelectionItem.name) with id $($DFWSectionSourceSelectionItem.id) - replicating" -Level Info
    foreach ($DFWSourceRule in $DFWSectionSourceSelectionItem.rule.where({$_.disabled -eq "false"})) {

        write-log "DFW Rule $($DFWSourceRule.name) id $($DFWSourceRule.id) - replicating" -Level Info
        
        #checking DFW rule source objects.
        $DFWRuleSourceMembers = $null
        if ($DFWSourceRule.sources.source) {
            $DFWRuleSourceMembers = $()
            write-log "DFW Rule id $($DFWSourceRule.id) - Source object(s) found"
            foreach ($DFWSourceRuleSourceObj in $DFWSourceRule.sources.source) {
                
                switch ($DFWSourceRuleSourceObj.type) { 
                    "IPSet" {
                        $DFWRuleSourceMember = $AllDestinationNSXIPSetObjects.where({$_.name -eq $DFWSourceRuleSourceObj.name})
                        if ($DFWRuleSourceMember) {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - existing NSX IPSet '$($DFWSourceRuleSourceObj.name)' found (as expected)" -Level info
                            $DFWRuleSourceMembers += $DFWRuleSourceMember
                        } else {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - IPset object '$($DFWSourceRuleSourceObj.name)' does not exist" -Level warn
                        }
                    }
                    "SecurityGroup" {
                        $DFWRuleSourceMember = $AllDestinationNSXSecurityGroups.where({$_.name -eq $DFWSourceRuleSourceObj.name})
                        if ($DFWRuleSourceMember ) {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - existing NSX Security Group $($DFWSourceRuleSourceObj.name)' found (as expected)" -Level info
                            $DFWRuleSourceMembers += $DFWRuleSourceMember
                        } else {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - NSX Security Group '$($DFWSourceRuleSourceObj.name)' does not exist" -Level warn
                        }
                    }
                    default {
                        write-log -Message "DFW Rule id $($DFWSourceRule.id) - $($DFWSourceRuleSourceObj.name) of $($DFWSourceRuleSourceObj.type) is not supported object, cannot continue" -Level Error
                    }
                }
            }
        }

        
        #checking DFW rule destination objects
        $DFWRuleDestinationMembers = $null
        if ($DFWSourceRule.destinations.destination) {
            $DFWRuleDestinationMembers = $()
            write-log "DFW Rule id $($DFWSourceRule.id) - Destination object(s) found"
            foreach ($DFWSourceRuleDestinationObj in $DFWSourceRule.destinations.destination) {
                switch ($DFWSourceRuleDestinationObj.type) { 
                    "IPSet" {
                        $DFWRuleDestinationMember = $AllDestinationNSXIPSetObjects.where({$_.name -eq $DFWSourceRuleDestinationObj.name})
                        if ($DFWRuleDestinationMember) {
                            write-log -Message "$DFW Rule id $($DFWSourceRule.id) - existing NSX IPSet '$($DFWRuleDestinationMember.name)' found (as expected)" -Level info
                            $DFWRuleDestinationMembers += $DFWRuleDestinationMember
                        } else {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - IPset object '$($DFWSourceRuleDestinationObj.name)' does not exist" -Level warn
                        }
                    }
                    "SecurityGroup" {
                        $DFWRuleDestinationMember = $AllDestinationNSXSecurityGroups.where({$_.name -eq $DFWSourceRuleDestinationObj.name})
                        if ($DFWRuleDestinationMember ) {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - existing NSX Security Group '$($DFWRuleDestinationMember.name)' found (as expected)" -Level info
                            $DFWRuleDestinationMembers += $DFWRuleDestinationMember
                        } else {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - NSX Security Group '$($DFWSourceRuleDestinationObj.name)' does not exist" -Level warn
                        }
                    }
                    default {
                        write-log -Message "DFW Rule id $($DFWSourceRule.id) - $($DFWSourceRuleDestinationObj.name) of $($DFWSourceRuleDestinationObj.type) is not supported object, cannot continue" -Level Error
                    }
                }
                
            }
        }

        #checking DFW rule Applied To objects, if they are not available replicate them (only IPset and NSX Security groups are supported).
        $DFWRuleAppliedToMembers = $null
        if ($DFWSourceRule.appliedToList.appliedTo) {
            $DFWRuleAppliedToMembers = $()
            write-log "DFW Rule id $($DFWSourceRule.id) - 'Applied To' object(s) found"
            foreach ($DFWSourceRuleAppliedToObj in $DFWSourceRule.appliedToList.appliedTo) {
                switch ($DFWSourceRuleAppliedToObj.type) { 
                    "DISTRIBUTED_FIREWALL" {}
                    "IPSet" {
                        $DFWRuleAppliedToMember = $AllDestinationNSXIPSetObjects.where({$_.name -eq $DFWSourceRuleAppliedToObj.name})
                        if ($DFWRuleAppliedToMember) {
                            write-log -Message "$DFW Rule id $($DFWSourceRule.id) - existing NSX IPSet '$($DFWRuleAppliedToMember.name)' found (as expected)" -Level info
                            $DFWRuleAppliedToMembers += $DFWRuleAppliedToMember
                        } else {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - IPset object '$($DFWSourceRuleAppliedToObj.name)' does not exist" -Level warn
                        }
                    }
                    "SecurityGroup" {
                        $DFWRuleAppliedToMember = $AllDestinationNSXSecurityGroups.where({$_.name -eq $DFWSourceRuleAppliedToObj.name})
                        if ($DFWRuleAppliedToMember ) {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - existing NSX Security Group '$($DFWRuleAppliedToMember.name)' found (as expected)" -Level info
                            $DFWRuleAppliedToMembers += $DFWRuleAppliedToMember
                        } else {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - NSX Security Group '$($DFWSourceRuleAppliedToObj.name)' does not exist" -Level warn
                        }
                    }
                    default {
                        write-log -Message "DFW Rule id $($DFWSourceRule.id) - $($DFWSourceRuleAppliedToObj.name) of $($DFWSourceRuleAppliedToObj.type) is not supported object, cannot continue" -Level Error
                    }
                }
                
            }
        }

        #checking DFW rule services object, if they are not available replicate them.
        $DFWRuleServiceObjects = $null
        if ($DFWSourceRule.services.service) {
            write-log "DFW Rule id $($DFWSourceRule.id) - NSX Service object(s) found"
            $DFWRuleServiceObjects = @()

            foreach ($DFWSourceRuleServiceObj in $DFWSourceRule.services.service) {
                switch ( $DFWSourceRuleServiceObj.type ) {
                    "ApplicationGroup" {
                        $DFWRuleServiceGroupObject = $AllDestinationNSXServiceGroups.where({$_.name -eq $DFWSourceRuleServiceObj.name})
                        if ($DFWRuleServiceGroupObject ) {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - existing NSX Service Group '$($DFWRuleServiceGroupObject.name)' found (as expected)" -Level info
                            $DFWRuleServiceObjects += $DFWRuleServiceGroupObject
                        } else {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - NSX Service Group '$($DFWRuleServiceGroupObject.name)' does not exist" -Level warn
                            
                        }
                    }
                    "Application" {
                        $DFWRuleServiceObject = $AllDestinationNSXServiceObjects.where({$_.name -eq $DFWSourceRuleServiceObj.name})
                        if ($DFWRuleServiceObject ) {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - existing NSX Service '$($DFWRuleServiceObject.name)' found (as expected)" -Level info
                            $DFWRuleServiceObjects += $DFWRuleServiceObject
                        } else {
                            write-log -Message "DFW Rule id $($DFWSourceRule.id) - NSX Service '$($DFWRuleServiceObject.name)' does not exist" -Level warn
                            
                        }
                    }
                }
            }
        }
        
        #building DFW rule XML with new informatio
        $generationNumber = $destinationDFWSection.generationNumber

        #Create the XMLRoot
        [System.XML.XMLDocument]$xmlDoc = New-Object System.XML.XMLDocument
        [System.XML.XMLElement]$xmlRule = $XMLDoc.CreateElement("rule")
        $xmlDoc.appendChild($xmlRule) | Out-Null

        Add-XmlElement -xmlRoot $xmlRule -xmlElementName "name" -xmlElementText $DFWSourceRule.name
        if ($DFWSourceRule.notes) {Add-XmlElement -xmlRoot $xmlRule -xmlElementName "notes" -xmlElementText $DFWSourceRule.notes}
        Add-XmlElement -xmlRoot $xmlRule -xmlElementName "action" -xmlElementText $DFWSourceRule.action
        Add-XmlElement -xmlRoot $xmlRule -xmlElementName "direction" -xmlElementText $DFWSourceRule.direction

        if ( $DFWSourceRule.logged ) {
            #Enable Logging attribute
            $xmlAttrLog = $xmlDoc.createAttribute("logged")
            $xmlAttrLog.value = $DFWSourceRule.logged
            $xmlRule.Attributes.Append($xmlAttrLog) | Out-Null
        }
        
        #Build Sources Node
        if ( $DFWRuleSourceMembers ) {

            Add-NsxSourceDestNode -Rule $xmlRule -Nodetype "sources" -negated:($DFWSourceRule.sources.excluded)

            #Add the source members
            Add-NsxSourceDestMember -membertype "source" -memberlist $DFWRuleSourceMembers -rule $xmlRule
        }

        #Destinations Node
        if ( $DFWRuleDestinationMembers ) {

            Add-NsxSourceDestNode -Rule $xmlRule -Nodetype "destinations" -negated:($DFWSourceRule.destinations.excluded)

            #Add the destination members
            Add-NsxSourceDestMember -membertype "destination" -memberlist $DFWRuleDestinationMembers -rule $xmlRule
        }

        #Services
        if ( $DFWRuleServiceObjects ) {
            $xmlservices = New-NsxServiceNode -itemType "service" -itemlist $DFWRuleServiceObjects -xmlDoc $xmlDoc
            $xmlRule.appendChild($xmlservices) | Out-Null
        }

        #Applied To
        if ( -not $DFWRuleAppliedToMembers) {
            $xmlAppliedToList = New-NsxAppliedToListNode -xmlDoc $xmlDoc -ApplyToDFW:$ApplyToDfw -ApplyToAllEdges:$ApplyToAllEdges
        }
        else {
            $xmlAppliedToList = New-NsxAppliedToListNode -itemlist $DFWRuleAppliedToMembers -xmlDoc $xmlDoc -ApplyToDFW:$ApplyToDfw -ApplyToAllEdges:$ApplyToAllEdges
        }
        $xmlRule.appendChild($xmlAppliedToList) | Out-Null

        #Tag
        if ( $DFWSourceRule.tag ) {
            Add-XmlElement -xmlRoot $xmlRule -xmlElementName "tag" -xmlElementText $DFWSourceRule.tag
        }

        #GetThe existing rule Ids and store them - we check for a rule that isnt contained here in the response so we can presnet back to user with rule id
        if ( (Invoke-XpathQuery -QueryMethod SelectSingleNode -Node $destinationDFWSection -query "child::rule") ) {
            $ExistingIds = @($destinationDFWSection.rule.id)
        }
        else {
            $ExistingIds = @()
        }

        #Append the new rule to the section
        $xmlrule = $destinationDFWSection.ownerDocument.ImportNode($xmlRule, $true)
        $destinationDFWSection.appendchild($xmlRule) | Out-Null 
                
    }
    #Do the post
    $body = $destinationDFWSection.OuterXml
    $URI = "/api/4.0/firewall/globalroot-0/config/$(ConvertTo-NsxApiSectionType $destinationDFWSection.type)/$($destinationDFWSection.Id)"


    #Need the IfMatch header to specify the current section generation id
    $IfMatchHeader = @{"If-Match" = $generationNumber }
    if (!$dryrun) {
        $response = Invoke-NsxWebRequest -method "put" -URI $URI -body $body -extraheader $IfMatchHeader -connection $connection

        try {
            [system.xml.xmldocument]$content = $response.content
        }
        catch {
            throw "API call to NSX was successful, but was unable to interpret NSX API response as xml."
        }
    }
}


