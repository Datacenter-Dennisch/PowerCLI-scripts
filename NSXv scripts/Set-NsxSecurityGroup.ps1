function Set-NsxSecurityGroup {

    <#
    .SYNOPSIS
    Set NSX Security Group description

    .DESCRIPTION
    An NSX Security Group is a grouping construct that provides a powerful
    grouping function that can be used in DFW Firewall Rules and the NSX
    Service Composer.

    This cmdlet returns Security Group object.

    .EXAMPLE
    PS C:\> Set-NsxSecurityGroup TestSG

    #>

    [CmdLetBinding(DefaultParameterSetName = "Default")]

    param (

        [Parameter (Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        #SecurityGroup whose membership is to be modified.
        [ValidateNotNullOrEmpty()]
        [object]$SecurityGroup,
        [Parameter (Mandatory = $True)]
        #Set description
        [string]$Description,
        #PowerNSX Connection object
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Connection = $defaultNSXConnection

    )

    begin {
    }

    process {
        #Get our internal SG object and id.  The internal obejct is used to modify and put for bulk update.
        if ( $SecurityGroup -is [System.Xml.XmlElement] ) {
            $SecurityGroupId = $securityGroup.objectId
            $_SecurityGroup = $SecurityGroup.cloneNode($true)
        }
        elseif ( ($securityGroup -is [string]) -and ($SecurityGroup -match "securitygroup-\d+")) {
            $SecurityGroupId = $securityGroup
            $_SecurityGroup = Get-NsxSecurityGroup -objectId $SecurityGroupId -Connection $connection
        }
        else {
            throw "Invalid SecurityGroup specified.  Specify a PowerNSX SecurityGroup object or a valid securitygroup objectid."
        }

        
        if (!$_SecurityGroup.SelectSingleNode("./description")) {
            Add-XmlElement -xmlRoot $_SecurityGroup -xmlElementName "description" -xmlElementText $Description
        } else { 
             $_SecurityGroup.description = $Description
        }

        $URI = "/api/2.0/services/securitygroup/$($SecurityGroupId)"
        Write-Progress -Activity "Updating Security Group $SecurityGroupId"
        $null = Invoke-NsxWebRequest -method "put" -URI $URI -connection $connection -body $_SecurityGroup.OuterXml
        Write-Progress -Activity "Updating Security Group $SecurityGroupId" -Completed

        $returnObj = Get-NsxSecurityGroup -objectid $SecurityGroupId

        return $returnObj 
    }

    end {}
}
