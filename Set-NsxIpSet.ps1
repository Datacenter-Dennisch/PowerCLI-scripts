function Set-NsxIpSet {

    param (

        [Parameter (Mandatory=$true,ValueFromPipeline=$true,Position=1)]
            [ValidateNotNullOrEmpty()]
            [System.Xml.XmlElement]$IPSet,
        [Parameter (Mandatory=$false,Position=2)]
            [ValidateNotNullOrEmpty()]
            [String]$NewName,
        [Parameter (Mandatory=$false,Position=3)]
            [ValidateNotNullOrEmpty()]
            [String]$Description,
        [Parameter (Mandatory=$False)]
            #PowerNSX Connection object
            [ValidateNotNullOrEmpty()]
            [PSCustomObject]$Connection=$defaultNSXConnection
    )

    begin {}

    process {
        #$IPSet = $PhyServerIpSetObj[0]
        if ($Description) {$IPset.description = $Description}
        if ($NewName) {$IPset.name = $NewName}
        $body = $IPset.OuterXml

        $URI = "/api/2.0/services/ipset/$($IPset.objectId)"
        $response = invoke-nsxwebrequest -method "put" -uri $URI -body $body -connection $Connection
        try {
            [system.xml.xmldocument]$ipsetdoc = $response.content
            $ipsetdoc.ipset
        }
        catch {
            throw "Unable to interpret response content from NSX API as XML. Response: $response"
        }

    }

    end {}

}
