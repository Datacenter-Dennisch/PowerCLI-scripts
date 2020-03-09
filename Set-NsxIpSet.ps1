function Set-NsxIpSet {

    param (

        [Parameter (Mandatory=$true,ValueFromPipeline=$true,Position=1)]
            [ValidateNotNullOrEmpty()]
            [System.Xml.XmlElement]$IPSet,
        [Parameter (Mandatory=$true,Position=2)]
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
        $IPset.description = $Description
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
