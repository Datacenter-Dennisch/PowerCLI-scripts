Function Retrieve-NSXOrgServiceEntries {

    param (
        $ServiceId
    )

    $ServiceEntryList = (Invoke-RestMethod -Method get -Uri "$($Global:defaultNsxConnections.ServerUri.AbsoluteUri)/infra/services/$($ServiceId)" -Headers $nsxheader).service_entries
    $returnObj = @()
    foreach ($ServiceEntryObj in $ServiceEntryList) {
        if ($ServiceEntryObj.resource_type -eq "NestedServiceServiceEntry") {
            
            #retrieve API path to referred service obj
            $ReferredServiceObj = (Invoke-RestMethod -Method get -Uri "$($Global:defaultNsxConnections.ServerUri.AbsoluteUri)$($ServiceEntryObj.Path)" -Headers $nsxheader)
            
            # Double check if this is the org service obj entry using this same function (inner-looping)
            $ServiceEntryObj = Retrieve-NSXOrgServiceEntries -ServiceId $ReferredServiceObj.nested_service_path.split("/")[3]
        }
        $returnObj += $ServiceEntryObj
    
    }
    return $returnObj 
}
