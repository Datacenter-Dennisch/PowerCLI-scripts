$daysofdata = 30 
$epochnow = (Get-Date -UFormat %s).Split(".")[0]
$epochdaysofdata = $epochnow - ($daysofdata * (3600 * 24))


add-type @"
 using System.Net;
 using System.Security.Cryptography.X509Certificates;
 public class TrustAllCertsPolicy : ICertificatePolicy {
 public bool CheckValidationResult(
 ServicePoint srvPoint, X509Certificate certificate,
 WebRequest request, int certificateProblem) {
 return true;
 }
 }
"@

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

$site = "https://vrni.domain.local"
if (!$apiKey) {
    do {
        $vrnicred = Get-Credential -Message "Enter admin credentials $site"
        $username = $vrnicred.UserName
        $password = $vrnicred.GetNetworkCredential().Password
        $domaintype = "LDAP"
        $domain = "domain.local"

        $jsonCredentials = @{username=$username;password=$password;domain=@{domain_type=$domaintype;value="$domain"}} | ConvertTo-Json

        $url = $site +"/api/ni/auth/token"
        $apiKey = Invoke-RestMethod $url -Method POST -Body $jsonCredentials -ContentType 'application/json'
    } until  ($apiKey)
}
$authVal = "NetworkInsight " + $apiKey.token

$VM = (get-vm | out-gridview -Title "Select VM to analyze" -PassThru).name

$jsonbody = @{entity_type="VirtualMachine";filter="name = '$VM'"} | ConvertTo-Json
$url = $site +"/api/ni/search"
$returnjson = Invoke-RestMethod $url -Method POST -ContentType 'application/json' -Headers @{"AUTHORIZATION"=$authVal} -Body $jsonbody
$entityid = $returnjson.results.entity_id

#get flows from source VM

$flowids = @()
$jsonbody = @{entity_type="flow";size="100"; filter="source_vm.entity_id = '$entityid'"} | ConvertTo-Json #;time_range= @{start_time=[int]$epochdaysofdata;end_time=[int]$epochnow}}
$url = $site +"/api/ni/search"
$returnjson = Invoke-RestMethod $url -Method POST -ContentType 'application/json' -Headers @{"AUTHORIZATION"=$authVal} -Body $jsonbody
$flowids += $returnjson.results.entity_id 

#get flows from destination VM
$jsonbody = @{entity_type="flow";size="100"; filter="destination_vm.entity_id = '$entityid'"} | ConvertTo-Json #;time_range= @{start_time=[int]$epochdaysofdata;end_time=[int]$epochnow}}
$url = $site +"/api/ni/search"
$returnjson = Invoke-RestMethod $url -Method POST -ContentType 'application/json' -Headers @{"AUTHORIZATION"=$authVal} -Body $jsonbody
$flowids += $returnjson.results.entity_id

$return = @()
foreach ($flowid in $flowids){
    $url = $site +"/api/ni/entities/flows/$flowid"
    $returnjson = Invoke-RestMethod $url -Method GET -ContentType 'application/json' -Headers @{"AUTHORIZATION"=$authVal}
    
    $url = $site +"/api/ni/entities/vms/$($returnjson.source_vm.entity_id)"
    $SourceVM = Invoke-RestMethod $url -Method GET -ContentType 'application/json' -Headers @{"AUTHORIZATION"=$authVal}
    
    $SGbody = $SourceVM.security_groups 
    if ($SGbody) {
        $jsonbody = @{entity_ids=$SGbody} | ConvertTo-Json
        $url = $site +"/api/ni/entities/fetch"
        $sourceSGName = (Invoke-RestMethod $url -Method post -ContentType 'application/json' -Headers @{"AUTHORIZATION"=$authVal} -Body $jsonbody).results.entity.name -join ","
    } else {$sourceSGName = ""}

    $url = $site +"/api/ni/entities/vms/$($returnjson.destination_vm.entity_id)"
    $DestinationVM = Invoke-RestMethod $url -Method GET -ContentType 'application/json' -Headers @{"AUTHORIZATION"=$authVal}
    
    $SGbody = $DestinationVM.security_groups 
    if ($SGbody) {
        $jsonbody = @{entity_ids=$SGbody} | ConvertTo-Json
        $url = $site +"/api/ni/entities/fetch"
        $DestinationSGName = (Invoke-RestMethod $url -Method post -ContentType 'application/json' -Headers @{"AUTHORIZATION"=$authVal} -Body $jsonbody).results.entity.name -join ","
    } else {$DestinationSGName = ""}
    $ReturnItem = [pscustomobject][ordered]@{        
        #ruleid = $PsEventItem.vmwnsxfirewallruleid
        vmwnsxfirewallsrc = $returnjson.source_ip.ip_address
        sourceVMname = $SourceVM.name 
        sourceSGname = $SourceSG.name
        vmwnsxfirewalldst = $returnjson.destination_ip.ip_address
        destinationVMname = $DestinationVM.name 
        destinationSGName = $DestinationSG.name 
        protocol = $returnjson.protocol
        port = $returnjson.port.display
        action = $returnjson.firewall_action
    }
    $return += $ReturnItem
}
$return | Out-GridView
