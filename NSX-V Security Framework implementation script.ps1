#define variables
$nssharedservicegroups = @{
"DNS Servers"="APP_DNS";
"DHCP servers"="APP_DHCP";
"Domain Controllers"=@("APP_LDAP","APP_KERBEROS","LDAP Global Catalog","Active Directory Server","Active Directory Server UDP");
"FTP servers"="APP_FTP";
"SNMP servers"="APP_SNMP";
"SMTP servers"="APP_SMTP";
}
$nsjumphostgroups = @("Jumphosts")
$nsisolationgroups = @("finance","HR","LoB","BCA","Drupal","Wordpress")
$nssegmentationgroups = @("Tier-0","Tier-1","Tier-2")
$nsfilteringgroup = @{
"Web service"=@("HTTP","HTTPS");
"MSSQL service"="MS-SQL-S";
"MySQL service"="MySQL";
"PostgreSQL service"="PostgreSQL"}
$DFWrule =@()
 
Function creatensobjects ($objects)
{
$NSXGroups = @()
foreach ($object in $objects){
    write-host "creating NSX Security Tag: $object"
    $NSXSecTag = New-NsxSecurityTag -Name $object
    write-host "creating NSX Security Group: $object"
    $NSXGroup = New-NsxSecurityGroup -Name $object -IncludeMember $NSXSecTag
    $NSXGroups += $NSXGroup
    }
return $NSXGroups
}
 
#create NS-objects
$nsxsharedservicegroups = @()
$nssharedservicegroups.keys | % {$nsxsharedservicegroups += creatensobjects $_ } 
$nsxjumphostgroups = creatensobjects $nsjumphostgroups
Add-NsxSecurityGroupMember -SecurityGroup $nsxjumphostgroups -Member (get-vm -name "jumphost")
$nsxisolationgroups = creatensobjects $nsisolationgroups
$nsxsegmentationgroups = creatensobjects $nssegmentationgroups
$nsxfilteringgroups = @()
$nsfilteringgroup.keys | % {$nsxfilteringgroups += creatensobjects $_ }
 
write-host "create NSX Security Framework"
#Creating Shared Service firewall rules
$dfwsection = New-NsxFirewallSection -Name "NSX DFW Firewall Rules - Shared Services"
foreach ($key in $nssharedservicegroups.keys) {
$NSXServices = @() ; $nssharedservicegroups[$key] | % {$NSXServices += Get-NsxService -Name $_ -LocalOnly} 
$DFWrule += New-NsxFirewallRule -Name $key -Section (Get-NsxFirewallSection -objectId $dfwsection.id) -Destination (Get-NsxSecurityGroup $key) -Service $NSXServices -Action allow -Position Bottom }
 
#Creating Jump Host firewall rules
$dfwsection = New-NsxFirewallSection -Name "NSX DFW Firewall Rules - Jump Hosts" -position after -anchorId $dfwsection.id
foreach ($nsxjumphostgroup in $nsxjumphostgroups) {
$DFWrule += New-NsxFirewallRule -Name $nsxjumphostgroup.name -Section (Get-NsxFirewallSection -objectId $dfwsection.id) -Destination $nsxjumphostgroup -Service ("APP_RDP" | % {Get-NsxService -name $_ -LocalOnly}) -Action allow -Position Bottom
$DFWrule += New-NsxFirewallRule -Name $nsxjumphostgroup.name -Section (Get-NsxFirewallSection -objectId $dfwsection.id) -Source $nsxjumphostgroup -Action allow -Position Bottom}
 
#Creating Isolation firewall rules
$dfwsection = New-NsxFirewallSection -Name "NSX DFW Firewall Rules - Isolation" -position after -anchorId $dfwsection.id
foreach ($nsxisolationgroup in $nsxisolationgroups) {$DFWrule += New-NsxFirewallRule -Name $nsxisolationgroup.name -Section (Get-NsxFirewallSection -objectId $dfwsection.id) -Source $nsxisolationgroup -Destination $nsxisolationgroup -NegateDestination -Action deny -Position Bottom}
 
#Creating Segmentation firewall rules
$dfwsection = New-NsxFirewallSection -Name "NSX DFW Firewall Rules - Segmentation " -position after -anchorId $dfwsection.id
$source = Get-NsxSecurityGroup -name "campus"
foreach ($nsxsegmentationgroup in $nsxsegmentationgroups) {
$DFWrule += New-NsxFirewallRule -Name $nsxsegmentationgroup.name -Section (Get-NsxFirewallSection -objectId $dfwsection.id) -Source $source -Destination $nsxsegmentationgroup -NegateDestination -Action deny -Position Bottom 
$source = $nsxsegmentationgroup}
 
#Creating Filtering firewall rules
$dfwsection = New-NsxFirewallSection -Name "NSX DFW Firewall Rules - Filtering " -position after -anchorId $dfwsection.id
foreach ($key in $nsfilteringgroup.keys) {
$NSXServices = @() ; $nsfilteringgroup[$key] | % {$NSXServices += Get-NsxService -Name $_ -LocalOnly} 
$DFWrule += New-NsxFirewallRule -Name $key -Section (Get-NsxFirewallSection -objectId $dfwsection.id) -Destination (Get-NsxSecurityGroup $key) -Service $NSXServices -Action allow -Position Bottom}
write-host "set zero trust policy"
get-nsxfirewallrule -RuleId 1001 | Set-NsxFirewallRule -action Deny