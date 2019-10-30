## vCloudDirectorNSX.psm1

This PowerShell module can be used for configuring VMware NSX for vSphere with vCloud Director from a tenant user perspective.
# Requirements:
- access: Organization Administrator role assigned
- Software: PowerShell (core) 6 version (or higher) installed.

# compatibility:
- tested with : 
  - vCD version 9.5, 9.7 and 10
  - NSX version 6.x
  
## Installation

Download the ***vCloudDirectorNSX.psm1*** file to your computer.
run the following Powershell command:

**import-module vCloudDirectorNSX.psm1**
  
## Usage

use the following command to retrieve a list of available cmdlets:

**Get-Command -Module vCloudDirectorNSX**

# Connectivity

You need to have a connection to the vCloud Director server.

Use the following command:

**Connect-vCDNSXAPI** [-Server] <string> [[-Port] <int>] [[-Protocol] <string>] [-cred] <pscredential> [-TenantID] <string>

***You need to provide a -tenantID to log in correctly!***

.example
> Connect-vCDNSXAPI -Server vcd01.dennisch.eu -cred (get-credential) -TenantID SchLab

You can disconnect by using the following command:

**Disconnect-vCDNSXAPI**

This command asks you for a verification of the disconnect, to overcome unwanted disconnects

# GET- PS-cmdlets

There are multiple GET- cmdlets available:

**Get-vCDNSXOrg**

Retrieves all Organization details.

**Get-vCDNSXOrgVDC [-OrgGuid] <string>**

Retrieves all Organization Virtual Datacenter details.

.example
> Get-vCDNSXOrg | Get-vCDNSXOrgVDC

Retrieves all available OrgVDCs.

**Get-vCDNSXOrgVDCvApp [[-OrgVdcGuid] <string>] [[-vAppName] <string>]**

Retrieves all OrgVDC vApps objects, or only a specific one when the -vAppName parameter is used.

**Get-vCDNSXOrgVDCVM [[-OrgVdcGuid] <string>] [[-VMName] <string>]**

Retrieves all OrgVDC VMs objects, or only a specific one when the -VMName parameter is used.

**Get-vCDNSXIpset [[-OrgVdcGuid] <string>] [[-IpSetName] <string>]**

Retrieves all OrgVDC IpSet objects, or only a specific one when the -IpSetName parameter is used.

**Get-vCDNSXMacset [[-OrgVdcGuid] <string>] [[-MacSetName] <string>]**

Retrieves all OrgVDC MacSet objects, or only a specific one when the -MacSetName parameter is used.

**Get-vCDNSXService [[-OrgVdcGuid] <string>] [[-ServiceName] <string>]**

Retrieves all Service objects, or only a specific one when the -ServiceGroupName parameter is used.

**Get-vCDNSXServiceGroup [[-OrgVdcGuid] <string>] [[-ServiceGroupName] <string>]**

Retrieves all ServiceGroup objects, or only a specific one when the -ServiceGroupName parameter is used. 

**Get-vCDNSXSecurityGroup [[-OrgVdcGuid] <string>] [[-SecurityGroupName] <string>]**

Retrieves all OrgVDC SecurityGroup objects (including member details), or only a specific one when the -SecurityGroupName parameter is used.

**Get-vCDNSXSecurityTag [[-OrgVdcGuid] <string>] [[-SecuritytagName] <string>]**

Retrieves all OrgVDC Security Tags, or only a specific one when the -SecuritytagName parameter is used.

**Get-vCDNSXSecurityTagVMs [[-SecuritytagGuid] <string>]**

Retrieves VMs assigned to a specific SecurityTag.

.example
> Get-vCDNSXSecurityTag -SecuritytagName test | Get-vCDNSXSecurityTagVMs

This will show all tagged VMs for NSX Security Tag named "test"

**Get-vCDNSXDistributedFirewallRule [[-DFWruleName] <string>] [[-DFWruleId] <string>]**

Retrieves all OrgVDC firewall rules, or only a specific one when the -DFWruleId or -DFWruleName parameter is used.

***PS the -DFWruleId parameter overrides the -DFWruleName parameter**

# NEW- PS-cmdlets

New-vCDNSXIpset [-IpSetName] <Object> [[-IpSetValue] <string>] [[-Description] <string>] [[-OrgVdcGuid] <string>]

Creates a new IpSet object within the OrgVDC.

**New-vCDNSXMacSet [-MacSetName] <string> [[-MacSetValue] <string>] [[-Description] <string>] [[-OrgVdcGuid] <string>]**

Creates a new MacSet object within the OrgVDC.

**New-vCDNSXSecurityGroup [-SecurityGroupName] <string> [[-Description] <string>] [[-OrgVdcGuid] <string>]**

Creates a new SecurityGroup object within the OrgVDC.

**New-vCDNSXSecurityTag [-SecurityTagName] <string> [[-Description] <string>] [[-OrgVdcGuid] <string>]**


Creates a new SecurityTag object within the OrgVDC.

# ADD- PS-cmdlets

**Add-vCDNSXSecurityGroupMember -SecurityGroupGuid <string> [-VmName <string>]**

Adds (one or multiple) VMs to a specific NSX Security Group

.example
>Get-vCDNSXSecurityGroup -SecurityGroupName "test-SG" | Add-vCDNSXSecurityGroupMember -VmName "test-vm"

This example will add VM with name "test-vm" to the NSX Security Group "test-SG".

The ***Add-vCDNSXSecurityGroupMember*** cmdlet is still being developed: assigning other objects to a NSX Security Group is not yet available.

**Add-vCDNSXDistributedFirewallRule [-DFWruleName] <string> [-DFWruleAction] {allow | deny} [[-DFWAppliedToObject] <string>] [[-SourceVMobject] <array>] [[-SourceIpSetobject] <array>] [[-SourceSecurityGroupobject] <array>] [[-SourceNegate] {true | false}] [[-DestinationVMobject] <array>] [[-DestinationIpSetobject] <array>] [[-DestinationSecurityGroupobject] <array>] [[-DestinationNegate] {true | false}] [[-ServiceObject] <array>] [[-DFWrulelogging] {true | false}] [[-DFWruleDisabled] {true | false}]**

Adds a firewall rule to the NSX DFW.
You can define multiple source- and destination objects in one command.

-Source, -Destination and -ServiceObject parameters are optional, when not defined "ANY" is being used.


.example
>Add-vCDNSXDistributedFirewallRule -DFWruleName "test-fwrule1" -DFWruleAction allow -SourceVMobject (Get-vCDNSXOrgVDCVM -VMName test-vm)

This example will create a new allow firewall rule, with the name "test-fwrule1" and with the "test-vm" Virtual Machine as a source.

