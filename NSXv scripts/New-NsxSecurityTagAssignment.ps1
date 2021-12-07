function New-NsxSecurityTagAssignment {

    <#
    .SYNOPSIS
    This cmdlet assigns is used to assign NSX Security Tags to a virtual machine.

    .DESCRIPTION
    A NSX Security Tag is an arbitrary string. It is used in other functions of
    NSX such as Security Groups match criteria. Security Tags are applied to a
    Virtual Machine.

    This cmdlet is used to assign NSX Security Tags to a virtual machine.

    .EXAMPLE
    Get-VM Web-01 | New-NsxSecurityTagAssignment -ApplyTag -SecurityTag (Get-NsxSecurityTag ST-Web-DMZ)

    Assign a single security tag to a virtual machine

    .EXAMPLE
    Get-NsxSecurityTag ST-Web-DMZ | New-NsxSecurityTagAssignment -ApplyToVm -VirtualMachine (Get-VM Web-01)

    Assign a single security tag to a virtual machine

    .EXAMPLE
    Get-VM Web-01 | New-NsxSecurityTagAssignment -ApplyTag -SecurityTag $( Get-NsxSecurityTag | where-object {$_.name -like "*prod*"} )

    Assign all security tags containing "prod" in the name to a virtual machine

    .EXAMPLE
    Get-NsxSecurityTag | where-object { $_.name -like "*dmz*" } | New-NsxSecurityTagAssignment -ApplyToVm -VirtualMachine (Get-VM web01,app01,db01)

    Assign all security tags containing "DMZ" in the name to multiple virtual machines

    #>
    [CmdLetBinding(DefaultParameterSetName="VirtualMachine")]

    param (
        [Parameter (Mandatory=$true, ValueFromPipeline=$true, ParameterSetName = "VirtualMachine")]
        [Parameter (Mandatory=$true, Position = 1, ParameterSetName = "SecurityTag")]
            [ValidateNotNullorEmpty()]
            [VMware.VimAutomation.ViCore.Interop.V1.Inventory.VirtualMachineInterop[]]$VirtualMachine,
        [Parameter (Mandatory=$true, Position = 1, ParameterSetName = "VirtualMachine")]
        [Parameter (Mandatory=$true, ValueFromPipeline=$true, ParameterSetName = "SecurityTag")]
           # [ValidateScript( { ValidateSecurityTag $_ })]
            [System.Xml.XmlElement[]]$SecurityTag,
        [Parameter (Mandatory=$true, ParameterSetName = "VirtualMachine")]
            [switch]$ApplyTag,
        [Parameter (Mandatory=$true, ParameterSetName = "SecurityTag")]
            [switch]$ApplyToVm,
        [Parameter (Mandatory=$False)]
            #PowerNSX Connection object
            [ValidateNotNullOrEmpty()]
            [PSCustomObject]$Connection=$defaultNSXConnection
    )

    begin {}

    process {

        foreach ( $tag in $SecurityTag) {

            $TagIdentifierString = $Tag.objectid

            foreach ( $vm in $VirtualMachine) {
                $vmMoid = $vm.ExtensionData.Config.InstanceUuid
                $body = "<securityTagAssignment><tagParameter><key>instance_uuid</key><value>$($vmMoid)</value></tagParameter></securityTagAssignment>"
                $URI = "/api/2.0/services/securitytags/tag/$($TagIdentifierString)/vm?action=attach"
                Write-Progress -activity "Adding Security Tag $($TagIdentifierString) to Virtual Machine $($vmMoid)"
                $null = invoke-nsxwebrequest -method "post" -uri $URI -connection $connection -body $body
                Write-Progress -activity "Adding Security Tag $TagIdentifierString to Virtual Machine $($vmMoid)" -completed
            }
        }
    }

    end{}
}