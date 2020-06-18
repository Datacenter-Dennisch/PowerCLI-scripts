function Remove-NsxSecurityTagAssignment {

    <#
    .SYNOPSIS
    This cmdlet is used to remove NSX Security Tags assigned to a virtual machine

    .DESCRIPTION
    A NSX Security Tag is a arbitrary string. It is used in other functions of
    NSX such as Security Groups match criteria. Security Tags are applied to a
    Virtual Machine.

    This cmdlet assigns is used to remove NSX Security Tags assigned to a virtual machine

    .EXAMPLE
    Get-NsxSecurityTag ST-WEB-DMZ | Get-NsxSecurityTagAssignment | Remove-NsxSecurityTagAssignment

    Gets all assignment of Security Tag ST-WEB-DMZ and removes its assignment from all VMs with confirmation.

    .EXAMPLE
    Get-VM Web01 | Get-NsxSecurityTagAssignment | Remove-NsxSecurityTagAssignment

    Removes all security tags assigned to Web01 virtual machine.

    #>

    [CmdLetBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidDefaultValueSwitchParameter","")] # Cant remove without breaking backward compatibility
    param (
        [Parameter (Mandatory=$true, ValueFromPipeline=$true)]
            #[ValidateScript ({ ValidateTagAssignment $_ })]
            [PSCustomObject]$TagAssignment,
        [Parameter (Mandatory=$False)]
            #Prompt for confirmation.  Specify as -confirm:$false to disable confirmation prompt
            [switch]$Confirm=$true,
        [Parameter (Mandatory=$False)]
            #PowerNSX Connection object
            [ValidateNotNullOrEmpty()]
            [PSCustomObject]$Connection=$defaultNSXConnection
    )

    begin {}

    process {

        if ( $confirm ) {
            $message  = "Removing Security Tag $($TagAssignment.SecurityTag.Name) from $($TagAssignment.VirtualMachine.name) may impact desired Security Posture and expose your infrastructure."
            $question = "Proceed with removal of Security Tag?"

            $choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
            $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
            $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

            $decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)

        }
        else { $decision = 0 }

        if ($decision -eq 0) {
            $vmMoid = $TagAssignment.VirtualMachine.ExtensionData.Config.InstanceUuid
            $body = "<securityTagAssignment><tagParameter><key>instance_uuid</key><value>$($vmMoid)</value></tagParameter></securityTagAssignment>"
            $URI = "/api/2.0/services/securitytags/tag/$($TagAssignment.SecurityTag.ObjectId)/vm?action=detach"
            Write-Progress -activity "Removing Security Tag $($TagAssignment.SecurityTag.ObjectId) to Virtual Machine $($TagAssignment.VirtualMachine.ExtensionData.Moref.Value)"
            $null = invoke-nsxwebrequest -method "post" -uri $URI -connection $connection -body $body
            Write-Progress -activity "Adding Security Tag $($TagAssignment.SecurityTag.ObjectId) to Virtual Machine $($TagAssignment.VirtualMachine.ExtensionData.Moref.Value)" -completed
        }
    }

    end{}
}