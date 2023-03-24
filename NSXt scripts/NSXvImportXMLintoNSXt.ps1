 Add-Type -AssemblyName System.Windows.Forms

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

function Get-FileName($InitialDirectory)
{
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.filter = "XML-Documents (*.xml) | *.xml"
    $OpenFileDialog.MultiSelect = $true 
    $OpenFileDialog.ShowDialog() | Out-Null
    return $OpenFileDialog.FileNames
}


$NSXfqdn = "NSXtMgr.vViking.local"

Disconnect-NsxServer * 
write-log "$($NSXfqdn): Logging into NSXt Manager"
if ($global:DefaultNsxtServers.name -eq $NSXfqdn) {
    write-log "$($NSXfqdn): Already Connected" 
} else {
    if (!$nsxcred) {$nsxcred = Get-Credential}
    Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false | Out-Null
    Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction:Ignore -Confirm:$false | Out-Null
    Connect-NsxServer -Server $NSXfqdn -Credential $nsxcred
    write-log "$($NSXfqdn): Connected" 
}

#xml file selection 
$importfilenames = Get-FileName $env:HOMEPATH

$overwrite = $false
$tag = Initialize-Tag -_Tag "nsxv-origin" 
$failedXML = @()
foreach ($importfilename in $importfilenames) {
    [xml]$XMLimport = get-content -Path $importfilename
    
    #retrieve all NSXt service objects
    $cursor = 0 
    $ExistingServices = @()
    do {
        if ($cursor -eq 0) {
            $listServiceReturn = Invoke-ListServicesForTenant
            [string]$cursor = $listServiceReturn.Cursor
        } else {
            $listServiceReturn = Invoke-ListServicesForTenant -Cursor $cursor
            [string]$cursor = $listServiceReturn.Cursor
        }
        $ExistingServices += $listServiceReturn.Results
    } until ($listServiceReturn.Cursor -eq $null)

    # bouwblokken
    if ($XMLimport.list) {
        $XMLimport.list.ChildNodes| foreach {
            $XML = $_
            switch ($XML.objectTypeName) {
                "securitygroup" {
                    $ExistingNsGroups = (Invoke-ListGroupForDomain -DomainId default).Results
                    if ($ExistingNsGroups.displayname -contains $XML.name -and $overwrite -eq $false) {
                        write-log "$($NSXfqdn): NsGroup $($XML.name) already exists"
                    } else {
                        Write-Log "$($NSXfqdn): Importing NsGroup $($XML.name)"
                        $GroupPathExpressionPaths = @()
                        $GroupCondition = @()
                        if ($XML.member) {
                            $XML.member | foreach {
                                $XMLmember = $_
                                switch ($XMLmember.objectTypeName) {
                                    "SecurityTag" {
                                        $GroupCondition += Initialize-Condition -ResourceType Condition -Id $XMLmember.name -MemberType VirtualMachine -Key Tag -Operator EQUALS -Value $XMLmember.name
                                    }
                                    "IPSet"{
                                        $GroupPathExpressionPaths +=  $ExistingNsGroups.where({$_.displayname -eq $XMLmember.name}).path 
                                    }
                                    default {
                                        write-log "$($NSXfqdn): $($XML.name) - $($XMLmember.name) member object type unknown" -level warn 
                                    }
                                }
                            }
                        }
                        $Counter = 0
                        if ($XML.dynamicMemberDefinition) {
                            $XML.dynamicMemberDefinition.dynamicSet.dynamicCriteria | foreach {
                                $Counter ++
                                if ($_.key -eq "VM.NAME") {$membertype = "VirtualMachine"} else {$membertype = $_.key}
                                $GroupCondition += Initialize-Condition -ResourceType Condition -MemberType $membertype -Key Name -Operator $_.criteria -Value $_.value
                                if ($XML.dynamicMemberDefinition.dynamicSet.operator -and ($XML.dynamicMemberDefinition.dynamicSet.dynamicCriteria.count -ne $Counter -xor $XML.dynamicMemberDefinition.dynamicSet.dynamicCriteria.count -eq $null)) {
                                    $GroupCondition += Initialize-ConjunctionOperator -_ConjunctionOperator $XML.dynamicMemberDefinition.dynamicSet.operator -ResourceType ConjunctionOperator
                                }
                            }
                        }

                        
                        $NSgroupVar = initialize-group -DisplayName $XML.name -Description $XML.description -tags $tag -Expression $GroupCondition
                        $CreatedGroup = Invoke-PatchGroupForDomain -DomainId default -Group $NSgroupVar -GroupId $XML.name
                        if ($GroupPathExpressionPaths) {
                            $GroupPathExpression = Initialize-PathExpression -Paths $GroupPathExpressionPaths -Id "$($XML.name)-exp" -ResourceType PathExpression 
                            Invoke-PatchGroupPathExpressionForDomain -DomainId default -GroupId $XML.name -PathExpression $GroupPathExpression -ExpressionId "$($XML.name)-exp"
                        }
                    }
                }
                "IPSet" {
                    $ExistingNsGroups = (Invoke-ListGroupForDomain -DomainId default).Results
                    $GroupCondition = $null
                    if ($ExistingNsGroups.displayname -contains $XML.name -and $overwrite -eq $false) {
                        write-log "$($NSXfqdn): IPSet NsGroup $($XML.name) already exists"
                    } else {
                        Write-Log "$($NSXfqdn): Importing IPSet NsGroup $($XML.name)"
                        if ($XML.value) {
                            $GroupCondition = Initialize-IPAddressExpression -IpAddresses @($XML.value.split(",")) -ResourceType IPAddressExpression 
                        }
                        if ($GroupCondition) {
                            $NSgroupVar = initialize-group -DisplayName $XML.name -Expression $GroupCondition -Description $XML.description -tags $tag -GroupType "IPAddress"
                            $CreatedGroup = Invoke-PatchGroupForDomain -DomainId default -Group $NSgroupVar -GroupId $XML.name 
                        } else {
                            write-log "$($NSXfqdn): Ipset object $($XML.name) has no value, cannot be created." -Level Warn
                        }
                    }
                }
                "Application" {
                    if ($XML.isReadOnly -eq "false" -xor $XML.name -match "APP_") {
                        if ($ExistingServices.displayname -contains $XML.name -and $overwrite -eq $false) {
                            write-log "$($NSXfqdn): Service $($XML.name) already exists" -Level info
                        } else {
                            Write-Log "$($NSXfqdn): Importing Service $($XML.name)"
                            $L4PortSetServiceEntries = @()
                            $ServiceId = $XML.name.Replace(" ","_").Replace("/","")
                            if ($XML.element) {
                                $XML.element | foreach {
                                    $XMLelement = $_
                                    $ElementEntry=0

                                    if ($XMLelement.applicationProtocol -eq "TCP" -or $XMLelement.applicationProtocol -eq "UDP") {
                                        
                                        if ($XMLelement.value) {
                                            $XMLelement.value.split(",") | foreach {
                                                $XMLelementItem = $_
                                                $ElementEntry ++
                                                $L4PortSetServiceEntries += Initialize-L4PortSetServiceEntry -DestinationPorts $XMLelementItem -L4Protocol $XMLelement.applicationProtocol -ResourceType L4PortSetServiceEntry -Id "$($ServiceId)_entry_$($ElementEntry)"
                                            }
                                        } elseif ($XMLelement.sourcePort) {
                                            $XMLelement.sourcePort.split(",") | foreach {
                                                $XMLelementItem = $_
                                                $ElementEntry ++
                                                $L4PortSetServiceEntries += Initialize-L4PortSetServiceEntry -SourcePorts $XMLelementItem -L4Protocol $XMLelement.applicationProtocol -ResourceType L4PortSetServiceEntry -Id "$($ServiceId)_entry_$($ElementEntry)"
                                            }
                                        } else {
                                            $L4PortSetServiceEntries += Initialize-L4PortSetServiceEntry -DestinationPorts "0-65535" -L4Protocol $XMLelement.applicationProtocol -ResourceType L4PortSetServiceEntry -Id "$($ServiceId)_entry_$($ElementEntry)"
                                        }
                                    } elseif ($XMLelement.applicationProtocol -eq "AH") {
                                        $L4PortSetServiceEntries += Initialize-IPProtocolServiceEntry -ProtocolNumber 51 -Id "$($ServiceId)_entry_$($ElementEntry)" -ResourceType IPProtocolServiceEntry
                                    } elseif ($XMLelement.applicationProtocol -eq "ESP") {
                                        $L4PortSetServiceEntries += Initialize-IPProtocolServiceEntry -ProtocolNumber 50 -Id "$($ServiceId)_entry_$($ElementEntry)" -ResourceType IPProtocolServiceEntry
                                    }

                                }
                            }
                            if ($L4PortSetServiceEntries.count -gt 0) {
                                $Service = Initialize-Service -DisplayName $XML.name -ServiceEntries $L4PortSetServiceEntries -Description $XML.description -tags $tag
                                
                                Invoke-PatchServiceForTenant -Service $Service -ServiceId $ServiceId
                            } else {
                                Write-Log "$($NSXfqdn): Importing Service $($XML.name) - failed due incomplete configuration" -level Warn
                                $failedXML += $XML
                                #exit
                            }
                        }
                    }
                    
                }
            } # xml type select
        } #XML node for each
        if ($failedXML) {
            Write-Log "writing failed entries to ./FailedServices.log" -Level Warn
            $failedXML | out-file "FailedServices.log"
            notepad FailedServices.log
            $failedXML = $null
        }
    } # if list

    # DFW security policies incl rules
    if ($XMLimport.firewallConfiguration) {
        $ExistingDfwConfig = (Invoke-ListSecurityPoliciesForDomain -DomainId default).Results
        $ExistingNsGroups = (Invoke-ListGroupForDomain -DomainId default).Results
        
        $DfwSections = $XMLimport.firewallConfiguration.layer3Sections.section
        #[array]::Reverse($DfwSections)


        $SectionId = 0
        foreach ($DfwSecPolicy in $DfwSections) {

            #display progress
            $SectionId ++
            Write-Progress -Activity "security policy" -status "building rulebase" -PercentComplete ((($sectionId) / $DfwSections.count) * 100) -Id 1
            
            $ruleid = 0
            write-log "$($NSXfqdn): $($DfwSecPolicy.name) - Building rulebase"
            $DfwSectionRuleConfig = @()
            foreach ($DfwSectionRule in $DfwSecPolicy.rule) {
                if ($DfwSectionRule.id -ne 1001) {
                    $ruleid ++
                    Write-Progress -Activity "DFW Rules" -status "building rulebase" -PercentComplete ((($ruleid) / $DfwSecPolicy.rule.count) * 100) -ParentId 1
                    #Source
                    $SourceGroupList = @()
                    if ($DfwSectionRule.Sources.Source) {
                        foreach ($DfwSectionRuleSourceItem in $DfwSectionRule.Sources.Source) {
                            switch ($DfwSectionRuleSourceItem.type) {
                                "IPSet" {
                                    $path = ($ExistingNsGroups.where({$_.displayname -eq $DfwSectionRuleSourceItem.name})).path
                                    if ($path) {
                                        $SourceGroupList += $Path
                                    } else {
                                        write-log "$($NSXfqdn): $($DfwSecPolicy.name) - $($DfwSectionRule.name) - NSGroups $($DfwSectionRuleSourceItem.name) not found" -Level Warn
                                    }
                                }
                                "SecurityGroup" {
                                    $path = ($ExistingNsGroups.where({$_.displayname -eq $DfwSectionRuleSourceItem.name})).path
                                    if ($path) {
                                        $SourceGroupList += $Path
                                    } else {
                                        write-log "$($NSXfqdn): $($DfwSecPolicy.name) - $($DfwSectionRule.name) - NSGroups $($DfwSectionRuleSourceItem.name) not found" -Level Warn
                                    }
                                }
                                "Ipv4Address" {
                                    $SourceGroupList += $($DfwSectionRuleSourceItem.value).Replace(" ","")
                                }
                                "Ipv6Address" {
                                    $SourceGroupList += $($DfwSectionRuleSourceItem.value).Replace(" ","")
                                }
                                default {
                                    write-log "$($NSXfqdn): $($DfwSecPolicy.name) - $($DfwSectionRule.name) - Unknown source object type" -Level Warn
                                }
                            }
                        }

                        #validate if all source objects are found
                        if ($DfwSectionRule.sources.source.count -eq $null) { $DfwSectionRuleCount = 1 } else {$DfwSectionRuleCount = $DfwSectionRule.sources.source.count} #an XML element with 1 object will not return a count number
                        if ($DfwSectionRuleCount -ne $sourceGroupList.count) {
                            write-log "$($NSXfqdn): $($DfwSecPolicy.name) - $($DfwSectionRule.name) - not all source objects could be found ($($sourceGroupList.count)/$($DfwSectionRuleCount))" -Level warn
                        }

                    }

                    #Destination
                    $DestinationGroupList = @()
                    if ($DfwSectionRule.destinations.destination) {
                        foreach ($DfwSectionRuleDestinationItem in $DfwSectionRule.destinations.destination) {
                            switch ($DfwSectionRuleDestinationItem.type) {
                                "IPSet" {
                                    $path = ($ExistingNsGroups.where({$_.displayname -eq $DfwSectionRuleDestinationItem.name})).path
                                    if ($path) {
                                        $DestinationGroupList += $Path
                                    } else {
                                        write-log "$($NSXfqdn): $($DfwSecPolicy.name) - $($DfwSectionRule.name) - NSGroups $($DfwSectionRuleDestinationItem.name) not found" -Level Warn
                                    }
                                }
                                "SecurityGroup" {
                                    $path = ($ExistingNsGroups.where({$_.displayname -eq $DfwSectionRuleDestinationItem.name})).path
                                    if ($path) {
                                        $DestinationGroupList += $Path
                                    } else {
                                        write-log "$($NSXfqdn): $($DfwSecPolicy.name) - $($DfwSectionRule.name) - NSGroups $($DfwSectionRuleDestinationItem.name) not found" -Level Warn
                                    }
                                }
                                "Ipv4Address" {
                                    $DestinationGroupList += $($DfwSectionRuleDestinationItem.value).Replace(" ","")
                                }
                                "Ipv6Address" {
                                    $DestinationGroupList += $($DfwSectionRuleDestinationItem.value).Replace(" ","")
                                }
                                default {
                                    write-log "$($NSXfqdn): $($DfwSecPolicy.name) - $($DfwSectionRule.name) - Unknown destination object type" -Level Warn
                                }
                            }
                        }

                        #validate if all destination objects are found
                        if ($DfwSectionRule.destinations.destination.count -eq $null) { $DfwSectionRuleCount = 1 } else {$DfwSectionRuleCount = $DfwSectionRule.destinations.destination.count} #an XML element with 1 object will not return a count number
                        if ($DfwSectionRuleCount -ne $DestinationGroupList.count) {
                            write-log "$($NSXfqdn): $($DfwSecPolicy.name) - $($DfwSectionRule.name) - not all destination objects could be found ($($DestinationGroupList.count)/$($DfwSectionRuleCount))" -Level warn
                        }
                    }

                    #Services
                    $ServicePathList = @()
                    if ($DfwSectionRule.services.service) {
                        foreach ($ServiceItem in $DfwSectionRule.services.service) {
                            $ServicePath = ($ExistingServices.where({$_.displayname -eq $ServiceItem.name})).path
                            if ($ServicePath) {
                                $ServicePathList += $ServicePath
                            } else {
                                write-log "$($NSXfqdn): $($DfwSecPolicy.name) - $($DfwSectionRule.name) - Service $($ServiceItem.name) not found" -Level Warn
                            }
                        }
                    } else {
                        $ServicePathList = "ANY"
                    } 
                
                    #APpliedTo
                    #$DfwSectionRule.appliedToList.appliedTo NVT!

                    #Action
                    if ($DfwSectionRule.action -eq "allow") {
                        $DfwActionType = "ALLOW"
                    } elseif ($DfwSectionRule.action -eq "reject" -or $DfwSectionRule.action -eq "deny") {
                        $DfwActionType = "DROP"
                    }

                    $Id = $DfwSectionRule.name.Replace(" ","_").Replace("/","")
                    $Id = "$($Id)_$($ruleid)"
                    $DfwSectionRuleConfig += Initialize-Rule -DisplayName $DfwSectionRule.name -Id $Id -SourcesExcluded ([System.Convert]::ToBoolean($DfwSectionRule.sources.excluded)) -SourceGroups $SourceGroupList -DestinationsExcluded ([System.Convert]::ToBoolean($DfwSectionRule.destinations.excluded)) -DestinationGroups $DestinationGroupList -Services $ServicePathList -Action $DfwActionType -Tags $tag -Direction $($DfwSectionRule.direction).ToUpper() -Logged ([System.Convert]::ToBoolean($DfwSectionRule.logged)) -Disabled ([System.Convert]::ToBoolean($DfwSectionRule.disabled)) -Tag $DfwSectionRule.tag -SequenceNumber $ruleid
                }
            }
            $Id = $DfwSecPolicy.name.Replace(" ","_").Replace("/","")
            $Id = "$($Id)_$($ruleid)"
            if ($DfwSecPolicy.rule.count -ne $DfwSectionRuleConfig.count) {write-log "$($NSXfqdn): $($DfwSecPolicy.name) - Not all rules could be implemented" -Level Warn}
            $DfwSecPolicyConfig = Initialize-SecurityPolicy -DisplayName $DfwSecPolicy.name -Id $Id -Rules $DfwSectionRuleConfig -Category "Application" -SequenceNumber $SectionId 
            write-log "$($NSXfqdn): $($DfwSecPolicy.name) - Implementing Security Policy"
            $CreatedDfwSecPolicy = Invoke-PatchSecurityPolicyForDomain -DomainId default -SecurityPolicyId $Id -SecurityPolicy $DfwSecPolicyConfig 
            write-log "$($NSXfqdn): $($DfwSecPolicy.name) - Implementing Security Policy - completed"
        }

    }

} #xml file foreach






#get-command -Module vmware.sdk.nsx.policy | out-gridview


 
