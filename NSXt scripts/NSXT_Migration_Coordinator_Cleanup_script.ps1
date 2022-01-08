function Write-Log {
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
        [string]$Path='D:\Security scripts\Logs\debug.log',
        
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

$NSXTServers = $("NSXTmgr.vViking.nl")
foreach ($NSXTServer in $NSXTServers) {
    if ($global:DefaultNSXtServers.name -notcontains $NSXTServer ) {
        Write-log -message "Connecting to NSX-T Manager ""$($NSXTServer)""." -Level Info
        do {
            if (!$GlobalCredential) {$Credential = Get-Credential} else {$Credential = $GlobalCredential}
            $null = Connect-NSXTServer -Server $NSXTServer -Credential $Credential
        } until ($global:DefaultNSXtServers.name -contains $NSXTServer )
        $GlobalCredential = $Credential
        Write-log -message "Connection with NSX-T Manager ""$($NSXTServer)"" established" -Level Info
    } else {
        Write-log -message "Connection with NSX-T Manager ""$($NSXTServer)"" already established" -Level info
    }
}


#set proxy cmdlets.
$groupsproxy = Get-NsxtpolicyService -Name com.vmware.nsx_policy.infra.domains.groups
$groupassocsproxy = Get-NsxtpolicyService -name com.vmware.nsx_policy.global_infra.group_associations
$grouppathexpressionproxy = Get-NsxtpolicyService -name com.vmware.nsx_policy.infra.domains.groups.path_expressions

#retrieve all policy based groups.
$groupobjectsreturn = $groupsproxy.list("default")

$groupobjects = @()
$groupobjects = $groupobjectsreturn.results
do  {
    $groupobjectsreturn = $groupsproxy.list("default",$groupobjectsreturn.cursor)
    $groupobjects += $groupobjectsreturn.results
} while ($groupobjectsreturn.cursor)

#filter temporary objects from all groups based on tag scope "v_temporary"
$grouptempobjects = $groupobjects.where({$_.tags.scope -eq "v_temporary"})

foreach ($grouptempobject in $grouptempobjects[0]) {
    
    write-log -message "retrieve parent group target from temporary group object ""$($grouptempobject.display_name)""."
    $ParentGroupsTargets = $groupassocsproxy.list($grouptempobject.path).results

    if ($ParentGroupsTargets) {
        foreach ($ParentGroupID in $ParentGroupsTargets.target_id) {
            #retrieve group object from parent group target id
            $ParentGroup = $groupsproxy.get("default", $ParentGroupID.Split("/")[5])
            $ParentGroupid = $ParentGroup.id
            write-log -message "group ""$($grouptempobject.display_name)"" is member from parent group ""$($ParentGroup.display_name)""."

            #retrieve pathexpression details from parent group
            $ParentGroupPathExpressionObj = $ParentGroup.expression.where({$_.resource_type -eq "PathExpression"})
            $ParentGroupPathExpressionObjId = $ParentGroupPathExpressionObj.id.Value
            $ParentGroupPathExpressionObjPaths = $ParentGroupPathExpressionObj.paths.value

            #recreate Group Path Expression specification without the temporary group.
            $ParentGroupPathExpressionObjspec = $grouppathexpressionproxy.help.patch.path_expression.Create()
            $ParentGroupPathExpressionObjspec.id = $ParentGroupPathExpressionObj.id
            $ParentGroupPathExpressionObjspec.resource_type = $ParentGroupPathExpressionObj.resource_type
            $ParentGroupPathExpressionObjspec.paths = $ParentGroupPathExpressionObjPaths.where({$_ -ne $ParentGroupPathExpressionObjPath})

            #$grouppathexpression.patch("default", $ParentGroupid, $ParentGroupPathExpressionObjId, $ParentGroupPathExpressionObjspec)
            write-log -Message "$($ParentGroupPathExpressionObjPathmember.display_name) removed as a member from (parent) group $($ParentGroup.display_name)" -Level Warn
        }
    } else {
        write-log -message "group ""$($grouptempobject.display_name)"" is not a member from a parent group."
    }
    #$groupsproxy.delete("default",$grouptempobject.id)
}



