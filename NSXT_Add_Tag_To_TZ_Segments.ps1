$NSXfqdn = "nsxmgr.domain.local"
$nsxcred = Get-Credential
Connect-NsxtServer $NSXfqdn -UseRemoteAuthentication -Credential $nsxcred

$nsxtTZproxy = Get-NsxtService -name com.vmware.nsx.transport_zones
$TZselection = ($nsxtTZproxy.list().results) | select display_name, id | Out-GridView -Title "Select Transport Zone" -OutputMode Single

$tag = $nsxtsegmentsproxy.help.update.segment.tags.Element
$tag.tag = "<tag_name>"
$tag.scope = "<scope_name>"

$nsxtsegmentsproxy = get-nsxtpolicyservice -Name com.vmware.nsx_policy.infra.segments
$nsxtxsegments = $nsxtsegmentsproxy.list().results.where({$_.transport_zone_path -match $TZselection.id}) 

foreach ($nsxtxsegment in $nsxtxsegments) {
    if ($nsxtxsegment.tags.tag -notcontains $tag.tag) {
        write-host "NSX-T segment $($nsxtxsegment.display_name) - added tag $($tag.tag)"
        $nsxtxsegment.tags += @($tag)
    }
    $null = $nsxtsegmentsproxy.update($nsxtxsegment.id, $nsxtxsegment)
}
