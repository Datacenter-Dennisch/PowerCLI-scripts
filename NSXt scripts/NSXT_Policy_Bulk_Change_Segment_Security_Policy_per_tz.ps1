
$nsxcred = Get-Credential
Connect-NsxtServer nsxtmanager.vviking.local -UseRemoteAuthentication -Credential $nsxcred

$nsxtTZproxy = Get-NsxtService -name com.vmware.nsx.transport_zones
$TZselection = ($nsxtTZproxy.list().results) | select display_name, id | Out-GridView -Title "Select Transport Zone" -OutputMode Single 
$nsxtsegmentsproxy = get-nsxtpolicyservice -Name com.vmware.nsx_policy.infra.segments
$nsxtxsegments = $nsxtsegmentsproxy.list().results.where({$_.transport_zone_path -match $TZselection.id}) 

$nsxtxsegmentbinding =  get-nsxtpolicyservice -name com.vmware.nsx_policy.infra.segments.segment_security_profile_binding_maps
$segsecprofile = (get-nsxtpolicyservice -name com.vmware.nsx_policy.infra.segment_security_profiles).list().results | Out-GridView -OutputMode Single -Title "Select Segment Security Profile" 
$spoofguardprofile = (get-nsxtpolicyservice -name com.vmware.nsx_policy.infra.spoofguard_profiles).list().results | Out-GridView -OutputMode Single -Title "Select Spoofguard  Profile" 

$nsxtxsegmentbindingmap = $nsxtxsegmentbinding.help.patch.segment_security_profile_binding_map.Create()

$nsxtxsegmentbindingmap.id = $segsecprofile.display_name
$nsxtxsegmentbindingmap.display_name = $segsecprofile.display_name
$nsxtxsegmentbindingmap.segment_security_profile_path = $segsecprofile.path
$nsxtxsegmentbindingmap.spoofguard_profile_path = $spoofguardprofile.path

foreach ($nsxtxsegment in $nsxtxsegments) {
    
    $nsxtxsegmentbinding.patch($nsxtxsegment.id, $segsecprofile.id, $nsxtxsegmentbindingmap)

}
