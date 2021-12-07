function Write-log {

    param (
        [string]$LogFolder,
        [ValidateSet("Info","Warning","Error")]
        [string]$Loglevel="info",
        [parameter(mandatory=$true)]
        [string]$Message
    )
    
    process {
        $daystamp = get-date -Format yyy-dd-MM
        $timestamp = get-date -Format yyy-dd-MM_HH:mm
       
        #check which folder to use
        if ($LogFolder) {
            if (!(test-path -path $LogFolder -ErrorAction SilentlyContinue)) {$LogFolder = $env:TEMP}
        } elseif ($NSXv2tMigrationFolder) {
            $LogFolder = $NSXv2tMigrationFolder        
        } else {
            $LogFolder = $env:TEMP
        }
        
        #create log folder if it does not exist
        if (!(test-path -path "$($LogFolder)\Log" -ErrorAction SilentlyContinue)) {
            New-Item -Path $LogFolder -Name "Log" -ItemType "directory"
            $LogFolder += "\Log"
            write-log -Loglevel Info -Message "New folder ""$($LogFolder)"" created" 
            
        } else {
            $LogFolder += "\Log"
        }
    
        #define log filename
        $LogFile = "$($daystamp)_NSXv2t_migration.log"
        
        #create logfile if it does not exist.
        if (!(test-path "$($LogFolder)\$($LogFile)" -ErrorAction SilentlyContinue)) {
            $null = New-Item -Path $LogFolder -Name $LogFile -ItemType "file"
            write-log -Loglevel Info -Message "New logfile created ""$($LogFolder)\$($LogFile)"" created" 
        }
    
        
        switch ($Loglevel) {
            "Info" {write-host "$($timestamp) $($Loglevel) ### $($Message)"}
            "Warning" {write-host -foregroundcolor Yellow "$($timestamp) $($Loglevel) ### $($Message)"}
            "Error" {write-host -foregroundcolor Red "$($timestamp) $($Loglevel) ### $($Message)"}
        }
        #add content to logfile=
        $null = Add-Content -Path "$($LogFolder)\$($LogFile)" -Value "$($timestamp) $($Loglevel) ### $($Message)" 
    }
    
}
    
#select, check and/or create migration folder structure
if ($NSXv2tMigrationFolder) {
    do {
        write-log -Message "Migration folder ""$($NSXv2tMigrationFolder)"" detected from global variable"
        $answer = (Read-Host "Continue with the following migration folder ""$($NSXv2tMigrationFolder)"" [Y]es or [N]o").ToLower()
    } while (!(($answer -eq 'y') -or ($answer -eq 'n')))
    if ($answer -eq 'y') {
        write-log -Message "Migration folder ""$($NSXv2tMigrationFolder)"" used from global variable, accepted by user"
        $MigrationFolder = $NSXv2tMigrationFolder
    } elseif ($answer -eq 'n') {
        write-log -Message "Migration folder ""$($NSXv2tMigrationFolder)"" detected from global variable, but not used"
        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.RootFolder = "MyComputer"
        $FolderBrowser.Description = "Select folder to put NSVv2t migration data"
        $null = $FolderBrowser.ShowDialog()
        $MigrationFolder = $FolderBrowser.SelectedPath
        write-log -Message "Migration folder ""$($MigrationFolder)"" is selected" -LogFolder $MigrationFolder
    }

} else  {
    Add-Type -AssemblyName System.Windows.Forms
    $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $FolderBrowser.RootFolder = "MyComputer"
    $FolderBrowser.Description = "Select folder to put NSVv2t migration data"
    $null = $FolderBrowser.ShowDialog()
    $MigrationFolder = $FolderBrowser.SelectedPath
    write-log -Message "Migration folder ""$($MigrationFolder)"" is manually selected" -LogFolder $MigrationFolder
}

#add \data to migationdatafolder
if (!(test-path -Path "$($MigrationFolder)\Data" -ErrorAction SilentlyContinue)) {
    $null = New-Item -Path $MigrationFolder -Name "Data" -ItemType "directory"
    write-log -Message "Created Migration Data folder ""$($MigrationDataFolder)"""
} 

#define variable

$MigrationDataFolder = "$($MigrationFolder)\Data"
Set-Variable -Name NSXv2tMigrationFolder -Value $MigrationFolder -Scope global

Write-log -Message "Running pre-checks .."

#check if data migration folder is empty
if (Get-ChildItem -Path $MigrationDataFolder) {
    write-log -Message "Folder $($MigrationDataFolder) contains existing files" -Loglevel Warning
    do{
        $answer = (read-host "Continue with removing files from Folder ""$($MigrationDataFolder)"" [Y]es or [N]o").ToLower()
    } while (!(($answer -eq 'y') -or ($answer -eq 'n')))
    if ($answer -eq 'y') {
        write-log -Message "Removing all files from folder ""$($MigrationDataFolder)"" " -Loglevel Warning
        Get-ChildItem -Path $MigrationDataFolder | Remove-Item -Confirm:$false
    } elseif ($answer -eq 'y') {
        write-log -Loglevel Error -Message "Folder ""$($MigrationDataFolder)"" is not empty, exiting script"
        Write-Error "Folder $MigrationDataFolder is not empty"
    }

} else {write-log -Message "folder $($MigrationDataFolder) is empty" }

#check if  NSX-v PS module exist, if not load it.
if (!( get-module -FullyQualifiedName "PowerNSX")) {
    do {
        write-log -Loglevel Error -message "PS module ""PowerNSX"" is not loaded"
        write-log -Message "trying to install PowerNSX throught the PowerShell galary"
        Find-Module PowerNSX | Install-Module -scope CurrentUser -Confirm:$false
        #if PS galery install method did not work, load it through auto-install from github directly
        if (!( get-module -FullyQualifiedName "PowerNSX")) {
            write-log -loglevel error -Message "installation of PS Module PowerNSX failed throught the PowerShell galary"
            write-log -Message "trying to install PowerNSX throught auto-install directly"
            $Branch="master";$url="https://raw.githubusercontent.com/vmware/powernsx/$Branch/PowerNSXInstaller.ps1"; try { $wc = new-object Net.WebClient;$scr = try { $wc.DownloadString($url)} catch { if ( $_.exception.innerexception -match "(407)") { $wc.proxy.credentials = Get-Credential -Message "Proxy Authentication Required"; $wc.DownloadString($url) } else { throw $_ }}; $scr | iex } catch { throw $_ }
        }
    } while (!( get-module -FullyQualifiedName "PowerNSX"))
} else {write-log -Message "PS Module ""PowerNSX"" correctly loaded"}

if (!$DefaultNSXConnection) {
    write-log -Loglevel Warning -Message "No connection with NSX-v manager detected"
    do {
        $NSXvMgr = read-host "Enter NSX-v manager FQDN" 
        Connect-NsxServer -NsxServer $NSXvMgr
    } while (!$DefaultNSXConnection)
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" established"
} else {
    Write-log -message "Connection with NSX-v manager ""$($DefaultNSXConnection.Server)"" already established"
}

Read-host "Press Enter to start the NSX-v Inventory" 

Write-Progress -Activity "inventory" -PercentComplete 0 -Status "Inventory NSX-V logical switches"
write-log -Message "Inventory NSX-V logical switches"
$NSXvLogicalSwitches = Get-NsxLogicalSwitch 

Write-Progress -Activity "inventory" -PercentComplete 5 -Status "Validating NSX-V logical switches"
write-log -Message "Validating NSX-V logical switches"
$NSXvValidatedLogicalSwitches = @()
foreach ($NSXvLogicalSwitch in $NSXvLogicalSwitches) {
    if ($NSXvLogicalSwitch.isUniversal -eq "true") {
        write-log -Loglevel Warning -Message "Logical Switch ""$($NSXvLogicalSwitch.name)"" is of unsupported type universal"
    } else {
        $NSXvValidatedLogicalSwitches += $NSXvLogicalSwitch
    }
}

Write-Progress -Activity "inventory" -PercentComplete 10 -Status "Exporting NSX-V logical switches"
write-log -Message "Exporting NSX-V logical switches"
$NSXvValidatedLogicalSwitches | Export-Csv -Path "$MigrationDataFolder\NSXvLogicalSwitch.csv"

Write-Progress -Activity "inventory" -PercentComplete 15 -Status "Inventory NSX-V Distributed Logical Routers"
write-log -Message "Inventory NSX-V Distributed Logical Routers"
$NSXvLogicalRouters = Get-NsxLogicalRouter 

Write-Progress -Activity "inventory" -PercentComplete 20 -Status "Validating NSX-V Distributed Logical Routers"
write-log -Message "Validating NSX-V logical switches"
$NSXvValidatedLogicalRouters = @()
foreach ($NSXvLogicalRouter in $NSXvLogicalRouters) {
    if ($NSXvLogicalRouter.isUniversal -eq "true") {
        write-log -Loglevel Warning -Message "Logical Switch ""$($NSXvLogicalRouter.name)"" is of unsupported type universal"
    } else {
        $NSXvValidatedLogicalRouters += $NSXvLogicalRouter
    }
}

Write-Progress -Activity "inventory" -PercentComplete 25 -Status "Exporting NSX-V Distributed Logical Routers"
write-log -Message "Exporting NSX-V Distributed Logical Routers"
$NSXvValidatedLogicalRouters | Export-Csv -Path "$MigrationDataFolder\NSXvLogicalRouters.csv"


$logicalswitches = Invoke-NsxRestMethod -method get -URI "/api/2.0/vdn/virtualwires" -connection $DefaultNSXConnection

while ($logicalswitches -eq $null) {write-host "hoi"}