    <#
    .SYNOPSIS
    Check if Tier 0 model is properly deployed
    .DESCRIPTION
    Author: Vladimir Mutić
    Version 0.9

    This script will go through Tier 0 configuration and check if it is applied properly

    .PARAMETER tier0groups (OPTIONAL)
    You can specify list of additional Tier 0 groups specific to your org. Specify the full source path to the CSV file i.e c:\temp\Tier0Groups.csv with DNs of your groups.
    CSV need to have DN column defined
    .EXAMPLE
    .\Check-Tier0.ps1 -tier0groups c:\temp\Tier0Groups.csv
    .PARAMETER breakGlassAccount (OPTIONAL)
    You should provide DN of break glass account. This will allow script to correctly identify this accounts within reports.
    .EXAMPLE
    .\Check-Tier0.ps1 -breakGlassAccount "CN=bga,CN=Users,DC=contoso,DC=com"
    .PARAMETER allInfo (OPTIONAL)
    If this parameter is specified, script will provide detailed info regarding all Tier 0 users and groups
    .EXAMPLE
    .\Check-Tier0.ps1 -allInfo

    .DISCLAIMER
    All scripts and other powershell references are offered AS IS with no warranty.
    These script and functions are tested in my environment and it is recommended that you test these scripts in a test environment before using in your production environment.
    #>



param (
    [Parameter(Mandatory = $false)]
    [string]
    $tier0groups,
    [Parameter(Mandatory = $false)]
    [string]
    $breakGlassAccount,
    [Parameter(Mandatory = $false)]
    [switch]
    $allInfo,
    [Parameter(Mandatory = $false)]
    [switch]
    $checkTierModel
)



#Checks if the user is in the administrator group. Warns and stops if the user is not.
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You are not running this as local administrator. Run it again in an elevated prompt."
    Break
}
try {
    Import-Module ActiveDirectory
}
catch {
    Write-Warning "The Active Directory module was not found"
}


$dt=get-date -format yyyy-MM-DD-hhmmss

$null = Start-Transcript -Path .\Check-Tier0-$dt.log -NoClobber

function CheckTrusts {
    write-host ("`nChecking Trusts`n") -ForegroundColor Cyan
    $trusts = Get-ADTrust -Filter * -Properties whenchanged
    if ($trusts) {
        foreach ($trust in $trusts) {
            $now = get-date
            $trustchanged =  (Get-ADTrust -identity $trust.name -Properties whenchanged).whenchanged
            if ((New-TimeSpan -Start $trustchanged -End $now).days -lt 45) {
                write-host "[X] Trust password for" $trust.target "was last changed in less than 45 days. All good!" -ForegroundColor Green
            } else {
                write-host "[ ] Trust password for $trust.name was not changed in more than 45 days." -ForegroundColor Red
            }       
        }
    } else {
        write-host ("No trusts were found in this domain.") -ForegroundColor Green
    }
}

Function ADObjectswithStaleAdminCount{
    #users_with_admincount
    [cmdletbinding()]
    param()
    process{
        $reportpath = "$env:userprofile\Documents"

        $orphan_log = "$reportpath\report_ADObjectswithStaleAdminCount.csv"
        $default_log = "$reportpath\report_ADObjectsMembersofPrivilegedGroups.csv"
        write-host ("`nChecking Stale Admin Count`n") -ForegroundColor Cyan
        
        #users with stale admin count
        $results = @();$orphan_results = @();$non_orphan_results  = @()
        $flagged_object = foreach($domain in (get-addomain).dnsroot)
            {get-adobject -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
                    -server $domain `
                    -properties whenchanged,whencreated,admincount,isCriticalSystemObject,"msDS-ReplAttributeMetaData",samaccountname |`
                select @{name='Domain';expression={$domain}},distinguishedname,whenchanged,whencreated,admincount,`
                    SamAccountName,objectclass,isCriticalSystemObject,@{name='adminCountDate';expression={($_ | `
                        Select-Object -ExpandProperty "msDS-ReplAttributeMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_ATTR_META_DATA |`
                        where { $_.pszAttributeName -eq "admincount"}}).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}}}
        $default_admin_groups = foreach($domain in (get-addomain).dnsroot){get-adgroup -filter 'admincount -eq 1 -and iscriticalsystemobject -like "*"'`
                    -server $domain | select @{name='Domain';expression={$domain}},distinguishedname}
        foreach($object in $flagged_object){
            $udn = ($object).distinguishedname
            $results = foreach($group in $default_admin_groups){
                $object | select `
                    @{Name="Group_Domain";Expression={$group.domain}},`
                    @{Name="Group_Distinguishedname";Expression={$group.distinguishedname}},`
                    @{Name="Member";Expression={if(Get-ADgroup -Filter {member -RecursiveMatch $udn} -searchbase $group.distinguishedname -server $group.domain){$True}else{$False}}},`
                    domain,distinguishedname,admincount,adminCountDate,whencreated,objectclass
            }
            if($results | where {$_.member -eq $True}){
                $non_orphan_results += $results | where {$_.member -eq $True}
            }else{
                #$results | select Domain,objectclass,admincount,adminCountDate,distinguishedname | get-unique
                $orphan_results += $results  | select Domain,objectclass,admincount,adminCountDate,distinguishedname | get-unique
            }
        }
        $non_orphan_results | export-csv $default_log -NoTypeInformation
        $orphan_results | export-csv $orphan_log -NoTypeInformation
        if($orphan_results){
            write-host "[ ] Found $(($orphan_results | Measure-Object).count) stale admin objects (admincount attribute set to 1 and inheritance disabled). Please run FixAdminCount1.ps1 script." -ForegroundColor Red
        }else{
            write-host "[X] Found 0 Objects with Stale Admin Count" -ForegroundColor Green
        }
    }
}

## Checking iportant accounts
write-host ("`nChecking important accounts`n") -ForegroundColor Cyan
if ($breakGlassAccount) {
    $bga=(get-aduser -identity $breakGlassAccount).distinguishedName
    write-host ("[X] Break Glass Account is defined as $bga") -ForegroundColor Green
} else {$bga = "unknownBreakGlassAccount"}
## check default administrator account (sid-500), current name (if it was renamed) and if it is enabled

# Retrieve the Administrator user by SID
$adminUser = Get-ADUser -filter * | ? { $_.SID -like "S-1-5-21-*-500" }

# Extract the required properties
$da = $adminUser.DistinguishedName
$daEnabled = $adminUser.Enabled
write-host ("[X] Default Administrator account is $da") -ForegroundColor Green
if ($daEnabled) {
    write-host ("[X] Default Administrator account is enabled") -ForegroundColor Green
    if ($breakGlassAccount) {
        if ($bga -ne $da) {
            write-host ("[ ] You have separate Break Glass Account, so you should disable default Administrator account.") -ForegroundColor Yellow
        } else {
            write-host ("[X] Break Glass Account is the same as Default Administrator account") -ForegroundColor Green
            $bga = $da
        }
    } 
} else {
    write-host ("[ ] Default Administrator account is disabled") -ForegroundColor Red
    if (!$breakGlassAccount) {
        write-host ("[ ] You didn't provide name of Break Glass Account. Make sure that you have one in case of emergency.") -ForegroundColor Yellow
    } 
}


## Checking Tiering model
if ($checkTierModel) {
    write-host ("`nChecking Tiering model`n") -ForegroundColor Cyan
    try {
        $null = Get-ADGroup -Identity "tier0admins"
        $null = Get-ADGroup -Identity "tier0servers"
        write-host ("[X] Tier model is in place") -ForegroundColor Green
        if (Get-ADGroupMember -Identity "Domain Admins" | Where-Object {$_.distinguishedName -like "*Tier 0 Admins*"}) {
            write-host ("[X] Tier 0 Admins are member of Domain Admins") -ForegroundColor Green
        }
        } catch {
            write-host ("[ ] Tier model is not properly deployed!") -ForegroundColor Red
    }

    ## Checking AccountsRestrictions
    write-host ("`nChecking AccountsRestrictions GPO`n") -ForegroundColor Cyan
    $root = (Get-ADObject -Identity (Get-ADDomain).distinguishedName -Properties name, distinguishedName, gPLink, gPOptions).gplink 

    $arguid = (get-gpo -all | Where-Object {$_.DisplayName -like "*AccountsRestriction*"}).id

    $link = $root -split ("]") -match $arguid

    if ($link) {
        write-host ("[X] AccountsRestrictions policy is linked to the ROOT of the domain!") -ForegroundColor Green

        $linkstatus = $link -replace '^.*(?=.{1}$)'

        switch ($linkstatus) {
            0 {write-host ("[ ] Policy link is enabled but not enforced!") -ForegroundColor Red}
            1 {write-host ("[ ] Policy link is nor enabled or enforced!") -ForegroundColor Red}
            2 {write-host ("[X] Policy link is enabled and enforced!") -ForegroundColor Green}
            3 {write-host ("[ ] Policy link is enforced but it is not enabled!") -ForegroundColor Red}
            } 
    } else {
        write-host ("[ ] AccountsRestrictions policy is not linked to the ROOT of the domain!") -ForegroundColor Red
    }
}

## Checking KRBTGT
write-host ("`nChecking KRBTGT`n") -ForegroundColor Cyan
$now = get-date
$krbtgtlch =  (get-aduser -identity krbtgt -properties passwordlastset).passwordlastset 
if ((New-TimeSpan -Start $krbtgtlch -End $now).days -lt 180) {
	write-host "[X] KRBTGT password was changed less than 180 days ago." -ForegroundColor Green
} else {
	write-host "[ ] KRBTGT password was changed more than 180 days ago." -ForegroundColor Red
}

## Checking Stale Admin Count

ADObjectswithStaleAdminCount

## Checking Trusts

CheckTrusts

## Checking Group Membership

$DefaultTier0Groups = `
    "Account Operators", `
    "Administrators", `
    "Backup Operators", `
    "Domain Admins", `
    "Enterprise Admins", `
    "Print Operators", `
    "Schema Admins", `
    "Server Operators"

Function Get-ADNestedGroups {
    param($Members)

    foreach ($member in $Members) {
        $out = Get-ADGroup -filter "DistinguishedName -eq '$member'" -properties members
        $out | Select-Object distinguishedName
        Get-ADNestedGroups -Members $out.Members
    }
}

$AllTier0GroupsDN = @()
$AllTier0UsersDN = @()

foreach ($Group in $DefaultTier0Groups) {
    $grpDN = (get-adgroup -identity $group).distinguishedname
    $AllTier0GroupsDN += $grpdn
}

if ($Tier0Groups) {
    $myTier0Groups = import-CSV -path $Tier0Groups
    foreach ($Group in $myTier0Groups) {
        $grpDN = get-adgroup -identity $group.DN
        $AllTier0GroupsDN += $grpdn.distinguishedname
    }
}

foreach ($group in $AllTier0GroupsDN) {
    $members = (Get-ADGroup -Identity $group -Properties Members).Members
    $all = Get-ADNestedGroups $members
    $AllTier0GroupsDN += $all.distinguishedname
}

$allgroups = $AllTier0GroupsDN | Sort-Object | Get-Unique

foreach ($group in $allgroups) {
    $grpDN = (get-adgroup -identity $group).distinguishedname
    $AllTier0UsersDN += (Get-ADGroupMember -Identity $grpdn -recursive).distinguishedname
}

Write-Host "`nChecking additional Tier 0 Servers (beside DCs)`n" -ForegroundColor Cyan
$additionalTier0Servers = 0
if (Get-childitem "AD:\CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,*" | ? {$_.objectclass -ne "container"}) {
    write-host ("[!] You have PKI deployed in this domain. Make sure that PKI servers are moved to the appropriate OU and added to the Tier0Servers Group.") -ForegroundColor Yellow
    $additionalTier0Servers +=1 
}
if (get-aduser -Filter * | ? {$_.name -like 'MSOL_*'}) {
    write-host ("[!] You have Azure AD Connect deployed in this domain. Make sure that AADCon servers are moved to the appropriate OU and added to the Tier0Servers Group.") -ForegroundColor Yellow
    $additionalTier0Servers +=1  
}
if (get-adcomputer -Filter * | ? {$_.name -like '*ADFS*'}) {
    write-host ("[!] You probably have ADFS deployed in this domain. Make sure that ADFS servers are moved to the appropriate OU and added to the Tier0Servers Group.") -ForegroundColor Yellow 
    $additionalTier0Servers +=1 
}
if ($additionalTier0Servers -eq 0) {
    write-host ("[X] No additional Tier 0 servers found.") -ForegroundColor Green
}

write-host ("`nChecking Tier 0 Users and Groups") -ForegroundColor Cyan

$allusers = $AllTier0UsersDN | Sort-Object | Get-Unique

if ($allInfo) {
    Write-Host "`nThese groups are recognized as a Tier 0 Groups `n"  -ForegroundColor Green
    $allgroups
    
    Write-Host "`nThese users are recognized as a Tier 0 Users `n"  -ForegroundColor Green
    $allusers
    
    Write-Host "`nTier 0 Groups and Users - membership" -ForegroundColor Green
    foreach ($group in $allgroups) {
        Write-Host "`n[ P ]" $group
        $members = Get-ADGroupmember -Identity $group
        foreach ($member in $members)  {
            Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname
        }
    }
}

if ($checkTierModel) {
    Write-Host "`nChecking Tier 0 Users`n" -ForegroundColor Cyan
    $allT0Accounts = (Get-AdGroupMember "Tier0Accounts" -Recursive).distinguishedname
    foreach ($user in $allusers) {
    if (($user -in $allT0Accounts) -and ($user -notmatch $bga)) {
        write-host ("[X] $user is reckognized as a Tier 0 user and is member of Tier 0 Accounts Group") -ForegroundColor Green
    } elseif (($user -notin $allT0Accounts) -and ($user -notmatch $bga)) {
        write-host ("[ ] $user is reckognized as a Tier 0 user but it is NOT member of Tier 0 Accounts Group") -ForegroundColor Red
    }
    }
}

Write-Host "`nChecking Users in Default Users Container`n" -ForegroundColor Cyan
# Retrieve the actual domain parameter dynamically
$domain = (Get-ADDomain).DistinguishedName

# Define the default Users container using the actual domain parameter
$defaultUsersContainer = "CN=Users,$domain"
foreach ($user in $allUsers) {
    if ($user -like "*$defaultUsersContainer*") {
        Write-Host ("[!] $($user) is located in the default Users container. Consider moving it to the Admin OU.") -ForegroundColor Yellow
    }
}

Write-Host "`nTier 0 Groups that should be cleaned up" -ForegroundColor Cyan
$needsCleanUp = 0
foreach ($group in $allgroups) {
    $members = Get-ADGroupmember -Identity $group
    
    if ($group -like "*CN=Domain Admins*" -and ($members | measure-object).count -gt 2){
        $needsCleanUp += 1
        Write-Host "`n$group - This group should have only 2 members - Tier 0 Admins Group and Break Glass Account." -ForegroundColor Red
        foreach ($member in $members)  {
            if ($member.distinguishedname -like "*Tier 0 Admins,*" -or $member.distinguishedname -like "*$bga*") {
                Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname
            } else {
                Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname -ForegroundColor Yellow
            }
            
        }   
    } 
    if ($group -like "*CN=Administrators*" -and ($members | measure-object).count -gt 2){
        
        Write-Host "`n$group - This group should have up to 3 members - Domain Admins, Enterprise Admins groups and optionally, Break Glass Account." -ForegroundColor Red
        foreach ($member in $members)  {
            if ($member.distinguishedname -like "*Domain Admins,*" -or $member.distinguishedname -like "*Enterprise Admins,*" -or $member.distinguishedname -like "*$bga*") {
                Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname
            } else {
                Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname -ForegroundColor Yellow
                $needsCleanUp += 1
            }
            
        }       
    } 
    if ($group -like "*CN=Enterprise Admins*" -and ($members | measure-object).count -gt 0){
        $needsCleanUp += 1
        Write-Host "`n$group - This group should be empty." -ForegroundColor Red
        foreach ($member in $members)  {
            Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname -ForegroundColor Yellow
        }        
    } 
    if ($group -like "*CN=Schema Admins*" -and ($members | measure-object).count -gt 0){
        $needsCleanUp += 1
        Write-Host "`n$group - This group should be empty." -ForegroundColor Red
        foreach ($member in $members)  {
            Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname -ForegroundColor Yellow
        }      
    } 
    if ($group -like "*CN=Account Operators*" -and ($members | measure-object).count -gt 0){
        $needsCleanUp += 1
        Write-Host "`n$group - This group should be empty." -ForegroundColor Red
        foreach ($member in $members)  {
            Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname -ForegroundColor Yellow
        }      
    } 
    if ($group -like "*CN=Backup Operators*" -and ($members | measure-object).count -gt 0){
        $needsCleanUp += 1
        Write-Host "`n$group - This group should be empty." -ForegroundColor Red
        foreach ($member in $members)  {
            Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname -ForegroundColor Yellow
        }      
    } 
    if ($group -like "*CN=Print Operators*" -and ($members | measure-object).count -gt 0){
        $needsCleanUp += 1
        Write-Host "`n$group - This group should be empty." -ForegroundColor Red
        foreach ($member in $members)  {
            Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname -ForegroundColor Yellow
        }      
    } 
    if ($group -like "*CN=Server Operators*" -and ($members | measure-object).count -gt 0){
        $needsCleanUp += 1
        Write-Host "`n$group - This group should be empty." -ForegroundColor Red
        foreach ($member in $members)  {
            Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname -ForegroundColor Yellow
        }      
    } 
}
if ($needsCleanUp -eq 0) {
    Write-Host "`nNothing.. CONGRATULATIONS.. you did your job!`n" -ForegroundColor Green
}

## Check all disabled accounts in domain. Log all disabled users to the file with timestap in the name.
Write-Host "`nLooking for Disabled Tier 0 users. List of all disabled users can be found in csv file within this directory.`n" -ForegroundColor Cyan
$disabledUsers = Get-ADUser -Filter {Enabled -eq $false} | Select-Object Name, SamAccountName, DistinguishedName
$disabledUsers | Export-Csv -Path .\DisabledUsers-$dt.csv -NoTypeInformation
## Print on screen only disabled users contained in $allUsers
foreach ($user in $allUsers) {
    if ($user -in $disabledUsers.DistinguishedName) {
        write-host ("$user is disabled but still has high privileges.") -ForegroundColor Yellow
    }
}

## For each account in $allUsers check they are used in the last 90 days. If not, log them to the file with timestap in the name.
Write-Host "`nLooking for Tier 0 Users with LastLogonTimeStamp greater than 90 days.`n" -ForegroundColor Cyan
$now = Get-Date
$lastLogon = $now.AddDays(-90)
$inactiveUsers = @()
foreach ($user in $allUsers) {
    $lastLogonDate = (Get-ADUser -Identity $user -Properties LastLogonTimeStamp).LastLogonTimeStamp
    if ($lastLogonDate) {
        $lastLogonDate = [DateTime]::FromFileTime($lastLogonDate)
    } else {
        $lastLogonDate = $null
    }
    if ($lastLogonDate -lt $lastLogon) {
        $inactiveUsers += $user
    }
}
$inactiveUsers

Write-Host "`nThat's all Folks!`n" -ForegroundColor Yellow

$null = Stop-Transcript