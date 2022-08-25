param (
    [Parameter(Mandatory = $false)]
    [string]
    $tier0groups,
    [Parameter(Mandatory = $false)]
    [switch]
    $allInfo
)

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
        $flagged_object = foreach($domain in (get-adforest).domains)
            {get-adobject -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
                    -server $domain `
                    -properties whenchanged,whencreated,admincount,isCriticalSystemObject,"msDS-ReplAttributeMetaData",samaccountname |`
                select @{name='Domain';expression={$domain}},distinguishedname,whenchanged,whencreated,admincount,`
                    SamAccountName,objectclass,isCriticalSystemObject,@{name='adminCountDate';expression={($_ | `
                        Select-Object -ExpandProperty "msDS-ReplAttributeMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_ATTR_META_DATA |`
                        where { $_.pszAttributeName -eq "admincount"}}).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}}}
        $default_admin_groups = foreach($domain in (get-adforest).domains){get-adgroup -filter 'admincount -eq 1 -and iscriticalsystemobject -like "*"'`
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
            write-host "[ ] Found $(($orphan_results | measure).count) stale admin objects (admincount attribute set to 1 and inheritance disabled). Please run FixAdminCount1.ps1 script." -ForegroundColor Red
        }else{
            write-host "[X] Found 0 Objects with Stale Admin Count" -ForegroundColor Green
        }
    }
}

Import-Module ActiveDirectory

## Checking Tiering model
write-host ("`nChecking Tiering model`n") -ForegroundColor Cyan
try {
	$null = Get-ADGroup -Identity "tier0admins"
    $null = Get-ADGroup -Identity "tier0servers"
	write-host ("[X] Tier model is in place") -ForegroundColor Green
    if (Get-ADGroupMember -Identity "Domain Admins" | ? {$_.distinguishedName -like "*Tier 0 Admins*"}) {
        write-host ("[X] Tier 0 Admins are member of Domain Admins") -ForegroundColor Green
    }
    } catch {
        write-host ("[ ] Tier model is not properly deployed!") -ForegroundColor Red
}

## Checking AccountsRestrictions
write-host ("`nChecking AccountsRestrictions GPO`n") -ForegroundColor Cyan
$root = (Get-ADObject -Identity (Get-ADDomain).distinguishedName -Properties name, distinguishedName, gPLink, gPOptions).gplink 

$arguid = (get-gpo -all | ? {$_.DisplayName -like "*AccountsRestriction*"}).id

$link = $root -split ("]") -match $arguid

if ($link) {
	write-host ("[X] AccountsRestrictions policy is linked to the ROOT of the domain!") -ForegroundColor Green

    $linkstatus = $link -replace '^.*(?=.{1}$)'

    switch ($linkstatus) {
        0 {write-host ("[ ] Policy link is enabled but not enforced!") -ForegroundColor Red}
        1 {write-host ("[ ] Policy link is nor enabled or enforced!") -ForegroundColor Red}
        2 {write-host ("[X] Policy link is enabled and enforced!") -ForegroundColor Green}
        3 {write-host ("[ ] Policy link is not enabled but it is enforced!") -ForegroundColor Red}
    } 
} else {
    write-host ("[ ] AccountsRestrictions policy is not linked to the ROOT of the domain!") -ForegroundColor Red
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

Write-Host "`nChecking Tier 0 Servers`n" -ForegroundColor Cyan
if (Get-childitem "AD:\CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,*" ) {
    write-host ("[!] You have PKI deployed in this domain. Make sure that PKI servers are moved to the appropriate OU and added to the Tier0Servers Group.") -ForegroundColor Yellow 
}
if (get-aduser -Filter * | ? {$_.name -like 'MSOL_*'}) {
    write-host ("[!] You have Azure AD Connect deployed in this domain. Make sure that AADCon servers are moved to the appropriate OU and added to the Tier0Servers Group.") -ForegroundColor Yellow 
}
if (get-adcomputer -Filter * | ? {$_.name -like '*ADFS*'}) {
    write-host ("[!] You probably have ADFS deployed in this domain. Make sure that ADFS servers are moved to the appropriate OU and added to the Tier0Servers Group.") -ForegroundColor Yellow 
}


$allusers = $AllTier0UsersDN | Sort-Object | Get-Unique

Write-Host "`nChecking Tier 0 Users`n" -ForegroundColor Cyan
$allT0Accounts = (Get-AdGroupMember "Tier0Accounts" -Recursive).distinguishedname
foreach ($user in $allusers) {
    if ($user -in $allT0Accounts) {
        write-host ("[X] $user is reckognized as a Tier 0 user and is member of Tier 0 Accounts Group") -ForegroundColor Green
    } else {
        write-host ("[ ] $user is reckognized as a Tier 0 user but it is NOT member of Tier 0 Accounts Group") -ForegroundColor Red
    }
}



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


Write-Host "`nTier 0 Groups that should be cleaned up" -ForegroundColor Cyan
$needsCleanUp = 0
foreach ($group in $allgroups) {
    $members = Get-ADGroupmember -Identity $group
    
    if ($group -like "*CN=Domain Admins*" -and ($members | measure-object).count -gt 1){
        $needsCleanUp += 1
        Write-Host "`n$group - This group should have only 1 member - Tier 0 Admins Group." -ForegroundColor Red
        foreach ($member in $members)  {
            if ($member.distinguishedname -like "*Tier 0 Admins,*") {
                Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname
            } else {
                Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname -ForegroundColor Yellow
            }
            
        }   
    } 
    if ($group -like "*CN=Administrators*" -and ($members | measure-object).count -gt 3){
        $needsCleanUp += 1
        Write-Host "`n$group - This group should have only 3 members - DA, EA and Break Glass account." -ForegroundColor Red
        foreach ($member in $members)  {
            if ($member.distinguishedname -like "*Domain Admins,*" -or $member.distinguishedname -like "*Enterprise Admins,*") {
                Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname
            } else {
                Write-Host "`t["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname -ForegroundColor Yellow
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

$null = Stop-Transcript