    <#
    .SYNOPSIS
    Author: Vladimir Mutić
    Version 0.1

    .DESCRIPTION
    Creates security group for each sub OU below stated OU

    .PARAMETER OU (MANDATORY)
    Specify the name of OU in which you want to create security groups.

    .EXAMPLE
    .\CreateSecGrps.ps1 -OU 'OU=admin,DC=Contoso,DC=COM'

    .PARAMETER LVL (OPTIONAL)
    Defines depth of search. By default it will go one level deep.

    .EXAMPLE
    .\CreateSecGrps.ps1 -OU 'OU=admin,DC=Contoso,DC=COM' -lvl 3

    .DISCLAIMER
    All scripts and other powershell references are offered AS IS with no warranty.
    These script and functions are tested in my environment and it is recommended that you test these scripts in a test environment before using in your production environment.
    #>


[CmdletBinding()]
param (
    # Parameter help description
    [Parameter(Mandatory = $true)]
    [string]
    $BaseOrgUnit,
    # Parameter help description
    [Parameter(Mandatory = $false)]
    [ValidateSet("Base","OneLevel","Subtree")]
    [string]
    $lvl="OneLevel"
)

BEGIN{
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
    break
    }
    try {
        Import-module AdmPwd.PS
    }
    catch {
        Write-Warning "The AdmPWD module was not found"
    break
    }
}

PROCESS {

    $OUS = Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase $BaseOrgUnit -SearchScope $lvl

    foreach ($OU in $OUS) {
        $grp_name = ("t2a-"+($OU.name)) -replace " ",""
        $grp_path = $OU.DistinguishedName

        Write-Host "`nOU - $OU.distinguishedname" -ForegroundColor Gray
        
        try{
            if(Get-ADGroup -filter {Name -eq $grp_name} -ErrorAction Continue)
            {
                Write-Host "Security group already exists for this OU" -ForegroundColor Green
                    $Result = "Already_Exists"
            } else 
                {
                    Write-Host "Creating security group for this OU" -ForegroundColor Green
                    New-ADGroup -Name $grp_name -SamAccountName $grp_name -GroupCategory Security -GroupScope Global -DisplayName $grp_name -Path $grp_path -Description "Members of this group will be able to retrieve passwords for computers within this OU"
                    $Result = 'Success'
                }
        }
        catch{
        $ErrorMessage = $_.Exception
        }
        
        Write-Host "Granting LAPS permissions on" $OU.name "for" $grp_name -ForegroundColor Yellow
        $null = Set-AdmPwdReadPasswordPermission -OrgUnit $OU.name -AllowedPrincipals $grp_name
        $null = Set-AdmPwdResetPasswordPermission -OrgUnit $OU.name -AllowedPrincipals $grp_name

    }

    Write-Host "`nAll done!`n" -ForegroundColor Green

}
