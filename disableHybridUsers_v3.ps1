param(
  [String[]]$UserList,
  [String]$OUPath,
  [String]$TempPW
)

<#
#
# Disable Hybrid Users
# By Kevin Birk - 10/24/2025
#
# The params at the top accept arguments
# -UserList user1,user2,user3
# -OUPath "OU=Users,OU=Users and Groups,OU=Name Corp,DC=namecorp,DC=local"
# -TempPW "e5chAS3412Av3"
#
# Example usage: .\DisableHybridUsers_v1.ps1 -UserList user1,user2,user3 -OUPath "OU=Users,OU=Users and Groups,OU=Name Corp,DC=namecorp,DC=local" -TempPW "e5chAS3412Av3"
#
# This script goes through a standard internal process for disabling users in
# a windows hybrid domain environment using Active Directory (AD), Microsoft Graph (MG),
# and ExchangeOnline (EXCH). I have tested and run this successfully only in Powershell 7
# so far. This script requires to connect to MSGraph and ExchangeOnline before you run it.
# Run Connect-MGGraph first, and then run Connect-ExchangeOnline afterwards.
#
#>

# Import these modules as they are needed
Import-Module ActiveDirectory
Import-Module -UseWindowsPowerShell -Name ADSync

# Define log path and create log file if it doesn't already exist
$LogFile = "disableHybridUsers_v3_($env:computername).txt"
if (-not (Test-Path "disableHybridUsers_v3_($env:computername).txt")) {
     Out-File -FilePath $LogFile
}

# Set date and write initial log entry
$DateTime = Get-Date -Format "MM/dd/yyyy HH:mm"
Write-Output "START DISABLE USERS JOB AT $DateTime"
Add-Content -Path $LogFile -Value "START DISABLE USERS JOB AT $DateTime"
Write-Output "AD Local Portion:"
Add-Content -Path $LogFile -Value "AD Local Portion:"

# Edit this list to include the scope of users you would like to disable
# $userList = @("abriceno", "areyes")
Write-Output "$($DateTime): UserList: $($UserList)"
Add-Content -Path $LogFile -Value "$($DateTime): UserList: $($UserList)"
# $OUPath = "OU=Disabled Users,OU=Users,OU=Users and Groups,OU=Container,DC=Contoso,DC=local"
Write-Output "$($DateTime): disabledUsersOUPath: $($OUPath)"
Add-Content -Path $LogFile -Value "$($DateTime): disabledUsersOUPath: $($OUPath)"
Write-Output ""
Add-Content -Path $LogFile -Value ""

# Main loop
foreach ($User in $UserList){

  # Add a Line
  Write-Output "----------"
  Add-Content -Path $LogFile -Value "----------"  
  # Add a space
  Write-Output ""
  Add-Content -Path $LogFile -Value ""

  $DateTime = Get-Date -Format "MM/dd/yyyy HH:mm"

  # Start User
  Write-Output "$($DateTime): Start User $($User)"
  Add-Content -Path $LogFile -Value "$($DateTime): Start User $($User)"
  
  # Add a space
  Write-Output ""
  Add-Content -Path $LogFile -Value ""

  # Start AD Portion
  Write-Output "AD Local Portion:"
  Add-Content -Path $LogFile -Value "AD Local Portion:"

  # Populate variables
  $TempUserSamAcctName = "$User"
  $TempADUser = Get-ADUser -Identity $TempUserSamAcctName -Properties MemberOf,DisplayName,DistinguishedName
  $TempADUserGroups = Get-ADPrincipalGroupMembership -Identity $TempUserSamAcctName

  # Make changes
  Set-ADAccountPassword -Identity $TempUserSamAcctName -NewPassword (ConvertTo-SecureString -AsPlainText $TempPW)
  Set-ADUser -Identity $TempUserSamAcctName -ChangePasswordAtLogon $True
  Disable-ADAccount -Identity $TempUserSamAcctName
  Set-ADUser -Identity $TempUserSamAcctName -Replace  @{'msDS-cloudExtensionAttribute1'="HideFromGAL"}
  Move-ADObject -Identity ($TempADUser.DistinguishedName) -TargetPath $OUPath

  # Write results to log + console
  # Document UserPrincipalName
  $DateTime = Get-Date -Format "MM/dd/yyyy HH:mm"
  Write-Output "$($DateTime): UserPrincipalName: $($TempADUser.UserPrincipalName)"
  Add-Content -Path $LogFile -Value "$($DateTime): UserPrincipalName: $($TempADUser.UserPrincipalName)"
  # Document User DistinguishedName
  Write-Output "$($DateTime): DistinguishedName: $($TempADUser.DistinguishedName)"
  Add-Content -Path $LogFile -Value "$($DateTime): DistinguishedName: $($TempADUser.DistinguishedName)"
  # Write output of users' groups they are a member of to log and console
  Write-Output "$($DateTime): AD Groups MemberOf:"
  Add-Content -Path $LogFile -Value "$($DateTime): AD Groups MemberOf:"  
  ForEach ($group in $TempADUserGroups){
    Write-Output "$group.name"
    Add-Content -Path $LogFile -Value "$group.name"
  }

  # Add a space
  Write-Output ""
  Add-Content -Path $LogFile -Value ""

  # Start Entra and O365 Portion
  Write-Output "$($DateTime): MS Entra + O365 Portion:"
  Add-Content -Path $LogFile -Value "$($DateTime): MS Entra + O365 Portion:"
  
  # Populate user
  $TempMgUser = Get-MgUser -UserId $TempADUser.UserPrincipalName

  # Make changes to user
  Revoke-MgUserSignInSession -UserId $TempMgUser.Id
  $MgAcctParams = @{ accountEnabled = $false}
  Update-MgUser -UserID $TempMgUser.Id -BodyParameter $MgAcctParams
  
  # Query user groups MemberOf and if they are NOT mail enabled, remove them from it
  $DateTime = Get-Date -Format "MM/dd/yyyy HH:mm"
  $UserGroupsMemberOf = Get-MgUserMemberOf -UserId $TempMgUser.Id
  foreach ($Group in $UserGroupsMemberOf) {
    $TempGroup = Get-MgGroup -GroupId $Group.Id
    if (($TempGroup).MailEnabled -eq $false) {
      Remove-MgGroupMemberDirectoryObjectByRef -GroupId $Group.Id -DirectoryObjectId $TempMgUser.Id
      Write-Output "$($DateTime): Removed $($User) from Mg group $($Group.Id) with DisplayName $($TempGroup.DisplayName)"
      Add-Content -Path $LogFile -Value "$($DateTime): Removed $($User) from Mg group $($Group.Id) with DisplayName $($TempGroup.DisplayName)"
    } else {}
  }

  # Add a space
  Write-Output ""
  Add-Content -Path $LogFile -Value ""  

  # Start Exchange Portion
  Write-Output "$($DateTime): ExchangeOnline Portion:"
  Add-Content -Path $LogFile -Value "$($DateTime): ExchangeOnline Portion:"
  $ExchUser = Get-User -Identity $TempADUser.UserPrincipalName

  # This removes the users devices that are associated with their exchange online mailbox
  $ExchUserMobileDevices = Get-MobileDevice -Mailbox $ExchUser  
  foreach ($MobileDevice in $ExchUserMobileDevices) {
    Remove-MobileDevice -Identity $MobileDevice -Confirm:$false
    Write-Output "$($DateTime): Removed device $($MobileDevice.DeviceId) with OS $($MobileDevice.DeviceOS)"
    Add-Content -Path $LogFile -Value "$($DateTime): Removed device $($MobileDevice.DeviceId) with OS $($MobileDevice.DeviceOS)"
  }

  # Remove user from email distribution groups + print output to log
  # This section requires both Ms Graph and Exchange Online PS modules
  # Requery the groups to discard the removed groups still present in the old object from previous call
  $UserGroupsMemberOf = Get-MgUserMemberOf -UserID $TempMgUser.Id
  foreach ($Group in $UserGroupsMemberOf){
    $TempGroup = Get-MgGroup -GroupId $Group.Id
    if ( ($TempGroup).MailEnabled -eq $true){
      Remove-DistributionGroupMember -Identity $Group.Id -Member $TempMgUser.Id -Confirm:$false
      Write-Output "$($DateTime): Removed $($User) from Exchange group $($TempGroup.Id) with DisplayName $($TempGroup.DisplayName)"
      Add-Content -Path $LogFile -Value "$($DateTime): Removed $($User) from Exchange group $($TempGroup.Id) with DisplayName $($TempGroup.DisplayName)"
    }
  }

  # Convert mailbox to shared mailbox
  # Need to set the displayName attribute separately from the command to convert to a shared mailbox
  Set-ADUser -Identity $TempUserSamAcctName -DisplayName ("(shared) " + $($TempADUser).DisplayName)
  # Refresh the object so that it pulls the newly set display name
  $TempADUser = Get-ADUser -Identity $TempUserSamAcctName -Properties DisplayName
  Write-Output "$($DateTime): $($User) DisplayName is $($TempADUser.DisplayName)"
  Add-Content -Path $LogFile -Value "$($DateTime): $($User) DisplayName is $($TempADUser.DisplayName)"

  Set-Mailbox -Identity $TempADUser.UserPrincipalName -Type Shared

  # Query all O365 licenses and remove them; write each to log and console
  $TempUserLicenses = Get-MgUserLicenseDetail -UserId $TempADUser.UserPrincipalName
  foreach ($license in $TempUserLicenses) {
    Set-MgUserLicense -UserId $TempMgUser.Id -AddLicenses @() -RemoveLicenses @($license.SkuId)
    Write-Output "$($DateTime): Removed license $($license.SkuId) from user $($user)"
    Add-Content -Path $LogFile -Value "$($DateTime): Removed license $($license.SkuId) from user $($user)"
  }

  # These actions are optional in the disable user project scope, and can be explored and developed in future
  # versions of this script. Basically add some input params at top and use them to make calls to update values here!
  
  # *Optional* Provide access to shared mailbox
  # Add-MailboxPermission -Identity $ADUser.UserPrincipalName -User <TargetOtherUserPrincipalName> -AccessRights FullAccess -InheritanceType All
  
  # Forward email
  # Set-Mailbox -Identity $ADUser.UserPrincipalName -DeliverToMailboxAndForward $true -ForwardingAddress "<InternalUserUPN@example.com>"

# Add a space
  Write-Output ""
  Add-Content -Path $LogFile -Value ""
}

# Synchronize the changes to the cloud
Start-ADSyncSyncCycle -PolicyType Delta

# Exit the script

Exit 0
