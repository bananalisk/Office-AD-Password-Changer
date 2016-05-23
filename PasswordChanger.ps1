$ErrorActionPreference = 'Stop'

try
{
    $suffixStart = "FX"
    $newPw = ""

    $policy = iex 'Get-ADDefaultDomainPasswordPolicy'
    $policyRememberedPasswords =  $policy.PasswordHistoryCount
    $policyMininumPasswordAge = $policy.MinPasswordAge
    $policyMinimumPasswordLength = $policy.MinPasswordLength

    $numberOfIterations = $policyRememberedPasswords + 1;
    if($policyMininumPasswordAge -eq 0)
    {
        $currentPassword = Read-Host 'Current pw?' -AsSecureString
        $currentPassword2 = Read-Host 'Repeat current pw' -AsSecureString
        $tmp1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($currentPassword))
        $tmp2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($currentPassword2))
        if($tmp1 -eq $tmp2)
        {
            $DesiredPassword = Read-Host 'New pw?' -AsSecureString
            $DesiredPassword2 = Read-Host 'Repeat new pw' -AsSecureString
            $tmp1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DesiredPassword))
            $tmp2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DesiredPassword2))
            if($tmp1 -eq $tmp2)
            {
                if($tmp1.Length -ge $policyMinimumPasswordLength)
                {
                    $currentPasswordPainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($currentPassword))
                    $lastPwUsed = $currentPassword
                    for($i=1; $i -le $numberOfIterations; $i++)
                    {
                        $lastPwUsedPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($lastPwUsed))
                        $newPw = (ConvertTo-SecureString -String "Password$suffixStart$i" -AsPlainText -Force)
                        $newPwPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPw))
                
                        Set-AdAccountPassword -Identity $env:USERNAME -Server $env:USERDOMAIN -OldPassword $lastPwUsed -NewPassword $newPw
                
                        if($currentPasswordPainText -eq $lastPwUsedPlainText)
                        {
                            $newPwPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPw))
                            Write-Host "Changed password from [HIDDEN_OLD] to $newPwPlainText"
                        }
                        else
                        {
                            $tmpLast = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($lastPwUsed))
                            Write-Host "Changed password from $tmpLast to $newPwPlainText"
                            $lastPwUsed = $newPw
                        }
                        $lastPwUsed = $newPw
                    }
                    Write-Host 'Now setting new password...'
                    $lastPwUsedPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($lastPwUsed))
                    Set-AdAccountPassword -Identity $env:USERNAME -Server $env:USERDOMAIN -OldPassword $lastPwUsed -NewPassword $DesiredPassword
                    Write-Host "Changed password from $lastPwUsedPlainText to [HIDDEN_NEW]"
                    Write-Host 'Success!'
                    pause
                }
                else
                {
                    Write-Host "Sorry, the password policy requires passwords to be at least $policyMinimumPasswordLength characters."
                }                
            }
            else
            {
                Write-Host 'New Passwords did not match. Nothing was done.'
            }
        }
        else
        {
            Write-Host 'Current Passwords did not match. Nothing was done.'
        }
    }
    else
    {
        Write-Host "Sorry, the password policy wont allow us to change Passwords more than once every $policyMininumPasswordAge days. Nothing was done."
    }
}
catch
{
    Write-Host 'Error detected, stopped running script.'
}