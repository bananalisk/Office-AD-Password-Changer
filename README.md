# Office-AD-Password-Changer

PowerShell Script workaround for Active Directories that force password changes every X days.

Requirements: Remote Server Administration Tools - Download URL for Windows 8.1: https://www.microsoft.com/en-us/download/details.aspx?id=39296


Description:

This is a Windows PowerShell Script that will try to iterate through X amount of filler passwords and then set your desiered password, ultimately letting you keep the same password.

If the AD is configured to not allow multiple password changes per day the script will not run.

You can change the $suffix variable to fit your AD password requirements.