cd C:\Users\<username>\Downloads
set-executionpolicy unrestricted -force

#get tenant ID, domains, etc

Invoke-AADIntReconAsOutsider | out-file BusinessName_AzureEnum_Date.txt

#download more tools

pip install prowler

Invoke-WebRequest -Uri https://aka.ms/installazurecliwindowsx64 -OutFile azurecli.msi

.\azurecli.msi

Invoke-WebRequest -Uri https://github.com/BloodHoundAD/AzureHound/releases/download/v1.2.4/azurehound-windows-amd64.zip -OutFile azurehound-windows-amd64.zip

expand-archive .\azurehound-windows-amd64.zip

#external cloud domain / blob enumeration

Invoke-WebRequest -Uri https://github.com/NetSPI/MicroBurst/archive/refs/heads/master.zip -OutFile Micro.zip

expand-archive .\Micro.zip

cd .\Micro

Import-Module .\MicroBurst.psm1

Install-Module AADInternals

Invoke-WebRequest -Uri https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip -OutFile subdomain.zip

expand-archive .\subdomain.zip

#for the below, before enumerating publicly available folders, check with business partner for blob validity

Get-Content .\Misc\permutations.txt >> .\subdomain\Discovery\DNS\subdomains-top1million-5000.txt

invoke-enumerateazureblobs -base <#<different iterations of business partner base domain name> #> -permutations .\subdomain\Discovery\DNS\subdomains-top1million-5000.txt | cut -d ' ' -f 3 > validnames.txt

#after verification, enumerate for public files using valid blob name txt file. Append previous permutations file to this new file.

Get-Content .\Misc\permutations.txt >> .\validnames.txt

Invoke-WebRequest -Uri https://github.com/3ndG4me/KaliLists/archive/refs/heads/master.zip -OutFile wordlists.zip

expand-archive .\wordlists.zip

#save output, process as finding, severity level based on information contained in public archives
invoke-enumerateazureblobs -base <#<different iterations of business partner base domain name> #> -permutations .\validnames.txt -folders .\wordlists\dirbuster\directory-list-2.3-medium.txt


## more information on prowler // azurehound (using 1.X version)


<#
Dealing with Multi-Factor Auth and Conditional Access Policies:

If a user has MFA or CAP restrictions applied to them, you will not be able to 
authenticate with just a username and password with AzureHound. 
In this situation, you can acquire a refresh token for the user and supply the refresh token to AzureHound.

The most straight-forward way to accomplish this is to use the device code flow. 
In this example I will show you how to perform this flow using PowerShell, but this example can 
be very easily ported to any language, as we are simply making calls to Azure APIs.

Open a PowerShell window on any system and paste the following:
#>

$body = @{
    "client_id" =     "1950a258-227b-4e31-a9cf-717495945fc2"
    "resource" =      "https://graph.microsoft.com"
}
$UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
$Headers=@{}
$Headers["User-Agent"] = $UserAgent
$authResponse = Invoke-RestMethod `
    -UseBasicParsing `
    -Method Post `
    -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" `
    -Headers $Headers `
    -Body $body
$authResponse


<#
The output will contain a `user_code` and `device_code`. Now, open a browser where your Entra ID user either 
already logged on or can log on to Azure. In this browser, navigate to https://microsoft.com/devicelogin

Enter the code you generated from the above PowerShell script. Follow the steps in the browser to authenticate as 
the Entra ID user and approve the device code flow request. When done, the browser page should display a message 
similar to “You have signed in to the Microsoft Azure PowerShell application on your device. You may now close this window.”

Now go back to your original PowerShell window and paste this:
#>
$body=@{
    "client_id" =  "1950a258-227b-4e31-a9cf-717495945fc2"
    "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
    "code" =       $authResponse.device_code
}
$Tokens = Invoke-RestMethod `
    -UseBasicParsing `
    -Method Post `
    -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" `
    -Headers $Headers `
    -Body $body
$Tokens

<#
The output will include several tokens including a `refresh_token`. It will start with characters similar to “0.ARwA6Wg…”. 
Now you are ready to run AzureHound! Take the refresh token and supply it to AzureHound using the `-r` switch:
#>

./azurehound.exe -r "0.ASwACdQ-Sh...-FGHJ-ASDFhgjkDFGH" list --tenant "domainnamecloud.com" -o BusinessName_date.json

#final step = upload json into blood hound
#in kali - spin up neo4j w/ command "sudo neo4j console"
#next run "bloodhound" ... drag/drop json into bloodhound


#log into cloud environment with provided cloud credentials

az login

#if there are no subscriptions available, refer to prowler documentation and send to 
#business partner to ensure you have the correct read permissions (NOTE: with the highest level of
#permissions, you will have more findings. Not all findings will be true positives

#rerun az login, select the correct subscription you wish to audit

cd C:\Users\<username>

prowler azure --az-cli-auth

#move output files to share folder 