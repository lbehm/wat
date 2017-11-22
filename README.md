# WAT - Windows ACME Tool

[![Join the chat at https://gitter.im/wat-ps/Lobby](https://badges.gitter.im/wat-ps/Lobby.svg)](https://gitter.im/wat-ps/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[wat.ps1](https://github.com/lbehm/wat/blob/master/wat.ps1) contains all the magic it needs to give you just what you want: free SSL/TLS Certificates for all your servers

In other terms it is a
* compact ACME client in just a single file
* running on Windows (tested on Server 2012R2, Win10v1703)
* that generates and renews RSA and ECDsa Certificates
* signed by an ACME-server like [Let'sEncrypt](https://letsencrypt.org/)
* implemented as a single powershell script
* exporting the Certificates in various formats (Pfx, Pkcs12, Pem)
* compatible with every decent web server
* needs just a single line of code for setup and execution
* doesn't fiddle with your holy web server configuration (only takes input and outputs Certificates)
* runs out of the box without any additional requirements (no extra module directory / dll / c# code / Bouncy Castle / openssl)
* uses only Windows components
* in-place Certificate renewel doesn't need config changes of IIS bindings
* uses Windows CNG API for handling private keys
* just what a serious network admin wants
* is more or less readable
* a useful way to show off some powershell skills

## Requirements
##### Windows 10 / Windows Server 2016
You are good to go!
##### Windows 7 / Windows Server 2008 R2
Make sure your system is up to date and has at least PowerShell 4 installed!
1. Find your PowerShell Version by executing `Get-Host` in a PowerShell Window.
2. If the Version shows 4.0 or greater everything is fine and you should continue in the [examples section](#examples).
3. If not (2.0 or 3.0) you should install *Windows Management Framework 4.0*. PowerShell 4.0 is part of it.
   1. Go to the [Windows Download page](https://www.microsoft.com/en-us/download/details.aspx?id=40855)
   2. Select your language, click Download
   3. Select `Windows6.1-KB2819745-x64-MultiPkg.msu` (on 64bit) or `Windows6.1-KB2819745-x86-MultiPkg.msu` (on 32bit Windows)
   4. Install the download.
   5. Search and Install Windows Updates!

Note: it isn't possible to export private keys of EC Certificates into Pem format on Windows 7 or Server 2012 R2

## Acknowledgement
At this point I want to thank @lukas2511 for his fantastic work in [dehydrated](https://github.com/lukas2511/dehydrated):bangbang:\
Without his inspirational masterpiece there would be no wat.ps1\
If you looking for a trustworthy slim acme client for linux/unix check out his works!

## Syntax
```
.\wat.ps1 [-Domains] <String[]> [-Email <String[]>] [-ResetRegistration] [-RenewRegistration] [-RenewCertificate] [-RecreateCertificate] [-RenewPrivateKey] [-OcspMustStaple] [-CA <Uri>] [-AcceptTerms] [-Staging] [-KeyAlgo [Rsa|ECDSA_P256|ECDSA_P384]] [-KeySize [2048|4096]] [-RenewDays <Int32>] [-ChallengeType [http-01|dns-01|tls-sni-01]] [-ACMEVersion [acme1-boulder|acme2-boulder|acme1]] [-BaseDir <DirectoryInfo>] [-CertDir <DirectoryInfo>] [-AccountDir <DirectoryInfo>] [-WellKnown <DirectoryInfo>] [-LockFile <FileInfo>] [-NoLock] [-ExportPassword <SecureString>] [-ExportPfx] [-ExportPkcs12] [-ExportCert] [-ExportPem] [-ExportPemCert] [-ExportPemKey] [-ExportIssuerPem] [-ExportPemEncoding [ASCII|UTF8|UTF32|Unicode|...]] [-onChallenge <ScriptBlock>] [-onChallengeCleanup <ScriptBlock>] [-NoDnsTest] [-InternalAccountIdentifier <String>] [-AccountKeyAlgo [Rsa|ECDSA_P256|ECDSA_P384]] [-AutoFix] [-Context {CurrentUser | LocalMachine}] [<CommonParameters>]
```
The script can take an array of domain names from piped input. Please have a look [at the examples](#examples).

For detailed informations, just go ahead:
```ps
Get-Help .\wat.ps1 -Detailed
Get-Help .\wat.ps1 -Full
```

## Parameter
### Mandatory Parameter
###### -Domains `<String[]>`
Specify a list of domain names.
The first is used as CommonName of your certificate.
Every domain name is added as SubjectAlternateName (SAN).
The Domains parameter can also be provided as piped input. Please be sure to define arrays of string arrays in this case.
### Recomended Parameter
###### -Email `<String[]>`
E-mail addresses that are linked to the account
###### -AcceptTerms
Accept CAs terms of service
###### -Staging
Using the staging environment of Let'sEncrypt if `-CA` isn't specified
###### -Context `[CurrentUser|LocalMachine]`
The place to save the certificate and keys
###### -WellKnown `<DirectoryInfo>`
Output directory for challenge-tokens to be served by webserver or deployed in `-onChallenge`
###### -ChallengeType `[http-01|dns-01|tls-sni-01]`
Which challenge should be used? (default: `http-01`)
###### -AutoFix
Try to fix common problems automatically.\
This includes:
- Creating new account with existing configuration if AccountKey is missing (this overwrites account id/data)
- Creating or updating registration without E-mail addresses if addresses aren't valid anymore (You will not receive notifications!)
###### -onChallenge `<ScriptBlock>`
Script to be invoked with challenge token receiving the following parameter:
    Domain                         The domain name you want to verify
    Token / FQDN                   The file name for http-01 or domain name for dns-01 and tls-sni-01 challenges
    KeyAuthorization / Certificate The value you have to place in the file or dns TXT record or the Certificate for tls-sni-01 challenges
###### -onChallengeCleanup `<ScriptBlock>`
Script to be invoked after completing the challenge receiving the same parameter as -onChallenge with the addition of the response status 'valid' or 'invalid' as 4th parameter
### Advanced Parameter
###### -ResetRegistration
Discards the ACME account key and performs a complete new account registration
###### -RenewRegistration
Force update of the account information (maybe you fiddled with the `account.json` file)
###### -RenewCertificate
Force renew of certificate even if it is longer valid than value in RenewDays
###### -RecreateCertificate
Create complete new private key and certificate
###### -RenewPrivateKey
Regenerate private keys instead of just signing new certificates on renewal
###### -OcspMustStaple
Adding CSR feature indicating that OCSP stapling should be mandatory
###### -CA `<Uri>`
Path to certificate authority (default: https://acme-v01.api.letsencrypt.org/directory)
###### -AccountKeyAlgo `[Rsa|ECDSA_P256|ECDSA_P384]`
Which algorithm should be used for the ACME account key?
###### -KeyAlgo `[Rsa|ECDSA_P256|ECDSA_P384]`
Which algorithm should be used?
###### -KeySize `[2048|4096]`
Size of rsa keys (default: `4096`)\
Possible values are between 2048 and 4096 and a multiple of 64 (e.g. 3072 is possible)
###### -RenewDays `<Int32>`
Minimum days before expiration to automatically renew certificate (default: `30`)
###### -ACMEVersion `[acme1-boulder|acme2-boulder|acme1]`
Currently only acme1-boulder dialect is tested
###### -BaseDir `<DirectoryInfo>`
Base directory for account config and generated certificates
###### -CertDir `<DirectoryInfo>`
Output directory for generated certificates
###### -AccountDir `<DirectoryInfo>`
Directory for account config and registration information
###### -LockFile `<FileInfo>`
Lockfile location, to prevent concurrent access
###### -NoLock
Do not use lockfile (potentially dangerous!)
###### -NoDnsTest
Don't verify the DNS record after executing onChallenge (applies only to dns-01 challenges)
###### -ExportPassword `<SecureString>`
Password to encrypt the exported certificate files (only applies to `-ExportPfx` and `-ExportPkcs12`)
###### -ExportPfx
Export the certificate in PFX format (please use `-ExportPassword`)
###### -ExportPkcs12
Export the certificate in Pkcs12 format (please use `-ExportPassword`)
###### -ExportCert
Export the certificate as a `.crt` public certificate file (Only public certificate without private key)
###### -ExportPem
Export the certificate with private key in Base64 encoded PEM format (Warning: private key is NOT encrypted)
###### -ExportPemCert
Export the certificate without private key in Base64 encoded PEM format
###### -ExportPemKey
Export the private key in Base64 encoded PEM format (Warning: private key is NOT encrypted)
###### -ExportIssuerPem
Export the certificate of the Issuer (e.g. Let'sEncrypt) in Base64 encoded PEM format
###### -ExportPemEncoding `[ASCII|UTF8|UTF32|Unicode|...]`
###### -InternalAccountIdentifier `<String>`
Internal identifier of the ACME account

## Examples
```ps
.\wat.ps1 example.com
```
Basic usage for issuing a certificate for `domain example.com`

```ps
.\wat.ps1 example.com -ContactEmail me@example.com
```
Updating the registration with given email address

```ps
.\wat.ps1 -Domain "example.com" -WellKnown D:\htdocs\.well-known\acme-challenge
```
Placing the verification tokens in the specified directory

```ps
.\wat.ps1 -Domain ("example.com", "www.example.com") -Staging
```
Including `example.com` and `www.example.com` in the SubjectAlternateName attribute of the certificate\
Using the Let'sEncrypt staging environment for testing purpose

```ps
$certs = (("example.com", "www.example.com"), ("jon.doe.xy")) | .\wat.ps1
```
Working a set of 2 certificates.\
__Certificate 1:__\
Name: `example.com`\
Domains: `example.com`, `www.example.com`\
__Certificate 2:__\
Name: `jon.doe.xy`\
Domains: `jon.doe.xy`

```ps
C:\Scripts\wat\wat.ps1 -Domains "example.com" -WellKnown C:\inetpub\well-known\acme-challenge -AcceptTerms -AutoFix -Context LocalMachine
```
This is my entire config (as scheduled task) to update the SMTP Certificate in one of my ExchangeServers.\
After the initial set up and binding of the Certificat to the SMTP service (e.g. in the ECP GUI), I don't have to update any ExchangeServer configuration every time the certificate is renewed.\
That's what I call In-Place-Renewal - I didn't find anything on the web to this mechanism.

```ps
.\wat.ps1 -Domains "example.com" -ChallengeType tls-sni-01 -Context LocalMachine -Staging -onChallenge {
    Param([String] $Domain, [String] $FQDN, [Security.Cryptography.X509Certificates.X509Certificate2] $Cert)
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    if (!(Get-Module WebAdministration) ) { throw "Couldn't load WebAdministration module" }
    # Remove old entries
    Get-WebBinding -Protocol https -Port 443 -HostHeader $FQDN -IPAddress '*' | Remove-WebBinding
    Get-Item "IIS:\SslBindings\*!443!$($FQDN)" -ErrorAction SilentlyContinue | Remove-Item
    # Create new bindings
    New-WebBinding -IPAddress "*" -Port 443 -HostHeader $FQDN -Protocol https -SslFlags 1 -Name "Default Web Site"
    New-Item "IIS:\SslBindings\*!443!$($FQDN)" -Thumbprint $($Cert.Thumbprint) -SSLFlags 1 | Out-Null
} -onChallengeCleanup {
    Param([String] $Domain, [String] $FQDN, [Security.Cryptography.X509Certificates.X509Certificate2] $Cert)
    # Remove bindings
    Get-WebBinding -Protocol https -Port 443 -HostHeader $FQDN -IPAddress '*' | Remove-WebBinding
    Get-Item "IIS:\SslBindings\*!443!$($FQDN)" -ErrorAction SilentlyContinue | Remove-Item
}
```
This is a working implementation of tls-sni-01 challenges in IIS. You may have to change it to match the name of your default web site.
As in the example above, you have to set up a binding of the new Certificat in the IIS GUI.
