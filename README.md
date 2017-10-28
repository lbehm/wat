# WAT - That Windows ACME Tool

[![Join the chat at https://gitter.im/wat-ps/Lobby](https://badges.gitter.im/wat-ps/Lobby.svg)](https://gitter.im/wat-ps/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

wat.ps1 contains all the magic it needs to give you just what you want: free SSL/TLS Certificates for all your servers

In other terms it is an
* ACME client
* running on Windows (tested on Server 2012R2, Win10v1703)
* that generates and renews RSA and ECDsa Certificates
* signed by an ACME-server like [Let'sEncrypt](https://letsencrypt.org/)
* implemented as a single powershell script
* exporting the Certificates in various formats (Pfx, Pkcs12, Pem)
* compatible with every decent web server
* needs just a single line of code to execute
* doesn't fiddle with your holy web server configuration (only take input and produce Certificates)
* runs out of the box without any additional requirements (no extra module directory / dll / c# code / buncy castle / openssl)
* uses only Windows components
* in-place Certificate renewel doesn't need config changes of IIS bindings
* uses Windows CNG API for handling private keys
* just what a serious network admin wants
* is more or less readable
* a useful way to show off some powershell skills

# Acknowledgement
At this point I want to thank @lukas2511 for his fantastic work in [dehydrated](https://github.com/lukas2511/dehydrated):bangbang:\
Without his inspirational masterpiece there would be no wat.ps1
If you looking for a trustworthy slim acme client for linux/unix check out his works!

## Syntax
```
.\wat.ps1 [-Domains] <String[]> [-ContactEmail <String>] [-Contact <String[]>] [-ResetRegistration] [-RenewRegistration] [-RenewCertificate] [-RecreateCertificate] [-RenewPrivateKey] [-OcspMustStaple] [-CA <Uri>] [-AcceptTerms] [-Staging] [-KeyAlgo <CngAlgorithm>] [-KeySize <Int32>] [-RenewDays <Int32>] [-ChallengeType <String>] [-ACMEVersion <String>] [-BaseDir <DirectoryInfo>] [-CertDir <DirectoryInfo>] [-AccountDir <DirectoryInfo>] [-WellKnown <DirectoryInfo>] [-LockFile <FileInfo>] [-NoLock] [-ExportPassword <SecureString>] [-ExportPfx] [-ExportPkcs12] [-ExportCert] [-ExportPem] [-ExportPemCert] [-ExportPemKey] [-ExportIssuerPem] [-ExportPemEncoding <String>] [-onChallenge <ScriptBlock>] [-InternalAccountIdentifier <String>] [-Context {CurrentUser | LocalMachine}] [<CommonParameters>]
```

For detailed informations, just go ahead:
```ps
Get-Help .\wat.ps1 -Detailed
Get-Help .\wat.ps1 -Full
```

## Parameter
```
Domains <String[]>
	Specify a list of domain names. The first is used as CommonName of your certificate

ContactEmail <String>
	E-Mail to use during the registration (alias for -Contact ("mailto:<ContactEmail>"))

Contact <String[]>
	Contact information to use during the registration (example: "mailto:me@example.com")

ResetRegistration [<SwitchParameter>]
	Discards the ACME account key and performs a complete new account registration

RenewRegistration [<SwitchParameter>]
	Force update of the account information (maybe you fiddled with the account.json file)

RenewCertificate [<SwitchParameter>]
	Force renew of certificate even if it is longer valid than value in RenewDays

RecreateCertificate [<SwitchParameter>]
	Create complete new private key and certificate (useful when changing -KeyAlgo)

RenewPrivateKey [<SwitchParameter>]
	Regenerate private keys instead of just signing new certificates on renewal

OcspMustStaple [<SwitchParameter>]
	Option to add CSR-flag indicating OCSP stapling to be mandatory

CA <Uri>
	Path to certificate authority (default: https://acme-v01.api.letsencrypt.org/directory)

AcceptTerms [<SwitchParameter>]
	Accept CAs terms of service

Staging [<SwitchParameter>]
	Using the staging environment of Let'sEncrypt if -CA isn't specified

KeyAlgo <CngAlgorithm>
	Which public key algorithm should be used? (use with -RecreateCertificate)

KeySize <Int32>
	Keysize for private rsa keys (default: 4096)

RenewDays <Int32>
	Minimum days before expiration to automatically renew certificate (default: 30)

ChallengeType <String>
	Which challenge should be used? (default: http-01)

ACMEVersion <String>
	Currently only acme1-boulder dialect is tested

BaseDir <DirectoryInfo>
	Base directory for account config and generated certificates

CertDir <DirectoryInfo>
	Output directory for generated certificates

AccountDir <DirectoryInfo>
	Directory for account config and registration information

WellKnown <DirectoryInfo>
	Output directory for challenge-tokens to be served by webserver or deployed in -onChallenge

LockFile <FileInfo>
	Lockfile location, to prevent concurrent access

NoLock [<SwitchParameter>]
	Don't use lockfile (potentially dangerous!)

ExportPassword <SecureString>
	Password to encrypt the exported certificate files (only applies to -ExportPfx -ExportPkcs12)

ExportPfx [<SwitchParameter>]
	Export the certificate in PFX format (please use -ExportPassword)

ExportPkcs12 [<SwitchParameter>]
	Export the certificate in Pkcs12 format (please use -ExportPassword)

ExportCert [<SwitchParameter>]
	Export the certificate as a .crt public certificate file (Only public certificate without private key)

ExportPem [<SwitchParameter>]
	Export the certificate with private key in Base64 encoded PEM format (Warning: private key is NOT encrypted)

ExportPemCert [<SwitchParameter>]
	Export the certificate without private key in Base64 encoded PEM format

ExportPemKey [<SwitchParameter>]
	Export the private key in Base64 encoded PEM format (Warning: private key is NOT encrypted)

ExportIssuerPem [<SwitchParameter>]

ExportPemEncoding <String>

onChallenge <ScriptBlock>
	Script to be invoked with challenge token

InternalAccountIdentifier <String>
	Internal identifier of the ACME account

Context
	The place to save the certificate and keys
```

## Examples
```ps
.\wat.ps1 example.com
```
Basic usage for issuing a certificate for domain example.com

```ps
.\wat.ps1 example.com -ContactEmail me@example.com
```
Updating the registration with given email address

```ps
.\wat.ps1 -Domain "example.com" -WellKnown D:\inetpub\.well-known\acme-challenge
```
Placing the verification tokens in the specified directory

```ps
.\wat.ps1 -Domain ("example.com", "www.example.com") -Staging
```
Including example.com and www.example.com in the SubjectAlternateName attribute of the certificate\
Using the Let'sEncrypt staging environment for testing purpose

```ps
$certs = (("example.com", "www.example.com"), ("jon.doe.xy")) | .\wat.ps1
```
Working a set of 2 certificates.\
__Certificate 1:__\
Name: example.com\
Domains: example.com, www.example.com \
__Certificate 2:__\
Name: jon.doe.xy\
Domains: jon.doe.xy
