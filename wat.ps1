<#
.SYNOPSIS
WAT - Windows ACME Tool

.DESCRIPTION
This is a client for signing certificates with an ACME-server implemented as a single powershell script.
This tool has no additional requirements.
This work is inspired by the commonly used linux/unix script dehydrated.

If you are serious about the safty of the crypto stuff, please have a look at the Create-Certificate function.

This work is published under:
MIT License

Copyright (c) 2017 Ludwig Behm

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

.INPUTS
System.String[] $Domains
Specify a list of domain names. The first is used as CommonName of your certificate and the following are used in the SubjectAlternateName attribute
You can query for multible certificates with: (("example.com", "www.example.com"), ("jon.doe.xy")) | .\wat.ps1

.OUTPUTS
System.Security.Cryptography.X509Certificates.X509Certificate2

.EXAMPLE
.\wat.ps1 example.com
Basic usage for issuing a certificate for domain example.com

.EXAMPLE
.\wat.ps1 example.com -ContactEmail me@example.com
Updating the registration with given email address

.EXAMPLE
.\wat.ps1 -Domain "example.com" -WellKnown D:\inetpub\.well-known\acme-challenge
Placing the verification tokens in the specified directory

.EXAMPLE
.\wat.ps1 -Domain ("example.com", "www.example.com") -Staging
Including example.com and www.example.com in the SubjectAlternateName attribute of the certificate
Using the Let'sEncrypt staging environment for testing purpose

.EXAMPLE
$certs = (("example.com", "www.example.com"), ("jon.doe.xy")) | .\wat.ps1
Working a set of 2 certificates.
Certificate 1:
Name: example.com
Domains: example.com, www.example.com
Certificate 2:
Name: jon.doe.xy
Domains: jon.doe.xy

.EXAMPLE
C:\Scripts\wat\wat.ps1 -Domains "example.com" -WellKnown C:\inetpub\well-known\acme-challenge -AcceptTerms -AutoFix -Context LocalMachine
This is my entire config (as scheduled task) to update the SMTP Certificate in one of my ExchangeServers.
After the initial set up and binding of the Certificat to the SMTP service (e.g. in the ECP GUI), I don't have to update any ExchangeServer configuration every time the certificate is renewed.
That's what I call In-Place-Renewal - I didn't find anything on the web to this mechanism.

.NOTES
This script uses only Windows components

For the ACME account a RSACng-Key is used and stored in the system
For the use in certificates, private keys are generated in the Create-Certificate function

#>
Param (
    # Specify a list of domain names.
    # The first is used as CommonName of your certificate.
    # Every domain name is added as SubjectAlternateName (SAN).
    # The Domains parameter can also be provided as piped input. Please be sure to define arrays of string arrays in this case.
    [Parameter(
        Position = 0,
        Mandatory = $true,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Specify a list of domain names. The first is used as CommonName of your certificate."
    )]
    [String[]] $Domains,

    # E-Mail to use during the registration (alias for -Contact ("mailto:<ContactEmail>"))
    [String] $ContactEmail,

    # Contact information to use during the registration (example: "mailto:me@example.com")
    [Parameter(DontShow = $true)]
    [String[]] $Contact,
    
    # Discards the ACME account key and performs a complete new account registration
    [Parameter(DontShow = $true)]
    [Switch] $ResetRegistration,
    
    # Force update of the account information (maybe you fiddled with the account.json file)
    [Parameter(DontShow = $true)]
    [Switch] $RenewRegistration,
    
    # Force renew of certificate even if it is longer valid than value in RenewDays
    [Switch] $RenewCertificate,
    
    # Create complete new private key and certificate
    [Parameter(DontShow = $true)]
    [Switch] $RecreateCertificate,
    
    # Regenerate private keys instead of just signing new certificates on renewal
    [Parameter(DontShow = $true)]
    [Switch] $RenewPrivateKey,
    
    # Adding CSR feature indicating that OCSP stapling should be mandatory
    [Switch] $OcspMustStaple,

    # Path to certificate authority (default: https://acme-v01.api.letsencrypt.org/directory)
    [Parameter(DontShow = $true)]
    [uri] $CA,

    # Accept CAs terms of service
    [Switch] $AcceptTerms,
    
    # Using the staging environment of Let'sEncrypt if -CA isn't specified
    [Switch] $Staging,
    
    # Which algorithm should be used?
    [ValidateSet("Rsa", "ECDSA_P256", "ECDSA_P384")]
    [System.Security.Cryptography.CngAlgorithm] $KeyAlgo = [System.Security.Cryptography.CngAlgorithm]::Rsa,
    
    # Size of rsa keys (default: 4096)
    # Possible values are between 2048 and 4096 and a multiple of 64 (e.g. 3072 is possible)
    [ValidateScript({ ($_%64) -eq 0 -and $_ -ge 2048 -and $_ -le 4096 })]
    [int] $KeySize = 4096,
    
    # Minimum days before expiration to automatically renew certificate (default: 30)
    [int] $RenewDays = 30,

    # Which challenge should be used? (default: http-01)
    [ValidateSet("http-01", "dns-01", "tls-sni-01")]
    [String] $ChallengeType = "http-01",

    # Currently only acme1-boulder dialect is tested
    [Parameter(DontShow = $true)]
    [ValidateSet("acme1-boulder", "acme2-boulder", "acme1")]
    [String] $ACMEVersion = "acme1-boulder",
    
    # Base directory for account config and generated certificates
    [Parameter(DontShow = $true)]
    [System.IO.DirectoryInfo] $BaseDir = (Split-Path -Parent $MyInvocation.MyCommand.Definition),
    
    # Output directory for generated certificates
    [Parameter(DontShow = $true)]
    [System.IO.DirectoryInfo] $CertDir = "$BaseDir\Certs",
    
    # Directory for account config and registration information
    [Parameter(DontShow = $true)]
    [System.IO.DirectoryInfo] $AccountDir = "$BaseDir\Accounts",
    
    # Output directory for challenge-tokens to be served by webserver or deployed in -onChallenge
    [System.IO.DirectoryInfo] $WellKnown = "C:\inetpub\wwwroot\.well-known\acme-challenge",
    
    # Lockfile location, to prevent concurrent access
    [Parameter(DontShow = $true)]
    [System.IO.FileInfo] $LockFile = "$BaseDir\lock",
    
    # Don't use lockfile (potentially dangerous!)
    [Switch] $NoLock,

    # Password to encrypt the exported certificate files (only applies to -ExportPfx and -ExportPkcs12)
    [securestring] $ExportPassword = (new-object System.Security.SecureString),

    # Export the certificate in PFX format (please use -ExportPassword)
    [Switch] $ExportPfx,

    # Export the certificate in Pkcs12 format (please use -ExportPassword)
    [Switch] $ExportPkcs12,

    # Export the certificate as a .crt public certificate file (Only public certificate without private key)
    [Switch] $ExportCert,
    
    # Export the certificate with private key in Base64 encoded PEM format (Warning: private key is NOT encrypted)
    [Switch] $ExportPem,
    
    # Export the certificate without private key in Base64 encoded PEM format
    [Switch] $ExportPemCert,
    
    # Export the private key in Base64 encoded PEM format (Warning: private key is NOT encrypted)
    [Switch] $ExportPemKey,
    
    # Export the certificate of the Issuer (e.g. Let'sEncrypt) in Base64 encoded PEM format
    [Switch] $ExportIssuerPem,

    [ValidateSet("ASCII", "UTF8", "UTF32", "UTF7", "BigEndianUnicode", "Default", "OEM", "Unicode")]
    [string] $ExportPemEncoding = "ASCII",

    # Script to be invoked with challenge token receiving the following parameter:
    # Domain - The domain name you want to verify
    # Token / FQDN - The file name for http-01 or domain name for dns-01 and tls-sni-01 challenges
    # KeyAuthorization / Certificate - The value you have to place in the file or dns TXT record or the Certificate for tls-sni-01 challenges
    [System.Management.Automation.ScriptBlock] $onChallenge,

    # Script to be invoked after completing the challenge receiving the same parameter as -onChallenge with the addition of the response status 'valid' or 'invalid' as 4th parameter
    [System.Management.Automation.ScriptBlock] $onChallengeCleanup,
    
    # Internal identifier of the ACME account
    [Parameter(DontShow = $true)]
    [String] $InternalAccountIdentifier = "ACMEDefaultAccount",

    # Try to fix common problems automatically.
    # This includes:
    # - Creating new account with existing configuration if AccountKey is missing (this overwrites account id/data)
    [Switch] $AutoFix,

    # The place to save the certificate and keys
    [System.Security.Cryptography.X509Certificates.StoreLocation] $Context = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
)
Begin {
    function die {
        param(
            [System.Management.Automation.ErrorRecord] $Exception,
            [string] $Message = "",
            [int] $ExitCode = 1,
            [int] $EventId = 0,
            [string] $LogName = "Windows PowerShell",
            [string] $Source = "PowerShell",
            [int] $Category = 0,
            [System.Diagnostics.EventLogEntryType] $EntryType = [System.Diagnostics.EventLogEntryType]::Error,
            [switch] $DontRemoveLock
        )
        try {
            [string] $FullDescription = "[$($AppName)] $($Message)"
            if ($Exception -ne $null) {
                $FullDescription += "`n$($Exception.FullyQualifiedErrorId)"
                $FullDescription += "`nExceptionMessage: $($Exception.Exception.Message)"
                if ($Exception.ErrorDetails -ne $null) {
                    $FullDescription += "`n$($Exception.ErrorDetails.Message)"
                }
                $FullDescription += "`n$($Exception.InvocationInfo.PositionMessage)"
                $FullDescription += "`nCategoryInfo: $($Exception.CategoryInfo.GetMessage())"
                $FullDescription += "`nStackTrace:`n$($Exception.ScriptStackTrace)"
                $FullDescription += "`n$($Exception.Exception.StackTrace)"
            }
            Write-Eventlog -EntryType $EntryType -LogName $LogName -Source $Source -Category $Category -EventId $EventId -Message $FullDescription
            Write-Host $FullDescription -ForegroundColor Red -BackgroundColor Black
            if (-not $DontRemoveLock) { Remove-Lock }
            Exit $ExitCode
        } catch {
            Write-Host " X An unexpected Error occured resulting in another error while handling your first error."
            Write-Host $_.FullyQualifiedErrorId
            Exit $ExitCode
        }
    }
    trap [Exception] { die -Exception $_ }
    Set-PSDebug -Strict
    Set-StrictMode -Version 4
    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    $Error.Clear()
    
    function Create-Lock([System.IO.FileInfo] $Path = $LockFile) {
        if ($NoLock) { return }
        if ($Path.Exists) {die -Message "Lock file $Path present, aborting." -DontRemoveLock}
        
        try {
            [IO.File]::OpenWrite($Path).Close()
            $PID | Out-File $Path
        } catch {
            die -Message "LOCKFILE $Path is not writable, aborting."
        }
    }
    function Remove-Lock([System.IO.FileInfo] $Path = $LockFile) {
        if ($NoLock) { return }
        Remove-Item $Path
    }
    function Invoke-SignedWebRequest([uri] $Uri, [Microsoft.PowerShell.Commands.WebRequestMethod] $Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Post, [String] $Resource, [hashtable] $Payload) {
        $Payload.resource = $Resource
        $body = @{
            header = Get-JWKHeader;
            protected = Get-JWKHeader -Nonce (Get-ACMENonce) -Base64;
            payload = Encode-UrlBase64 -Object $Payload;
        }
        $body.signature = Get-JWSignature -Value "$($body.protected).$($body.payload)"
        [String] $json = ConvertTo-Json -InputObject $body -Compress
        
        try {
            $resp = Invoke-WebRequest -Uri $Uri -Method $Method -Body $json -ContentType 'application/json' -UseBasicParsing -UserAgent $UserAgent
        } catch [System.Net.WebException] {
            $acmeError = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($acmeError -ne $null) {
                $errType = $acmeError.type.Split(':')|Select-Object -Last 1
                Write-Host " ! Error[$($errType)]: $($acmeError.detail)"
                throw $errType
            }
            die -Exception $_
        }
        $resp.Content|ConvertFrom-Json
    }
    function Get-ACMENonce([uri] $Uri = $CA) {
        $resp = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -UserAgent $UserAgent
        if (-not $resp.Headers.ContainsKey('Replay-Nonce')) {throw "Can't fetch Nonce"}
        $resp.Headers['Replay-Nonce']
    }
    function Get-JWKHeader([System.Security.Cryptography.RSACng] $Rsa = $AccountKey, [String] $Nonce, [Switch] $JSON, [Switch] $Base64) {
        $export = $Rsa.ExportParameters($false)
    
        $header = @{
            alg = "RS256";
            jwk = @{
                kty = "RSA";
                e = (Encode-UrlBase64 -Bytes $export.Exponent);
                n = (Encode-UrlBase64 -Bytes $export.Modulus);
            };
        }
    
        if ($Nonce.Length) {
            $header.nonce = $Nonce
        }

        if (-not ($JSON -or $Base64)) {
            return $header
        } elseif ($Base64){
            Encode-UrlBase64 -Object $header
        } else {
            ConvertTo-Json -Compress -InputObject $header
        }
    }
    function Get-JWSignature([String] $Value, [System.Security.Cryptography.RSACng] $Rsa = $AccountKey, [System.Security.Cryptography.HashAlgorithmName] $Algo = [System.Security.Cryptography.HashAlgorithmName]::SHA256) {
        Encode-UrlBase64 -Bytes ($Rsa.SignData([System.Text.Encoding]::UTF8.GetBytes($Value), $Algo, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1))
    }
    function Get-ACMEDirectory([uri] $Uri) {
        [hashtable] $Directory = @{
            "newNonce" = "";
            "newAccount" = "";
            "newAuthz" = "";
            "newOrder" = "";
            "keyChange" = "";
            "revokeCert" = "";
            "termsOfService" = "";
        }
    
        $json = (Invoke-WebRequest -Uri $Uri -UseBasicParsing -UserAgent $UserAgent).Content | ConvertFrom-Json

        if ($ACMEVersion -eq "acme1-boulder") {
            # WAT moment #1:
                # They invent acme
                # Let'sEncrypt is first in implementation
                # Fundamentally changes the very first api call! That single point that configures every client!
                # WAT?
            $Directory.newAccount = $json.'new-reg'
            $Directory.account = $json.'new-reg' -replace 'new-reg', 'reg/'
            $Directory.newAuthz = $json.'new-authz'
            $Directory.authz = $json.'new-authz' -replace 'new-authz', 'authz/'
            $Directory.newOrder = $json.'new-cert'
            $Directory.order = $json.'new-cert' -replace 'new-cert', 'cert/'
            $Directory.keyChange = $json.'key-change'
            $Directory.revokeCert = $json.'revoke-cert'
            $Directory.termsOfService = $json.meta.'terms-of-service'
        } else {
            $json.psobject.properties|% {$Directory[$_.Name] = $_.Value }
        }
    
        $Directory
    }
    function Get-RSACng([String] $Name, [int] $Size = 4096) {
        if ($ResetRegistration -and [System.Security.Cryptography.CngKey]::Exists($Name)) {
            [System.Security.Cryptography.CngKey]::Open($Name).Delete()
        }
        if ([System.Security.Cryptography.CngKey]::Exists($Name)) {
            return New-Object System.Security.Cryptography.RSACng ([System.Security.Cryptography.CngKey]::Open($Name))
        } else {
            $ResetRegistration = $true
            [System.Security.Cryptography.CngKeyCreationParameters] $keyCreationParams = New-Object System.Security.Cryptography.CngKeyCreationParameters
            $keyCreationParams.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport -bor [System.Security.Cryptography.CngExportPolicies]::AllowExport
            $keyCreationParams.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::AllUsages
            $keyCreationParams.Parameters.Add([System.Security.Cryptography.CngProperty](New-Object System.Security.Cryptography.CngProperty "Length", ([BitConverter]::GetBytes($Size)), ([System.Security.Cryptography.CngPropertyOptions]::None)))
        
            return New-Object System.Security.Cryptography.RSACng ([System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, $Name, $keyCreationParams))
        }
    }
    function Get-PrivateKey([string] $Name, [int] $Size, [System.Security.Cryptography.CngAlgorithm] $Algorithm = [System.Security.Cryptography.CngAlgorithm]::Rsa) {
        switch ($Algorithm) {
            ([System.Security.Cryptography.CngAlgorithm]::Rsa) {
                [type] $RetType = [System.Security.Cryptography.RSACng]
            }
            ([System.Security.Cryptography.CngAlgorithm]::ECDsaP256) {
                $Size = 256
                [type] $RetType = [System.Security.Cryptography.ECDsaCng]
            }
            ([System.Security.Cryptography.CngAlgorithm]::ECDsaP384) {
                $Size = 384
                [type] $RetType = [System.Security.Cryptography.ECDsaCng]
            }
        }

        if ([System.Security.Cryptography.CngKey]::Exists($Name)) {
            New-Object -TypeName $RetType.FullName -ArgumentList ([System.Security.Cryptography.CngKey]::Open($Name))
        } else {
            [System.Security.Cryptography.CngKeyCreationParameters] $keyCreationParams = New-Object System.Security.Cryptography.CngKeyCreationParameters
            $keyCreationParams.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport -bor [System.Security.Cryptography.CngExportPolicies]::AllowExport
            $keyCreationParams.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::AllUsages
            
            $keyCreationParams.Parameters.Add([System.Security.Cryptography.CngProperty](New-Object System.Security.Cryptography.CngProperty "Length", ([BitConverter]::GetBytes($Size)), ([System.Security.Cryptography.CngPropertyOptions]::None)))
        
            New-Object -TypeName $RetType.FullName -ArgumentList ([System.Security.Cryptography.CngKey]::Create($CngAlgorithm, $Name, $keyCreationParams))
        }
    }
    function Get-ACMEPrivateKeyThumbprint {
        [System.Security.Cryptography.HashAlgorithm] $Algo = [System.Security.Cryptography.SHA256Cng]::Create()
        $export = $AccountKey.ExportParameters($false)
        Encode-UrlBase64 -Bytes (
            $Algo.ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes(
                    '{"e":"' + (Encode-UrlBase64 -Bytes $export.Exponent) + '","kty":"RSA","n":"' + (Encode-UrlBase64 -Bytes $export.Modulus) + '"}'
                )
            )
        )
    }
    function Get-CngPrivateKeyFromCertificate([Parameter(Mandatory = $true, ValueFromPipeline = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert) {
        # well, by now it should be obvious whats going on here
        # feel free to test it with:
        # gci cert:\CurrentUser\my | Get-CngPrivateKeyFromCertificate
        Begin {
            if (-not ("WINAPI.crypt32" -as [type])) {
                Add-Type -Namespace WINAPI -Name crypt32 -MemberDefinition @"
                    [DllImport("crypt32.dll", SetLastError = true)]
                    [return: MarshalAs(UnmanagedType.Bool)]
                    public static extern bool CryptAcquireCertificatePrivateKey(
                        IntPtr pCert,
                        uint dwFlags,
                        IntPtr pvReserved,  // must be null
                        [Out] out Microsoft.Win32.SafeHandles.SafeNCryptKeyHandle phCryptProvOrNCryptKey,
                        [Out] out int dwKeySpec,
                        [Out, MarshalAs(UnmanagedType.Bool)] out bool pfCallerFreeProvOrNCryptKey);
"@
            }
        }
        Process {
            [IntPtr] $handle = $Cert.Handle
            [Microsoft.Win32.SafeHandles.SafeNCryptKeyHandle] $key = $null
            [int] $keySpec = 0
            [bool] $free = $false

            [bool] $ret = [WINAPI.crypt32]::CryptAcquireCertificatePrivateKey($handle, 0x00040000 <#CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG#>, 0, [ref]$key, [ref]$keySpec, [ref]$free)

            if (-not $ret) { throw "Can't acquire NCRYPT private key" }

            [System.Security.Cryptography.CngKey] $cngkey = [System.Security.Cryptography.CngKey]::Open($key, [System.Security.Cryptography.CngKeyHandleOpenOptions]::None)
            if ($cngkey -eq $null) { throw "Can't acquire private CngKey" }
            $cngkey
        }
    }
    function ConvertTo-PEM([Parameter(Mandatory = $true, ValueFromPipeline = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert, [Switch] $Public, [Switch] $Private) {
        if ($Public) {
            Format-Pem -Bytes ($Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)) -Header "CERTIFICATE"
        }
        if ($Private) {
            if (-not $Cert.HasPrivateKey) {throw "Can't get private key"}

            $key = $Cert.PrivateKey
            if ($key -eq $null) {
                $key = Get-CngPrivateKeyFromCertificate -Cert $Cert

                switch ($key.AlgorithmGroup.AlgorithmGroup) {
                    RSA { ConvertRSATo-Pem -PrivateKey (New-Object -TypeName System.Security.Cryptography.RSACng -ArgumentList ($key)) }
                    ECDSA { ConvertECDsaTo-Pem -PrivateKey (New-Object -TypeName System.Security.Cryptography.ECDsaCng -ArgumentList ($key)) }
                    ECDH { Write-Host " ! Exports of EC Certificates in PEM format isn't supported on your system." }
                }
            } else { ConvertRSATo-Pem -PrivateKey $key }
        }
    }
    function Format-Pem([byte[]]$Bytes, [string]$Header) {
        [string] $out = ""
        if ($Header.Length) {
            $out += "-----BEGIN $($Header)-----`n"
        }
        [string] $base64 = [System.Convert]::ToBase64String($Bytes)
        for ([int] $i = 0; $i -lt $base64.Length; $i += 64) {
            $out += $base64.Substring($i, [System.Math]::Min(64, $base64.Length - $i)) + "`n"
        }
        if ($Header.Length) {
            $out += "-----END $($Header)-----"
        }
        $out
    }
    function ConvertRSATo-Pem([System.Security.Cryptography.RSA] $PrivateKey) {
        [System.Security.Cryptography.RSAParameters] $params = $PrivateKey.ExportParameters($true)

        Format-Pem -Bytes (
            (Encode-ASN1Sequence (
                (Encode-ASN1Integer 0), # version
                (Encode-ASN1Integer $params.Modulus),
                (Encode-ASN1Integer $params.Exponent),
                (Encode-ASN1Integer $params.D),
                (Encode-ASN1Integer $params.P),
                (Encode-ASN1Integer $params.Q),
                (Encode-ASN1Integer $params.DP),
                (Encode-ASN1Integer $params.DQ),
                (Encode-ASN1Integer $params.InverseQ)
            ))) -Header "RSA PRIVATE KEY"
    }
    function ConvertECDsaTo-Pem([System.Security.Cryptography.ECDsa] $PrivateKey) {
        [System.Security.Cryptography.ECParameters] $params = $PrivateKey.ExportParameters($true)
        if ($params.D -eq $null) {throw "Can't get private key"}

        <#
            ECPrivateKey ::= SEQUENCE {
                version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
                privateKey     OCTET STRING, $params.D
                parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
                publicKey  [1] BIT STRING OPTIONAL  CompressingOption, $params.Q.X, $params.Q.Y
            }        
        #>
        Format-Pem -Bytes (
            (Encode-ASN1Sequence (
                (Encode-ASN1Integer 1), # version
                (Encode-ASN1OctetString $params.D), # privateKey
                (Encode-ASN1Choice 0 (
                    [System.Security.Cryptography.CryptoConfig]::EncodeOID(([System.Security.Cryptography.Oid]($PrivateKey.Key.Algorithm.Algorithm)).Value))), # parameters / curve oid
                (Encode-ASN1Choice 1 (
                    Encode-ASN1BitString (([byte[]]0x04) + $params.Q.X + $params.Q.Y))) # 0x04 uncompressed ECPoint, publicKey
            ))) -Header "EC PRIVATE KEY"
    }
    function Encode-ASN1OctetString([byte[]] $Data) {
        [byte[]] $ret = (4)
        $ret += Encode-ASN1ByteLength $Data.Count
        $ret += $Data
        $ret
    }
    function Encode-ASN1Integer([Parameter(Position = 0, ParameterSetName = 'Int')] [int] $Data, [Parameter(Position = 0, ParameterSetName = 'Bytes')] [byte[]] $Bytes) {
        if ($PSCmdlet.ParameterSetName -eq 'Int') {
            [byte[]] $val = [System.BitConverter]::GetBytes($Data)
            if ([System.BitConverter]::IsLittleEndian) {[array]::Reverse($val)}
        } else {
            [byte[]] $val = $Bytes
        }

        [int] $leftPadLen = 0
        for ([int] $i = 0; $i -lt $val.Count -and $val[$i] -eq 0; $i+=1) { $leftPadLen++ }
        [byte[]] $trimed = $val|select -Skip $leftPadLen
        [byte[]] $filtered = $val|? { $_ -eq 0}
        if ($filtered -ne $null -and $filtered.Count -eq $val.Count) { # $val is array of 0
            [byte[]] $sanitized = ([byte]0x0)
        } else {
            if ($trimed[0] -gt 0x7f) {
                [byte[]] $sanitized = ([byte]0x0)
                $sanitized += $trimed
            } else {
                [byte[]] $sanitized = $trimed
            }
        }

        [byte[]] $ret = (2)
        $ret += Encode-ASN1ByteLength -Length $sanitized.Count
        $ret += $sanitized
        $ret
    }
    function Encode-ASN1Sequence([byte[][]] $Data){
        [byte[]] $ret = (0x30)
        $ret += Encode-ASN1ByteLength -Length ($Data|ForEach-Object -Begin {$i=0} -Process {$i+=([byte[]]$_).Count} -End {$i})
        for ([int] $i = 0; $i -lt $Data.Count; $i++) {
            $ret += $Data[$i]
        }
        $ret
    }
    function Encode-ASN1BitString([byte[]] $Data){
        [byte[]] $ret = (0x03)
        $ret += Encode-ASN1ByteLength ($Data.Count + 1)
        $ret += 0x00 # number of padded bits (our bytes are always 8-based in length)
        $ret += $Data
        $ret
    }
    function Encode-ASN1Choice([int] $Value, [byte[]] $Data){
        [byte[]] $ret = ((0xA0 -bor $Value))
        $ret += Encode-ASN1ByteLength -Length $Data.Count
        $ret += $Data
        $ret
    }
    function Encode-ASN1ByteLength([int] $Length) {
        if ($Length -lt 128) {
            # Short form
            [byte[]] $ret = ([byte] $Length)
        } else {
            # Long form
            [int] $req = 0
            [int] $t = $Length
            while ($t -gt 0) {
                $t = $t -shr 8
                $req++
            }
            [byte[]] $ret = (([byte]$req) -bor 0x80)
            for ([int] $i = $req -1; $i -ge 0; $i--) {
                $ret += [byte]($Length -shr (8*$i) -band 0xff)
            }
        }
        $ret
    }
    function Get-AccountConfig {
        Get-Content -Path $AccountConfig | ConvertFrom-Json | ConvertTo-Hashtable
    }
    function Verify-ACMELicense {
        [String] $License = $Directory.termsOfService
        if ($License -eq "") {return}
    
        if ($AccountConfig.Exists) {
            $config = Get-AccountConfig
            if ($config.agreement -ne $License) {
                if ($AcceptTerms) {
                    $config.agreement = $License
                    Update-ACMERegistration -Config $config
                } else {
                    die -Message "The terms of service changed.`nTo use this certificate authority you have to agree to their terms of service which you can find here: $License`nTo accept these terms of service use -AcceptTerms."
                }
            }
        } elseif (!$AcceptTerms) {
            die -Message "To use this certificate authority you have to agree to their terms of service which you can find here: $License`nTo accept these terms of service use -AcceptTerms."
        }
    }
    function Verify-ACMERegistration {
        if (-not $AccountConfig.Exists -or $ResetRegistration) {
            return Create-ACMERegistration
        }

        # check $Contact for changes
        if ($Contact -ne $null) {
            $config = Get-AccountConfig
            if (-not (Compare-Lists $Contact $config.contact)) {
                $config.contact = $Contact
                return Update-ACMERegistration -Config $config
            }
        }

        if ($RenewRegistration) {
            return Update-ACMERegistration
        }
    }
    function Create-ACMERegistration([hashtable] $Config) {
        try {
            $req = @{ agreement = $Directory.termsOfService; }

            if ($Config -ne $null -and $Config.contact -ne $null) {
                $req.contact = $Config.contact
            } elseif ($Contact -ne $null) {
                $req.contact = $Contact
            }

            $resp = Invoke-SignedWebRequest -Uri $Directory.newAccount -Resource new-reg -Payload $req
        } catch {
            switch ($_.Exception.Message) {
                'invalidEmail' {
                    if ($AutoFix) {
                        Write-Host " ! AutoFix: removing Contact from request. You will not receive notifications!"
                        $Config.contact = $null
                        Update-ACMERegistration $Config
                        Write-Host " + AutoFix: successful"
                        return
                    }
                    die -Message "Email domain verification failed! Check your email address!"
                }
                'malformed' { # AccountKey is assigned to different account; possible reason I can think of: (re)moved/deleted account file/directory => only rescue would be creation of new account
                    if ($AutoFix) {
                        Write-Host " ! AutoFix: applying -ResetRegistration and recreating AccountKey"
                        $AutoFix = $false # disable due to recursive loop
                        [System.Security.Cryptography.CngKey]::Open($AccHash).Delete()
                        $AccountKey = Get-RSACng -Name $AccHash
                        Create-ACMERegistration $Config
                        $AutoFix = $true
                        Write-Host " + AutoFix: successful"
                        return
                    }
                    die -Message "Local account data is corrupt. Please recreate account with -ResetRegistration"
                }
            }
            die -Exception $_
        }
        $resp.agreement = $Directory.termsOfService
        $resp | ConvertTo-Json -Compress | Out-File -FilePath $AccountConfig
    }
    function Update-ACMERegistration($Config = (Get-AccountConfig)) {
        try {
            $resp = Invoke-SignedWebRequest -Uri ($Directory.account + $Config.id) -Resource reg -Payload $Config
        } catch {
            switch ($_.Exception.Message) {
                'invalidEmail' {
                    if ($AutoFix) {
                        Write-Host " ! AutoFix: removing Contact from request. You will not receive notifications!"
                        $Config.contact = $null
                        Update-ACMERegistration $Config
                        Write-Host " + AutoFix: successful"
                        return
                    }
                    die -Message "Email domain verification failed! Check your email address!"
                }
                'malformed' { # id in url is missing or -lt 0; possible reason I can think of: (re)moved account file => only rescue would be creation of new account
                    if ($AutoFix) {
                        Write-Host " ! AutoFix: applying -ResetRegistration and recreating account"
                        Create-ACMERegistration $Config
                        Write-Host " + AutoFix: successful"
                        return
                    }
                    die -Message "Local account data is corrupt. Please recreate account with -ResetRegistration"
                }
                'unauthorized' { # wrong account key; maybe copied account directory to different server or runs in different user context?
                    if ($AutoFix) {
                        Write-Host " ! AutoFix: applying -ResetRegistration and recreating account"
                        Create-ACMERegistration $Config
                        Write-Host " + AutoFix: successful"
                        return
                    }
                    die -Message "Local account data is corrupt. Please recreate account with -ResetRegistration"
                }
            }
            die -Exception $_
        }
        $resp | ConvertTo-Json -Compress | Out-File -FilePath $AccountConfig
    }
    function Encode-UrlBase64 {
        Param(
            [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='String')]
            [String] $String,
            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='Bytes')]
            [byte[]] $Bytes,
            [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='Object')]
            [hashtable] $Object
        )
        if ($PSCmdlet.ParameterSetName -eq 'Object') {
            [byte[]] $Bytes = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Object -Compress))
        } elseif ($PSCmdlet.ParameterSetName -eq 'String') {
            [byte[]] $Bytes = [System.Text.Encoding]::UTF8.GetBytes($String)
        }

        [Convert]::ToBase64String($Bytes).TrimEnd("=").Replace('+', '-').Replace('/', '_')
    }
    function Decode-UrlBase64 {
        Param(
            [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='String')]
            [String] $Value,
            [Switch] $AsString,
            [Switch] $AsObject
        )

        if ($Value.Length % 4 -gt 0) {
            $Value = $Value + ('=' * (4 - ($Value.Length % 4)))
        }
        $Value = $Value.Replace('-', '+').Replace('_', '/')

        [byte[]] $Bytes = [Convert]::FromBase64String($Value)

        if ($AsString) {
            [System.Text.Encoding]::UTF8.GetString($Bytes)
        } elseif ($AsObject) {
            ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString($Bytes))
        } else {
            $Bytes
        }
    }
    function ConvertTo-Hashtable([Parameter(Mandatory=$true, ValueFromPipeline=$true)] $Object) {
        $Object.psobject.Properties|% -Begin {[hashtable] $h = @{}} -Process { $h[$_.Name] = $_.Value } -End { $h }
    }
    function Compare-Lists([array] $a = $null, [array] $b = $null) {
        if ($a -eq $null -and $b -eq $null) { return $true } # boath are $null
        if ($a -eq $null -or $b -eq $null) { return $false } # only one of them $null?

        if ($a.Count -ne $b.Count) { return $false }
        for ([int] $i = 0; $i -lt $a.Count; $i++) {
            if ($a.IndexOf($b[$i]) -eq -1 -or $b.IndexOf($a[$i]) -eq -1) {
                return $false
            }
        }
        $true
    }
    function Verify-Certificate([String] $Domain, [String[]] $SAN) {
        if ($ResetRegistration -or $RenewCertificate -or $RecreateCertificate) { return $false }
        
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $cert = Get-LastCertificate -Domain $Domain -SAN $SAN
        
        if ($cert -eq $null) {
            Write-Host " ! Can't find existing certificate. Creating new..."
            return $false
        }

        Write-Host " + Checking expire date of existing cert..."
        Write-Host " + Valid till $($cert.NotAfter) " -NoNewline
        [System.DateTime] $offDate = (Get-Date).AddDays($RenewDays)
        if ($cert.NotAfter -gt $offDate) {
            Write-Host "(Longer than $(($cert.NotAfter - $offDate).Days) days)."
        } else {
            Write-Host "(Less than $(($cert.NotAfter - $offDate).Days) days). Renewing!"
            return $false        
        }

        # passed all checks
        return $true
    }
    function Get-CertificateFriendlyName([String] $Domain) { "$($Domain) - $($AccHash)" }
    function Get-CertificateAlternateDomainNames([Parameter(Mandatory = $true, ValueFromPipeline = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert) {
        if (($Cert | Get-Member -Name DnsNameList) -ne $null -and $Cert.DnsNameList -ne $null -and $Cert.DnsNameList.Count -gt 0) {
            $Cert.DnsNameList|% {$_.ToString()}
        } else { # fallback
            $Cert.Extensions["2.5.29.17"].Format($false)|% {$_ -split ', '}|? {($_ -split '=')[0] -like '*DNS*'}|% {($_ -split '=')[1]}
        }
    }
    function Get-LastCertificate([String] $Domain, [string[]] $SAN) {
        [string[]] $DnsNameList = ($Domain)
        if ($SAN -ne $null) { $DnsNameList += $SAN }

        [System.Security.Cryptography.X509Certificates.X509Certificate2](gci "Cert:\$($Context)\My" |? {
            $_.FriendlyName -eq (Get-CertificateFriendlyName $Domain) -and # Domain and CA check
            (Compare-Lists (Get-CertificateAlternateDomainNames $_) $DnsNameList) -and # SAN/DnsNamesList check
            $_.HasPrivateKey -and
            ($key = $_ | Get-CngPrivateKeyFromCertificate) -ne $null -and # PK check
            $key.Algorithm.Algorithm.Replace("ECDH_", "ECDSA_") -eq $KeyAlgo.Algorithm -and # PK ExchAlgo check (global input)
                # In Win7/2012R2 ECDSA_* keys will show up as ECDH_* - and also I can't export the private keys in pem format
                # I don't know yet if I can fix that
            ($KeyAlgo -ne [System.Security.Cryptography.CngAlgorithm]::Rsa -or $key.KeySize -eq $KeySize) -and # Rsa PK size check (global input)
            ($_.Extensions["1.3.6.1.5.5.7.1.24"] -ne $null) -eq $OcspMustStaple # OcspMustStaple
        } | Sort-Object -Property NotAfter -Descending | Select-Object -First 1)
    }
    function Get-CertificateIssuerCertificate([Parameter(Mandatory = $true, ValueFromPipeline = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert) {
        # $issuerUrl = ($Cert.Extensions|? {$_.Oid.Value -eq "1.3.6.1.5.5.7.1.1"}).RawData|Decode-ASN1Sequence|? {($_|Decode-ASN1Sequence)[0].IsCAIssuer}|% {($_|Decode-ASN1Sequence)[1]|Decode-ASN1String}
        [System.Security.Cryptography.X509Certificates.X509Extension] $oid = $Cert.Extensions["1.3.6.1.5.5.7.1.1"]
        if ($oid -eq $null) { return }
        
        [string] $CaInfo = $oid.Format($false)
        if ($CaInfo.IndexOf("(1.3.6.1.5.5.7.48.2)") -eq -1) { return }
        
        [int] $i = $CaInfo.IndexOf("URL=", $CaInfo.LastIndexOf("(1.3.6.1.5.5.7.48.2)")) +4
        [uri] $uri = $CaInfo.Substring($i, [System.Math]::Min($CaInfo.Length, $(if ($CaInfo.IndexOf(",", $i) -ne -1) { $CaInfo.IndexOf(",", $i) } else { $CaInfo.Length })) - $i)
        
        $resp = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Get
        if ($resp.StatusCode -ne 200) { return }
        
        New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList ($resp.Content, "")
    }
    function Sign-Domain([String] $Domain, [String[]] $SAN) {
        Verify-ACMEAuthorization $Domain
        if ($SAN -ne $null) { $SAN |% { Verify-ACMEAuthorization $_ } }

        [System.Security.Cryptography.X509Certificates.X509Certificate2] $OldCert = Get-LastCertificate -Domain $Domain -SAN $SAN
        
        if ($RecreateCertificate -or $OldCert -eq $null) {
            Create-Certificate -Domain $Domain -SAN $SAN
        } else {
            Renew-Certificate -OldCert $OldCert
        }
    }
    function Verify-ACMEAuthorization([String] $Domain) {
        Write-Host " + Requesting challenge for $($Domain)..."
        $challenges = (Invoke-SignedWebRequest -Uri $Directory.newAuthz -Resource "new-authz" -Payload @{
            "identifier" = @{
                "type" = "dns";
                "value" = $Domain;
            }
        }).challenges
        if (($challenges|? {$_.status -eq "valid"}) -ne $null) { # any valid challange is ok
            Write-Host " + Already validated!"
            return
        }
        $challenge = $challenges|? {$_.type -eq $ChallengeType}
        if ($challenge.status -ne "pending") { die -Message "Challenge status is '$($challenge.status)'. Can't continue!" }

        [string] $keyAuthorization = "$($challenge.token).$(Get-ACMEPrivateKeyThumbprint)"

        switch ($ChallengeType) {
            'http-01' { &$onChallenge "$($Domain)" "$($challenge.token)" "$($keyAuthorization)" | Write-Host }
            'dns-01' {
                [string] $dnsAuthorization = Encode-UrlBase64 -Bytes ([System.Security.Cryptography.SHA256Cng]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($keyAuthorization)))
                &$onChallenge "$($Domain)" "_acme-challenge.$($Domain)" "$($dnsAuthorization)" | Write-Host
            }
            'tls-sni-01' {
                [string] $sniAuthorization = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256Cng]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($keyAuthorization))).Replace('-','').ToLower()
                [string] $sniFqdn = "$($sniAuthorization.Substring(0, 32)).$($sniAuthorization.Substring(32, 32)).acme.invalid"
                [System.Security.Cryptography.X509Certificates.X509Certificate2] $sniCert = Create-Certificate -Domain $sniFqdn -SelfSigned
                &$onChallenge "$($Domain)" "$sniFqdn" $sniCert | Write-Host
            }
        }

        Write-Host " + Responding to challenge for $($Domain)..."
        $resp = Invoke-SignedWebRequest -Uri $challenge.uri -Resource 'challenge' -Payload @{
            "keyAuthorization" = $keyAuthorization;
        }

        while ($resp.status -eq "pending") {
            Start-Sleep -Seconds 1
            $resp = (Invoke-WebRequest -Uri $challenge.uri -Method Get -UseBasicParsing).Content|ConvertFrom-Json
        }

        switch ($ChallengeType) {
            'http-01' { &$onChallengeCleanup "$($Domain)" "$($challenge.token)" "$($keyAuthorization)" "$($resp.status)" | Write-Host }
            'dns-01'  { &$onChallengeCleanup "$($Domain)" "_acme-challenge.$($Domain)" "$($dnsAuthorization)" "$($resp.status)" | Write-Host }
            'tls-sni-01'  { &$onChallengeCleanup "$($Domain)" "$sniFqdn" $sniCert "$($resp.status)" | Write-Host }
        }

        if ($resp.status -eq "valid") {
            Write-Host " + Challenge is valid!"
        } elseif ($resp.status -eq "invalid") {
            die -Message ("Challenge is invalid`n" + " ! Error[$($resp.error.type.Split(':')|Select-Object -Last 1)]: $($resp.error.detail)")
        }
    }
    function Create-Certificate([String] $Domain, [String[]] $SAN, [Switch] $SelfSigned) {
        # setup defaults
        [int] $Size = $KeySize
        [string] $HashAlgo = "SHA256"
        $algoId = New-Object -ComObject X509Enrollment.CObjectId
        # set crypto specific settings
        switch ($KeyAlgo) {
            ([System.Security.Cryptography.CngAlgorithm]::Rsa) {
                $algoId.InitializeFromAlgorithmName(3 <#XCN_CRYPT_PUBKEY_ALG_OID_GROUP_ID#>, 0 <#XCN_CRYPT_OID_INFO_PUBKEY_ANY#>, 0 <#AlgorithmFlagsNone#>, "RSA")
            }
            ([System.Security.Cryptography.CngAlgorithm]::ECDsaP256) {
                $algoId.InitializeFromAlgorithmName(3 <#XCN_CRYPT_PUBKEY_ALG_OID_GROUP_ID#>, 0 <#XCN_CRYPT_OID_INFO_PUBKEY_ANY#>, 0 <#AlgorithmFlagsNone#>, "ECDSA_P256")
                $Size = 256
            }
            ([System.Security.Cryptography.CngAlgorithm]::ECDsaP384) {
                $algoId.InitializeFromAlgorithmName(3 <#XCN_CRYPT_PUBKEY_ALG_OID_GROUP_ID#>, 0 <#XCN_CRYPT_OID_INFO_PUBKEY_ANY#>, 0 <#AlgorithmFlagsNone#>, "ECDSA_P384")
                $Size = 384
                $HashAlgo = "SHA384"
            }
        }
        Write-Host " + Creating request: ExchangeAlgorithm: $($KeyAlgo.Algorithm), KeySize: $($Size), HashAlgorithm: $($HashAlgo), OCSP-MustStaple: $(if($OcspMustStaple){"On"}else{"Off"})"

        # create Key with CertEnroll API
        $pk = New-Object -ComObject X509Enrollment.CX509PrivateKey -Property @{
            Length = $Size;
            ProviderName = "Microsoft Software Key Storage Provider";
            ExportPolicy = ( # request for discussion!
                1 -bor # XCN_NCRYPT_ALLOW_EXPORT_FLAG
                2 -bor # XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
                4 -bor # XCN_NCRYPT_ALLOW_ARCHIVING_FLAG
                8      # XCN_NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG
            );
            KeySpec = 1; # XCN_AT_KEYEXCHANGE
            KeyUsage = (
                1 -bor # XCN_NCRYPT_ALLOW_DECRYPT_FLAG
                2 -bor # XCN_NCRYPT_ALLOW_SIGNING_FLAG
                4      # XCN_NCRYPT_ALLOW_KEY_AGREEMENT_FLAG
            );
            Algorithm = $algoId;
            MachineContext = ($Context -eq [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine);
        }
        $pk.Create()
    
        # create request object
        $request = if ($SelfSigned) { New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate }
                               else { New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10 }
        $request.InitializeFromPrivateKey($(
            if ($Context -eq [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine) {
                3 # ContextAdministratorForceMachine
            } else {
                1 # ContextUser
            }
        ), $pk, "")

        $request.SuppressDefaults = $true
    
        # add Subject
        $dn = New-Object -ComObject X509Enrollment.CX500DistinguishedName
        $dn.Encode("CN=$($Domain)", 0) # XCN_CERT_NAME_STR_NONE = 0
        $request.Subject = $dn

        # sha256/384 signature
        $hashId = New-Object -ComObject X509Enrollment.CObjectId
        $hashId.InitializeFromValue(([System.Security.Cryptography.Oid]$HashAlgo).Value)
        $request.HashAlgorithm = $hashId

        # Key Usage
        $extKeyUsage = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
        $extKeyUsage.InitializeEncode([int][System.Security.Cryptography.X509Certificates.X509KeyUsageFlags](("DigitalSignature", "KeyEncipherment")))
        $extKeyUsage.Critical = $true
        $request.X509Extensions.Add($extKeyUsage)
    
        # add extensions
        $objectIds = New-Object -ComObject X509Enrollment.CObjectIds
        # Serverauthentifizierung, Clientauthentifizierung
        # Can't work with common friendly names because they vary based on your systems language.... WAT?
        "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"|% {
            $objectId = New-Object -ComObject X509Enrollment.CObjectId
            $objectId.InitializeFromValue($_)
            $objectIds.Add($objectId)
        }

        $extEnhancedKeyUsage = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
        $extEnhancedKeyUsage.InitializeEncode($objectIds)
        $request.X509Extensions.Add($extEnhancedKeyUsage)
    
        # add alternative names
        $alternameNames = New-Object -ComObject X509Enrollment.CAlternativeNames
    
        $alternameName = New-Object -ComObject X509Enrollment.CAlternativeName
        $alternameName.InitializeFromString(3, $Domain) # XCN_CERT_ALT_NAME_DNS_NAME = 3
        $alternameNames.Add($alternameName)
        if ($SAN -ne $null) {
            $SAN|% {
                $alternameName = New-Object -ComObject X509Enrollment.CAlternativeName
                $alternameName.InitializeFromString(3, $_) # XCN_CERT_ALT_NAME_DNS_NAME = 3
                $alternameNames.Add($alternameName)
            }
        }
    
        $extAlternativeNames = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
        $extAlternativeNames.InitializeEncode($alternameNames)
        $request.X509Extensions.Add($extAlternativeNames)
    
        if ($OcspMustStaple) {
            # X509Extension(OID(1.3.6.1.5.5.7.1.24), SEQUENCE(INTEGER(5)))
            $objectId = New-Object -ComObject X509Enrollment.CObjectId
            $objectId.InitializeFromValue("1.3.6.1.5.5.7.1.24")
            $ocsp = New-Object -ComObject X509Enrollment.CX509Extension
            $ocsp.Initialize($objectId, 1, [System.Convert]::ToBase64String((Encode-ASN1Sequence(Encode-ASN1Integer 5))))
            $request.X509Extensions.Add($ocsp)
        }

        # finish Pkcs10 request
        $request.Encode()

        # create enrollment class
        $enroll = New-Object -ComObject X509Enrollment.CX509Enrollment
        $enroll.InitializeFromRequest($request)
        
        $enroll.CertificateFriendlyName = Get-CertificateFriendlyName $Domain
        $enroll.CertificateDescription = ("Generated with " + $AppName)
        
        # Creates Request in cert store and stores private key
        # and.. somehow removes the request from the cert store in the next InstallResponse step?
        # What I know is that, in step by step debugging the cert request is placed in your cert store / requests
        # and if you don't do this step your private key isn't stored, resulting in a cert without key
        
        if ($SelfSigned) {
            $enroll.InstallResponse([int](0x2), $enroll.CreateRequest(), [int](0x1 <#XCN_CRYPT_STRING_BASE64#>), "")
        } else {
            # export request
            [String] $csr = $enroll.CreateRequest(0x1 <#XCN_CRYPT_STRING_BASE64#> -bor 0x40000000 <#XCN_CRYPT_STRING_NOCRLF#>).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            #[String] $csr = $request.RawData([int](0x1 <#XCN_CRYPT_STRING_BASE64#> -bor 0x40000000 <#XCN_CRYPT_STRING_NOCRLF#>)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            # push csr to CA and fetch certificate
            [String] $der = Sign-CSR -CSR $csr
            $enroll.InstallResponse([int](0x1 -bor 0x4), $der, [int](0x1), "")
        }


        # get the thumbprint of the new certificate, find the matching certificate in the cert store and return it
        [string] $thumbprint = [System.BitConverter]::ToString(([System.Security.Cryptography.SHA1Cng]::Create().ComputeHash([convert]::FromBase64String($enroll.Certificate(0x40000001))))).Replace('-', '')
        gci "Cert:\$($Context)\" -Recurse|? {
            $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate] -and
            (Split-Path $_.PSParentPath -Leaf) -ne "CA" -and
            $_.Thumbprint -eq $thumbprint
        }
    }
    function Renew-Certificate([System.Security.Cryptography.X509Certificates.X509Certificate2] $OldCert) {
        Write-Host " + Creating renewal request. Based on $($OldCert.Thumbprint)"
        
        [int] $InheritOptions = (
            0x00000020 -bor # InheritRenewalCertificateFlag
            0x00000080 -bor # InheritSubjectFlag
            0x00000100 -bor # InheritExtensionsFlag
            0x00000200      # InheritSubjectAltNameFlag
        )

        if (-not $RenewPrivateKey) { $InheritOptions = $InheritOptions -bor 0x00000003 } # InheritPrivateKey

        $request = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
        $request.InitializeFromCertificate($(
            if ($Context -eq [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine) {
                3 # ContextAdministratorForceMachine
            } else {
                1 # ContextUser
            }
        ), [System.Convert]::ToBase64String($OldCert.RawData), 1, $InheritOptions)

        if ($RenewPrivateKey) {
            # ToDo: do something...
            # does anyone has an idea?
        }

        # finish Pkcs10 request
        $request.Encode()

        # export request
        [String] $csr = $request.RawData([int](0x1 <#XCN_CRYPT_STRING_BASE64#> -bor 0x40000000 <#XCN_CRYPT_STRING_NOCRLF#>)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        
        # push csr to CA and fetch certificate
        [String] $der = Sign-CSR -CSR $csr
    
        # create enrollment class
        $enroll = New-Object -ComObject X509Enrollment.CX509Enrollment
        $enroll.InitializeFromRequest($request)
        
        $enroll.CertificateFriendlyName = Get-CertificateFriendlyName $Domain
        $enroll.CertificateDescription = ("Generated with " + $AppName)
        
        # Creates Request in cert store and stores private key
        $enroll.CreateRequest(1) | Out-Null

        $enroll.InstallResponse([int](0x1 -bor 0x4), $der, [int](0x1), "")

        [string] $thumbprint = [System.BitConverter]::ToString(([System.Security.Cryptography.SHA1Cng]::Create().ComputeHash([convert]::FromBase64String($enroll.Certificate(0x40000001))))).Replace('-', '')
        gci "Cert:\$($Context)\" -Recurse|? {$_ -is [System.Security.Cryptography.X509Certificates.X509Certificate] -and $_.Thumbprint -eq $thumbprint}
    }
    function Sign-CSR([String] $CSR) { [Convert]::ToBase64String((Invoke-SignedWebRequest -Uri $Directory.newOrder -Resource "new-cert" -Payload @{ "csr" = $CSR })) }
    
    [string] $VERSION = "0.3.0.1"
    # 1st level are huge api changes (i really don't know yet)
    # 2nd level are bigger internal changes - you may have to reassign your certificates in your ssl bindings
    # 3rd level are minor changes
    # 4th level -eq 0 tells you it is tested in production
    [string] $AppName = "WAT v$VERSION"
    [string] $UserAgent = "$AppName (ACME 1.0)"

    Write-Host "[$($AppName)]"

    # Fixing input parameter
    if ($ContactEmail -ne "" -and $Contact -eq $null) {
        $Contact = ("mailto:$($ContactEmail)")
    }

    if ($CA -eq $null) {
        $CA = if ($Staging) { "https://acme-staging.api.letsencrypt.org/directory" }
                       else { "https://acme-v01.api.letsencrypt.org/directory" }
    }
    
    switch ($ChallengeType) {
        'http-01' {
            if ($onChallenge -eq $null) {
                if (!$WellKnown.Exists) { die -Message "WellKnown directory doesn't exist, please create $WellKnown and set appropriate permissions." }

                $onChallenge = {
                    Param([String] $Domain, [String] $Token, [String] $KeyAuthorization)
                    $KeyAuthorization | Out-File -FilePath "$($WellKnown.FullName)\$($Token)" -Encoding ascii
                }
            }
            if ($onChallengeCleanup -eq $null) {
                $onChallengeCleanup = {
                    Param([String] $Domain, [String] $Token, [String] $KeyAuthorization, [String] $Status)
                    Remove-Item -Path "$($WellKnown.FullName)\$($Token)" -Force
                }
            }
        }
        'dns-01' {
            if ($onChallenge -eq $null) {
                Write-Host " ! Challenge type dns-01 should be used with an automated -onChallenge script for deployment."
                # manual dns challenge handling - for testing purposes only
                $onChallenge = {
                    Param([String] $Domain, [String] $FQDN, [String] $KeyAuthorization)
                    Write-Host " ! Please deploy a DNS TXT record under the name $($FQDN) with the following value:"
                    Write-Host "   $($KeyAuthorization)"
                    Write-Host " ! Once this is deployed, press Enter to continue"
                    Read-Host | Out-Null
                    if ((Get-Command -Verb Resolve -Noun DnsName) -ne $null) {
                        Write-Host "Testing DNS record"
                        while (($rec = Resolve-DnsName -Name $FQDN -Type TXT -Server 8.8.8.8, 8.8.4.4 -NoHostsFile -DnsOnly) -eq $null -or -not ($rec |? {$_.Text -eq $KeyAuthorization})) {
                            Write-Host -NoNewline "."
                            sleep -Seconds 3
                        }
                        Write-Host " "
                    }
                }
            }
            if ($onChallengeCleanup -eq $null) {
                $onChallengeCleanup = {
                    Param([String] $Domain, [String] $FQDN, [String] $KeyAuthorization, [String] $Status)
                    Write-Host " ! You can now remove the DNS TXT record $($FQDN) with the following value: $($KeyAuthorization)"
                }
            }
        }
        'tls-sni-01' {
            if ($onChallenge -eq $null) {
                Write-Host " ! Challenge type tls-sni-01 should be used with an automated -onChallenge script for deployment."
                # manual challenge handling - for testing purposes only
                $onChallenge = {
                    Param([String] $Domain, [String] $FQDN, [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert)
                    Write-Host " ! Please set up a SSL binding for FQDN $($FQDN) with the following Certificate:"
                    Write-Host "   FriendlyName: $($Cert.FriendlyName)"
                    Write-Host "   Thumbprint:   $($Cert.Thumbprint)"
                    Write-Host " ! Once this is deployed, press Enter to continue"
                    Read-Host | Out-Null
                }
            }
            if ($onChallengeCleanup -eq $null) {
                $onChallengeCleanup = {
                    Param([String] $Domain, [String] $FQDN, [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert, [String] $Status)
                    Write-Host " ! You can now remove the SSL binding with the FQDN $($FQDN)"
                }
            }
        }
    }

    # Building up a fixed environment/namespace to reach just one goal:
    #  Having only ONE AccountKey in this namespace
    # Based on following estimations
    #  1. Our AccountKey is stored in user context or local machine if script runs as SYSTEM (please don't do this)
    #  2. About every admin will throw that script into C:\scripts\ and will call it with different users contexts
    #  3. About every admin will not set $InternalAccountIdentifier
    #  4. Maybe something breaks and user dumps complete account directory, it shouldn't break the certificate enumeration in that namespace (even if AccountKey is lost we don't care)
    # To reduce mismatching in the Account directory and issued certificates we differentiate our namespace with following parameter:
    #  CA
    #    Are we in Staging or normal environment?
    #    The user can distinguish that on the folder level in his AccountDir
    #  InternalAccountIdentifier
    #    It's basically like a nice prefix
    #    It is shown in the file handle of the account config
    #  SID
    #    The SID of the active user context
    #    We don't show that - it would be just confusing
    #  Context [CurrentUser|LocalMachine]
    #    The selected destination of your issued certificates
    # For obfuscation we hash it with SHA256 and call it $AccHash
    # The $AccHash is used in following instances
    #  Part of the account config file name
    #  Suffix of the display name of every created Certificate
    #  Identifier of our AccountKey in the CNG provider
    
    [string] $AccHash = [System.BitConverter]::ToString(([System.Security.Cryptography.SHA256Cng]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes(
        "$($CA).$($InternalAccountIdentifier).$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value).$($Context.value__)")))).Replace('-', '')
    
    [System.IO.FileInfo] $AccountConfig = "$($AccountDir)\$($CA.Host)\$($InternalAccountIdentifier) - $($AccHash).json"
    
    # Loading our AccountKey - still Rsa
    [System.Security.Cryptography.RSA] $AccountKey = Get-RSACng -Name $AccHash
    
    # Load CA / Directory Informations
    [hashtable] $Directory = Get-ACMEDirectory $CA

    
    # Creating Directories
    if (-not $BaseDir.Exists) { die -Message "BaseDir does not exist: $BaseDir" }
    if (-not $CertDir.Exists) { New-Item -Type Directory -Path $CertDir.FullName -Force | Out-Null }
    if (-not ([System.IO.DirectoryInfo] "$($AccountDir)\$($CA.Host)").Exists) { New-Item -Type Directory -Path "$($AccountDir)\$($CA.Host)" -Force | Out-Null }
    
    Create-Lock
    Verify-ACMELicense
    Verify-ACMERegistration
}
Process {
    try {
        if ($Domains.Count -lt 1) {
            die -Message "No Domains found in parameter"
        }
    
        [String] $Domain = $Domains.Get(0)
        [String[]] $SAN = $Domains|? {$_ -ne $Domain}
    
        Write-Host ("Processing $Domain" + $(if ($SAN -ne $null) {" with alternative names: $SAN"}))
    
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert = if (Verify-Certificate -Domain $Domain -SAN $SAN) {
            # Cert didn't changed just return existing
            Get-LastCertificate -Domain $Domain -SAN $SAN
        } else {
            # Need to create new cert
            Sign-Domain -Domain $Domain -SAN $SAN
        }

        # Export
        if ($ExportPfx) { [System.IO.File]::WriteAllBytes("$($CertDir.FullName)\$($Domain).$($AccHash).pfx", $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $ExportPassword)) }
        if ($ExportPkcs12) { [System.IO.File]::WriteAllBytes("$($CertDir.FullName)\$($Domain).$($AccHash).p12", $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $ExportPassword)) }
        if ($ExportCert) { [System.IO.File]::WriteAllBytes("$($CertDir.FullName)\$($Domain).$($AccHash).crt", $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)) }
        if ($ExportPem) { $Cert | ConvertTo-PEM -Public -Private | Out-File -FilePath "$($CertDir.FullName)\$($Domain).$($AccHash).pem" -Encoding $ExportPemEncoding }
        if ($ExportPemCert) { $Cert | ConvertTo-PEM -Public | Out-File -FilePath "$($CertDir.FullName)\$($Domain).$($AccHash).cert.pem" -Encoding $ExportPemEncoding }
        if ($ExportPemKey) { $Cert | ConvertTo-PEM -Private | Out-File -FilePath "$($CertDir.FullName)\$($Domain).$($AccHash).key.pem" -Encoding $ExportPemEncoding }
        if ($ExportIssuerPem) { $Cert | Get-CertificateIssuerCertificate | ConvertTo-PEM -Public | Out-File -FilePath "$($CertDir.FullName)\$($Domain).$($AccHash).chain.pem" -Encoding $ExportPemEncoding }

        $Cert
    } catch { die -Exception $_ }
}
End {
    Remove-Lock
}
