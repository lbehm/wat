<#
.SYNOPSIS
WAT Integration: VegaDNS

.DESCRIPTION
This is a implementation script for handling dns-01 challenges with the old VegaDNS php interface.

1. Load this integration script with defined BaseURI and Credentials to access the VegaDNS control panel
2. Define onChallenge and onChallengeCleanup for WAT by using the functions Add-VDNSRecord, Get-VDNSRecord and Remove-VDNSRecord
3. Execute wat.ps1 with the parameter Domains, ChallengeType (dns-01), onChallenge and onChallengeCleanup

.EXAMPLE
. .\Integrations\dns-VegaDNS.ps1 -DefaultBaseURI "https://your.dns.provider.example/vegadns/index.php" -DefaultCredential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("username", "password"))
& .\wat.ps1 -Domains my.domain.to.verify.example.com -AcceptTerms -Staging -ChallengeType dns-01 -onChallenge {
    Param([string] $Domain, [string] $FQDN, [string] $KeyAuthorization)
    Add-VDNSRecord -Zone (($FQDN -split '\.'|select -Last 2) -join '.') -Name $FQDN -Address $KeyAuthorization -Type 'TXT' -TTL 10
} -onChallengeCleanup {
    Param([String] $Domain, [String] $FQDN, [String] $KeyAuthorization, [String] $Status)
    Get-VDNSRecord -Zone (($FQDN -split '\.'|select -Last 2) -join '.') |? {$_.Name -eq $FQDN -and $_.Type -eq 'TXT' -and $_.Address -eq $KeyAuthorization} | Remove-VDNSRecord
}

#>
Param (
    # The Url to the VegaDNS control panel (like "https://your.dns.provider.example/vegadns/index.php")
    [Parameter(Mandatory)]
    [uri] $DefaultBaseURI,

    # Credentials to access the VegaDNS control panel
    [Parameter(Mandatory)]
    [pscredential] $DefaultCredential
)
function Get-VDNSSession ([uri] $BaseURI = $DefaultBaseURI, [pscredential] $Credential = $DefaultCredential) {
    [string] $VDNSSessid = ([string]((Invoke-WebRequest -UseBasicParsing -Uri $BaseURI).Content.Split("`n")|? {$_ -like '*<input *' -and $_ -like '* name="VDNSSessid" *'}|select -First 1)).Trim('<>') -split ' '|? {$_ -like 'value="*'}|% {($_ -split '=')[1].Trim('"')}
    Invoke-WebRequest -UseBasicParsing -Uri $($BaseURI) -Method Post -Body @{
        VDNSSessid = $VDNSSessid;
        state = "login";
        email = $Credential.UserName;
        password = $Credential.GetNetworkCredential().Password;
    } | Out-Null
    New-Object -TypeName PSObject |
        Add-Member -MemberType NoteProperty -Name SessionId -Value $VDNSSessid -PassThru |
        Add-Member -MemberType NoteProperty -Name BaseURI -Value $BaseURI -PassThru
}
function Get-VDNSRecord ([string] $Zone, [psobject] $Session = (Get-VDNSSession)) {
    $r = Invoke-WebRequest -UseBasicParsing -Uri $Session.BaseURI -Method Post -Body @{
        VDNSSessid = $Session.SessionId;
        domain = $Zone;
        state = "logged_in";
        mode = "records";
        page = "all";
        sortfield = "host";
        sortway = "asc";
        search = "";
    }
    (($r.Content -split '</colgroup>')[1] -split '</table>')[0] -split '</tr>'|select -Skip 1|? {$_.Trim() -ne ''}|% {
        $recordId = ($_ -split "`n")|? {$_ -like '*record_mode=delete&*'}|% {$_ -split '&'|? {$_ -like 'record_id=*'}|% {$_ -split '='}}|select -last 1
        $data = (($_ -split ">`n")|? {$_ -like '*<td *'} |% {$_ -replace '^.*>([^<>]+)<.*$', '$1'}|? {$_ -notlike '*<td *'})
        $record = New-Object -TypeName PSObject |
            Add-Member -MemberType NoteProperty -Name Zone -Value $Zone -PassThru |
            Add-Member -MemberType NoteProperty -Name RecordId -Value $recordId -PassThru |
            Add-Member -MemberType NoteProperty -Name Session -Value $Session -PassThru |
            Add-Member -MemberType NoteProperty -Name Name -Value $data[0] -PassThru |
            Add-Member -MemberType NoteProperty -Name Type -Value $data[1] -PassThru |
            Add-Member -MemberType NoteProperty -Name Address -Value $data[2] -PassThru |
            Add-Member -MemberType NoteProperty -Name TTL -Value $data[6] -PassThru
        switch ($data[1]) {
            "MX" { Add-Member -InputObject $record -MemberType NoteProperty -Name Priority -Value $data[3] }
            "SRV" {
                Add-Member -InputObject $record -MemberType NoteProperty -Name Priority -Value $data[3]
                Add-Member -InputObject $record -MemberType NoteProperty -Name Weight -Value $data[4]
                Add-Member -InputObject $record -MemberType NoteProperty -Name Port -Value $data[5]
            }
        }
        $record
    }
}
function Add-VDNSRecord ([string] $Zone, [string] $Name, [string] $Type = "A", [string] $Address = "", [int] $Distance = 0, [string] $Weight = "", [string] $Port = "", [int] $TTL=3600, [psobject] $Session = (Get-VDNSSession)) {
    Invoke-WebRequest -UseBasicParsing -Uri $Session.BaseURI -Method Post -Body @{
        VDNSSessid = $Session.SessionId;
        domain = $Zone;
        state = "logged_in";
        mode = "records";
        record_mode = "add_record_now";
        name = $Name;
        type = $Type;
        address = $Address;
        distance = $Distance;
        weight = $Weight;
        port = $Port;
        ttl = $TTL;
    } | Out-Null
}
function Remove-VDNSRecord ([Parameter(ValueFromPipelineByPropertyName)][string] $Zone, [Parameter(ValueFromPipelineByPropertyName)][int] $RecordId, [Parameter(ValueFromPipelineByPropertyName)][psobject] $Session = (Get-VDNSSession)) {
    Invoke-WebRequest -UseBasicParsing -Uri $Session.BaseURI -Method Post -Body @{
        VDNSSessid = $Session.SessionId;
        domain = $Zone;
        state = "logged_in";
        mode = "records";
        record_mode = "delete_now";
        record_id = $RecordId;
    } | Out-Null
}
