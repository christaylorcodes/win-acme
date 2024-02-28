<#
.SYNOPSIS
Imports a cert from WIN-ACME renewal into all roles listed by Get-RDCertificate and RDWebClient if present.

.DESCRIPTION
Note that this script is intended to be run via the install script plugin from win-acme. As such, we use positional parameters to avoid issues with using a dash in the cmd line. 

.PARAMETER CacheFile
The temporary path to the certificate created by the renewal.

.PARAMETER CachePassword
The password of the temp certificate created by the renewal.

.PARAMETER RDCB
This parameter specifies the Remote Desktop Connection Broker (RD Connection Broker) server for a Remote Desktop deployment.

If you don't specify a value, the script uses the local computer's fully qualified domain name (FQDN).

.PARAMETER OldCertThumbprint
The exact thumbprint of the cert to be replaced. The script will delete this cert from the Personal store of the RD Connection Broker upon successful completion.

If you don't specify this value and the RD Connection Broker is not the local machine, the replaced cert will remain in the store.

.EXAMPLE 

ImportRDSFullv2.ps1 {CachePassword} {CacheFile}

Import the cert to all the local RD roles.

.EXAMPLE 

ImportRDSFullv2.ps1 {CachePassword} {CacheFile} 'ConnectionBroker.contoso.com' {OldCertThumbprint}

Import the cert to all RD roles of a remote connection broker and remove the old cert from the store.

.NOTES
In order for this script to update the cert on a remote RD Connection Broker, PowerShell on the RD Connection Broker needs to be configured to receive remote commands and the scheduled task needs to be configured to run with highest privileges as a domain user who is an admin on both the machine running the update and the RD Connection Broker.

#>

param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]$CachePassword,
    [Parameter(Position = 1, Mandatory = $true)]
    [string]$CacheFile,
    [Parameter(Position = 2, Mandatory = $false)]
    [string]$RDCB,
    [Parameter(Position = 3, Mandatory = $false)]
    [string]$OldCertThumbprint
)

Write-Output 'Starting RDS Certificate Import'

$Password = $CachePassword | ConvertTo-SecureString -Force -AsPlainText
Remove-Variable CachePassword

try { Get-Module @('RemoteDesktopServices', 'RemoteDesktop') -ListAvailable | Import-Module }
catch {
    Write-Output "Could not load Remote Desktop Services module on $($LocalHost)"
    Write-Output "Error: $($_)"
    # Looks like you check for exit codes
    # Any info on codes I should use?
    # Seems any non 0 exit code cancels the renewal and will retry on next schedule?
    Exit 1
}

$System = Get-CimInstance Win32_ComputerSystem
$LocalHost = '{0}.{1}' -f $System.DNSHostName, $System.Domain
if (!$PSBoundParameters.ContainsKey('RDCB')) { $RDCB = $LocalHost } 

if ($RDCB -ne $LocalHost) {
    try {
        Write-Output "Remote initialization: $($RDCB)"
        $RDCBPS = New-PSSession -ComputerName $RDCB 

    }
    catch {
        Write-Output 'Could not create remote PowerShell Session to Remote Desktop Connection Broker'
        Write-Output "Error: $($_)"
        Exit 1
    }

    try { Invoke-Command -Session $RDCBPS { Import-Module RemoteDesktopServices } }
    catch {
        Write-Output "Could not load Remote Desktop Services module on $($RDCB)"
        Write-Output "Error: $($_)"
        Exit 1
    }
}

try {
    $null = Get-RDServer $RDCB -ErrorAction Stop
    Write-Output "RDCB: $RDCB"
}
catch {
    Write-Output "Unable to find RDCB: $($RDCB)"
    Write-Output "Error: $($_)"
    Exit 1
}

try {
    $Existing = Get-RDCertificate -ConnectionBroker $RDCB -ErrorAction Stop
}
catch {
    Write-Output "Unable to get a list of certificates from: $($RDCB)"
    Write-Output "Error: $($_)"
    Exit 1
}

Write-Output 'Updating certificates:'
$Issue = $false
$Padding = ($Existing.Role.ForEach{ $_.toString().Length } | Measure-Object -Maximum).Maximum + 1
foreach ($Role in $Existing.Role) {
    try {
        $SetSplat = @{
            Role             = $Role
            ImportPath       = $CacheFile
            Password         = $Password
            ConnectionBroker = $RDCB
            Force            = $true
            ErrorAction      = 'Stop'
        }
        Set-RDCertificate @SetSplat
        Write-Output " $("${Role}".PadRight($Padding,' ')): SUCCESS"
    } 
    catch {
        # There is always an issue with these roles failing due to restart timeout
        if ($Role -in @('RDGateway', 'RDWebAccess')) {
            $null = Start-Service 'TSGateway' -ErrorAction SilentlyContinue
            $Service = Get-Service 'TSGateway'
            if ($Service.Status -eq 'Running') { 
                Write-Output " $("${Role}".PadRight($Padding,' ')): SUCCESS"
                continue 
            }
        }
        Write-Output " $("${Role}".PadRight($Padding,' ')): ERROR"
        Write-Output "- $($_)"
        # Not sure it is good to terminate the script once import has started
        # Import to as many roles as possible is better than stopping at first error?
        # Looks like giving an exit code will cancel the renewal and try again
        # Maybe it is better to throw an exit code and try again?
        $Issue = $true
    }
}

# Configure Certificate that RDWebClient checks for
# Warning: browser caching can keep the old Certificate for a long time!
try {
    $Role = 'RDWebClient'
    if ((Get-Command -Module RDWebClientManagement | Measure-Object).Count -eq 0) {
        Write-Output " $("${Role}".PadRight($Padding,' ')): SKIPPING"
    }
    else {
        Remove-RDWebClientBrokerCert
        Import-RDWebClientBrokerCert -Path $CacheFile -Password $Password
        Write-Output " $("${Role}".PadRight($Padding,' ')): SUCCESS"
    }
}
catch {
    Write-Output " $("${Role}".PadRight($Padding,' ')): ERROR"
    Write-Output "- $($_)"
    # Same, not sure it is beneficial to terminate the script at this point
    $Issue = $true
}

try {
    $Existing = Get-RDCertificate -ConnectionBroker $RDCB -ErrorAction Stop
    Write-Output ' '
    Write-Output 'Certificate Status:'
    Write-Output $Existing | Out-String
}
catch {
    Write-Output "Unable to get a list of certificates from: $($RDCB)"
    Write-Output "Error: $($_)"
    $Issue = $true
}

finally {    
    # Wait to throw until the end?
    # Seems it is better to try to apply to everything?
    if ($Issue) { Exit 1 }

    if ($RDCB -ne $LocalHost) {
        Write-Output "Removing old cert from: $RDCB"
        if ($PSBoundParameters.ContainsKey('OldCertThumbprint')) {
            Invoke-Command -Session $RDCBPS {
                Get-ChildItem -Path Cert:\LocalMachine\My -Recurse | Where-Object { 
                    $_.thumbprint -eq $Using:OldCertThumbprint 
                } | Remove-Item
            }
        } 
        Remove-PSSession $RDCBPS
    }
    Write-Output 'Success'
}
