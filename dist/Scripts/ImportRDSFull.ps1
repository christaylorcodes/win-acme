<#
.SYNOPSIS
Imports a cert from WACS renewal into the RD Gateway, RD Listener, RD WebAccess, RD Redirector and RD Connection Broker

.DESCRIPTION
Note that this script is intended to be run via the install script plugin from win-acme via the batch script wrapper. As such, we use positional parameters to avoid issues with using a dash in the cmd line. 

Proper information should be available here

https://github.com/PKISharp/win-acme/wiki/Install-Script

or more generally, here

https://github.com/PKISharp/win-acme/wiki/Example-Scripts

.PARAMETER NewCertThumbprint
The exact thumbprint of the cert to be imported. The script will copy this cert to the Personal store if not already there.

.PARAMETER RDCB
This parameter specifies the Remote Desktop Connection Broker (RD Connection Broker) server for a Remote Desktop deployment.

If you don't specify a value, the script uses the local computer's fully qualified domain name (FQDN).

.PARAMETER OldCertThumbprint
The exact thumbprint of the cert to be replaced. The script will delete this cert from the Personal store of the RD Connection Broker upon successful completion.

If you don't specify this value and the RD Connection Broker is not the local machine, the replaced cert will remain in the store.

.EXAMPLE 

ImportRDS.ps1 <certThumbprint> <ConnectionBroker.contoso.com> <oldCertThumbprint>

.NOTES
The private key of the letsencrypt certificate needs to be exportable. Set "PrivateKeyExportable" in settings.json to true.

In order for this script to update the cert on a remote RD Connection Broker, PowerShell on the RD Connection Broker needs to be configured to receive remote commands and the scheduled task needs to be configured to run with highest privileges as a domain user who is an admin on both the machine running the update and the RD Connection Broker.

#>

param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]$NewCertThumbprint,
    [Parameter(Position = 1, Mandatory = $false)]
    [string]$RDCB,
    [Parameter(Position = 2, Mandatory = $false)]
    [string]$OldCertThumbprint
)

Write-Output 'Local initialization'
$System = Get-CimInstance Win32_ComputerSystem
$LocalHost = '{0}.{1}' -f $System.DNSHostName, $System.Domain

try { Import-Module RemoteDesktopServices }
catch {
    Write-Output "Could not load Remote Desktop Services module on $($LocalHost)"
    Write-Output "Error: $($_)"
    # Looks like you check for exit codes
    # Any info on codes I should use?
    # Seems any non 0 exit code cancels the renewal and will retry on next schedule?
    Exit 1
}

try {
    $RDS = Get-RDServer $RDCB -ErrorAction Stop
    Write-Output "RDCB found, detected roles: $($RDS.Roles -join ', ')"
}
catch {
    Write-Output "Unable to find RDCB: $($RDCB)"
    Write-Output "Error: $($_)"
    Exit 1
}

$CertInStore = Get-ChildItem -Path Cert:\LocalMachine\My -Recurse | Where-Object { 
    $_.thumbprint -eq $NewCertThumbprint 
} | Sort-Object -Descending | Select-Object -First 1
if (!$CertInStore) {
    Write-Output 'Cert thumbprint not found in the My cert store... have you specified --certificatestore My?'
    Exit 1
}

if (!$PSBoundParameters.ContainsKey('RDCB')) { $RDCB = $LocalHost } 
try {
    if ($RDCB -ne $LocalHost) { 
        Write-Output "Remote initialization: $($RDCB)"
        $RDCBPS = New-PSSession -ComputerName $RDCB 
    }
}
catch {
    Write-Output 'Could not create remote PowerShell Session to Remote Desktop Connection Broker'
    Write-Output "Error: $($_)"
    Exit 1
}

if ($RDCB -ne $LocalHost) {
    try { Invoke-Command -Session $RDCBPS { Import-Module RemoteDesktopServices } }
    catch {
        Write-Output "Could not load Remote Desktop Services module on $($RDCB)"
        Write-Output "Error: $($_)"
        Exit 1
    }
}

try {
    Write-Output 'Exporting certificate'
    # Plans to support powershell 7+?
    # This assembly is not available
    Add-Type -AssemblyName 'System.Web'
    $tempPasswordPfx = [System.Web.Security.Membership]::GeneratePassword(10, 5) | ConvertTo-SecureString -Force -AsPlainText
    $tempPfxPath = New-TemporaryFile | Rename-Item -PassThru -NewName { $_.name -Replace '\.tmp$', '.pfx' }
    $ExportSplat = @{
        Cert         = $CertInStore 
        FilePath     = $tempPfxPath
        Force        = $true
        NoProperties = $true
        Password     = $tempPasswordPfx
    }
    $null = Export-PfxCertificate @ExportSplat
}
catch {
    Write-Output 'Could not export temporary certificate, certificates not set.'
    Write-Output "Error: $($_)"
    Exit 1
}

try {
    $Existing = Get-RDCertificate -ConnectionBroker $RDCB -ErrorAction Stop
    Write-Output 'Existing certificates:'
    Write-Output $Existing | Out-String
}
catch {
    Write-Output "Unable to get a list of certificates from: $($RDCB)"
    Write-Output "Error: $($_)"
    Exit 1
}

Write-Output 'Updating certificates'
$Issue = $false
foreach ($Role in $Existing.Role) {
    try {
        $SetSplat = @{
            Role             = $Role
            ImportPath       = $tempPfxPath
            Password         = $tempPasswordPfx
            ConnectionBroker = $RDCB
            Force            = $true
            ErrorAction      = 'Stop'
        }
        Set-RDCertificate @SetSplat
        Write-Output "$($Role) Certificate for RDS was set"
    } 
    catch {
        Write-Output "$($Role) Certificate for RDS was not set"
        Write-Output "Error: $($_)"
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
    if ((Get-Command -Module RDWebClientManagement | Measure-Object).Count -eq 0) {
        Write-Output 'RDWebClient not installed, skipping'
    }
    else {
        Remove-RDWebClientBrokerCert
        Import-RDWebClientBrokerCert -Path $tempPfxPath -Password $tempPasswordPfx
        Write-Output 'RDWebClient Certificate for RDS was set'
    }
}
catch {
    Write-Output 'RDWebClient Certificate for RDS was not set'
    Write-Output "Error: $($_)"
    # Same, not sure it is beneficial to terminate the script at this point
    $Issue = $true
}

finally {
    Write-Output 'Cleaning up'
    Remove-Item -Path $tempPfxPath
    if ($RDCB -ne $LocalHost) {
        if ($PSBoundParameters.ContainsKey('OldCertThumbprint')) {
            $RemoteCert = Invoke-Command -Session $RDCBPS { 
                Get-ChildItem -Path Cert:\LocalMachine\My -Recurse | Where-Object {
                    $_.thumbprint -eq $Using:NewCertThumbprint 
                } 
            }
            if ($RemoteCert -and $RemoteCert.thumbprint -ne $OldCertThumbprint) {
                Invoke-Command -Session $RDCBPS {
                    Get-ChildItem -Path Cert:\LocalMachine\My -Recurse | Where-Object { 
                        $_.thumbprint -eq $Using:OldCertThumbprint 
                    } | Remove-Item
                }
            }
            else { Write-Output 'Remote cert not changed, skipping deletion.' }
        } 
        Remove-PSSession $RDCBPS
    }
    if ($Issue) { Exit 1 }
}
