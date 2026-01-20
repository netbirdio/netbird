#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Bootstraps AD CS with NetBirdMachine template for Lab environment
.DESCRIPTION
    - Installs AD CS Enterprise Root CA (if not installed)
    - Creates NetBirdMachine certificate template via ADSI
    - Adds template to CA
    - Configures Auto-Enrollment GPO
    - Restricts RPC port range for firewall compatibility
.PARAMETER CAName
    Common Name for the CA (default: TEST-CA)
.PARAMETER Domain
    Domain name (default: test.local)
.EXAMPLE
    .\setup-lab-ca.ps1 -CAName "CORP-CA" -Domain "corp.local"
#>

param(
    [string]$CAName = "TEST-CA",
    [string]$Domain = "test.local"
)

$ErrorActionPreference = "Stop"

Write-Host "=== NetBird Lab CA Bootstrap ===" -ForegroundColor Cyan
Write-Host "CA Name: $CAName" -ForegroundColor Gray
Write-Host "Domain:  $Domain" -ForegroundColor Gray
Write-Host ""

# Helper function
function Test-ADCSInstalled {
    $svc = Get-Service CertSvc -ErrorAction SilentlyContinue
    return ($null -ne $svc)
}

# =============================================================================
# Step 1: Install AD CS Role
# =============================================================================
Write-Host "[1/6] Checking AD CS Installation..." -ForegroundColor Yellow

if (Test-ADCSInstalled) {
    Write-Host "  AD CS already installed, skipping." -ForegroundColor Green
} else {
    Write-Host "  Installing AD CS role..." -ForegroundColor Gray
    Install-WindowsFeature -Name AD-Certificate, ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools

    Write-Host "  Configuring CA: $CAName..." -ForegroundColor Gray
    Install-AdcsCertificationAuthority `
        -CAType EnterpriseRootCA `
        -CACommonName $CAName `
        -KeyLength 4096 `
        -HashAlgorithmName SHA256 `
        -ValidityPeriod Years `
        -ValidityPeriodUnits 10 `
        -Force

    Write-Host "  AD CS installed and configured." -ForegroundColor Green
}

# =============================================================================
# Step 2: Restrict RPC Port Range (for firewall rules)
# =============================================================================
Write-Host "[2/6] Configuring RPC Port Range (5000-5100)..." -ForegroundColor Yellow

$currentPorts = netsh int ipv4 show dynamicport tcp
if ($currentPorts -match "Start Port\s*:\s*5000") {
    Write-Host "  RPC range already configured." -ForegroundColor Green
} else {
    netsh int ipv4 set dynamicport tcp start=5000 num=100
    netsh int ipv4 set dynamicport udp start=5000 num=100
    Write-Host "  RPC range set to 5000-5100." -ForegroundColor Green
}

# =============================================================================
# Step 3: Create NetBirdMachine Template via ADSI
# =============================================================================
Write-Host "[3/6] Creating NetBirdMachine Certificate Template..." -ForegroundColor Yellow

$configContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$templateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configContext"

# Check if template already exists
$existingTemplate = [ADSI]"LDAP://CN=NetBirdMachine,$templateContainer"
if ($existingTemplate.Name) {
    Write-Host "  Template 'NetBirdMachine' already exists." -ForegroundColor Green
} else {
    Write-Host "  Creating template from 'Machine' base..." -ForegroundColor Gray

    # Get Machine template as base
    $machineTemplate = [ADSI]"LDAP://CN=Machine,$templateContainer"

    # Create new template
    $container = [ADSI]"LDAP://$templateContainer"
    $newTemplate = $container.Create("pKICertificateTemplate", "CN=NetBirdMachine")

    # Copy base properties from Machine template
    $newTemplate.Put("displayName", "NetBird Machine Authentication")

    # Generate unique OID (simplified - production should use proper OID generation)
    $oidBase = "1.3.6.1.4.1.311.21.8"
    $random = Get-Random -Minimum 1000000 -Maximum 9999999
    $templateOID = "$oidBase.$random.1"
    $newTemplate.Put("msPKI-Cert-Template-OID", $templateOID)

    # Template flags
    # msPKI-Certificate-Name-Flag: 0x18000000 = SUBJECT_ALT_REQUIRE_DNS | SUBJECT_ALT_REQUIRE_DOMAIN_DNS
    $newTemplate.Put("msPKI-Certificate-Name-Flag", 402653184)

    # msPKI-Enrollment-Flag: 32 = AUTO_ENROLLMENT
    $newTemplate.Put("msPKI-Enrollment-Flag", 32)

    # msPKI-Private-Key-Flag: 0 = NOT exportable
    $newTemplate.Put("msPKI-Private-Key-Flag", 0)

    # msPKI-Minimal-Key-Size: 2048
    $newTemplate.Put("msPKI-Minimal-Key-Size", 2048)

    # pKIMaxIssuingDepth: 0
    $newTemplate.Put("pKIMaxIssuingDepth", 0)

    # pKIDefaultKeySpec: 1 (AT_KEYEXCHANGE)
    $newTemplate.Put("pKIDefaultKeySpec", 1)

    # Validity: 1 year (in 100-nanosecond intervals)
    $validity = [byte[]]@(0x00, 0x40, 0x1F, 0xD4, 0xB0, 0xCE, 0xFE, 0xFF)  # 1 year
    $newTemplate.Put("pKIExpirationPeriod", $validity)

    # Renewal: 6 weeks
    $renewal = [byte[]]@(0x00, 0x80, 0xA6, 0x0A, 0xFF, 0xDE, 0xFF, 0xFF)  # 6 weeks
    $newTemplate.Put("pKIOverlapPeriod", $renewal)

    # EKU: Client Auth + Server Auth
    $newTemplate.PutEx(2, "pKIExtendedKeyUsage", @("1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"))

    # Key Usage: Digital Signature + Key Encipherment
    $newTemplate.Put("pKIKeyUsage", [byte[]]@(0xA0, 0x00))

    # Schema version
    $newTemplate.Put("msPKI-Template-Schema-Version", 2)
    $newTemplate.Put("msPKI-Template-Minor-Revision", 1)
    $newTemplate.Put("revision", 100)

    # Flags
    $newTemplate.Put("flags", 131680)  # CT_FLAG_PUBLISH_TO_DS | CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE

    $newTemplate.SetInfo()
    Write-Host "  Template 'NetBirdMachine' created." -ForegroundColor Green

    # Set permissions: Domain Computers can Enroll and AutoEnroll
    Write-Host "  Setting template permissions..." -ForegroundColor Gray
    $template = [ADSI]"LDAP://CN=NetBirdMachine,$templateContainer"
    $domainSID = (Get-ADDomain).DomainSID
    $domainComputersSID = New-Object System.Security.Principal.SecurityIdentifier("$domainSID-515")

    # Create ACE for Enroll (ExtendedRight)
    $enrollGUID = [GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
    $aceEnroll = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $domainComputersSID,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $enrollGUID
    )

    # Create ACE for AutoEnroll (ExtendedRight)
    $autoEnrollGUID = [GUID]"a05b8cc2-17bc-4802-a710-e7c15ab866a2"
    $aceAutoEnroll = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $domainComputersSID,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $autoEnrollGUID
    )

    $template.ObjectSecurity.AddAccessRule($aceEnroll)
    $template.ObjectSecurity.AddAccessRule($aceAutoEnroll)
    $template.CommitChanges()
    Write-Host "  Permissions set for Domain Computers." -ForegroundColor Green
}

# =============================================================================
# Step 4: Add Template to CA
# =============================================================================
Write-Host "[4/6] Adding Template to CA..." -ForegroundColor Yellow

$caTemplates = certutil -CATemplates 2>&1
if ($caTemplates -match "NetBirdMachine") {
    Write-Host "  Template already published to CA." -ForegroundColor Green
} else {
    certutil -SetCATemplates +NetBirdMachine
    Write-Host "  Template added to CA." -ForegroundColor Green
}

# =============================================================================
# Step 5: Create Auto-Enrollment GPO
# =============================================================================
Write-Host "[5/6] Creating Auto-Enrollment GPO..." -ForegroundColor Yellow

$gpoName = "NetBird-AutoEnrollment"
$existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

if ($existingGPO) {
    Write-Host "  GPO '$gpoName' already exists." -ForegroundColor Green
} else {
    $gpo = New-GPO -Name $gpoName

    # Link to domain root
    $domainDN = (Get-ADDomain).DistinguishedName
    New-GPLink -Name $gpoName -Target $domainDN -LinkEnabled Yes

    Write-Host "  GPO created and linked to $domainDN" -ForegroundColor Green
}

# Set Auto-Enrollment registry via GPO
$gpoPath = "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment"
Set-GPRegistryValue -Name $gpoName -Key $gpoPath -ValueName "AEPolicy" -Type DWord -Value 7
Set-GPRegistryValue -Name $gpoName -Key $gpoPath -ValueName "OfflineExpirationPercent" -Type DWord -Value 10
Set-GPRegistryValue -Name $gpoName -Key $gpoPath -ValueName "OfflineExpirationStoreNames" -Type String -Value "MY"

Write-Host "  Auto-Enrollment settings configured (AEPolicy=7)." -ForegroundColor Green

# =============================================================================
# Step 6: Configure DCOM for Remote Enrollment
# =============================================================================
Write-Host "[6/6] Configuring DCOM Access..." -ForegroundColor Yellow

# Add Domain Computers to Certificate Service DCOM Access
$group = [ADSI]"WinNT://./Certificate Service DCOM Access,group"
$domainComputersGroup = "WinNT://$($Domain.Split('.')[0])/Domain Computers,group"

try {
    $group.Add($domainComputersGroup)
    Write-Host "  Domain Computers added to DCOM Access group." -ForegroundColor Green
} catch {
    if ($_.Exception.Message -match "already a member") {
        Write-Host "  Domain Computers already in DCOM Access group." -ForegroundColor Green
    } else {
        Write-Host "  Warning: Could not add to DCOM group: $_" -ForegroundColor Yellow
    }
}

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "=== Bootstrap Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Run 'gpupdate /force' on domain controllers"
Write-Host "2. Domain-join a test client"
Write-Host "3. Run test-client-enrollment.ps1 on the client"
Write-Host ""
Write-Host "Verification:" -ForegroundColor Cyan
Write-Host "  certutil -CATemplates | findstr NetBird"
Write-Host "  Get-GPO -Name 'NetBird-AutoEnrollment'"
