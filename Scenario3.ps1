
$ErrorActionPreference = "Stop"
$location = "westus"
$spnPath = "$PWD\AzureRT-spn.json"
$spn2Path = "$PWD\ApplicationGuard.json"
$spName = "AzureRTSP"
$spnName2 = "Application Guard"
$keyVaultName = "TBHFinanceVault"
$managedKeyVaultName = "TBHCurrencyVault"
$containerName = "tbh-files"
$blobFilePath = "$env:TEMP\youfoundme.txt"
$blobContent = "You found me"
$TBHResourceGroups = @("TBH-HR", "TBH-Engineering", "TBH-Finance")
$ProjectFolder = "$PWD"
$FunctionAppName = "render"
$SqlServerName = "financesqlsrvr001"
$SqlAdminUser = "sqladmin"


# ---------------- Helper Functions ----------------
function Invoke-Retry {
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 5,
        [string]$ActionName = "Operation"
    )
    $attempt = 0
    do {
        try {
            $result = & $ScriptBlock
            Write-Host "[+] $ActionName succeeded on attempt $($attempt + 1)."
            return $result
        } catch {
            if ($_.Exception.Message -match "Conflict") {
                Write-Host "[i] $ActionName encountered a 'Conflict' error, which indicates it already exists. Continuing..."
                return $null
            }
            $attempt++
            Write-Warning "[!] $ActionName failed on attempt $attempt. Error: $($_.Exception.Message)"
            if ($attempt -lt $MaxAttempts) {
                Write-Host "Retrying $ActionName in $DelaySeconds seconds..."
                Start-Sleep -Seconds $DelaySeconds
            } else {
                Write-Warning "[✗] $ActionName failed after $MaxAttempts attempts."
                throw
            }
        }
    } while ($attempt -lt $MaxAttempts)
}

# ---------------- Login and Context ----------------
function Login-IfNeeded {
    Write-Host "[*] Checking Az PowerShell login status..."
    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        Write-Host "[*] Logging in to Azure via Az PowerShell..."
        Connect-AzAccount | Out-Null
    }

    Write-Host "[*] Checking Microsoft Graph login status..."
    try {
        $mgContext = Get-MgContext -ErrorAction Stop
    } catch {
        $mgContext = $null
    }
    if (-not $mgContext) {
        Write-Host "[*] Logging in to Microsoft Graph..."
        Connect-MgGraph -NoWelcome -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.ReadWrite.All", "Group.ReadWrite.All", "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "Policy.ReadWrite.ApplicationConfiguration", "Organization.Read.All", "DelegatedPermissionGrant.ReadWrite.All", "Directory.AccessAsUser.All" | Out-Null
    }
}

function Get-ContextInfo {
    Write-Host "[*] Getting subscription and tenant information..."
    $context = Get-AzContext
    Start-Sleep -Seconds 2
    return @{ SubId = $context.Subscription.Id; Tenant = $context.Tenant.Id }
}


# --------------- Build Linux VM --------------------

function Create-LinuxVM {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [string]$Location,
        [string]$VMName = "TBH-WebPage"
    )

    Write-Host "[*] Creating Linux VM: $VMName in resource group $ResourceGroupName..." -ForegroundColor Cyan

    $username = "bobsmith"
    $password = "SpR!ng2025_Cmplx" | ConvertTo-SecureString -AsPlainText -Force
    $vmCredential = New-Object System.Management.Automation.PSCredential($username, $password)

    # Define VNet and Subnet
    $vnetName = "$VMName-VNet"
    $subnetName = "$VMName-Subnet"

    # Check or create VNet + Subnet
    $vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $vnet) {
        $vnet = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Location $Location -Name $vnetName -AddressPrefix "10.2.0.0/16"
        $vnet = Add-AzVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix "10.2.0.0/24" -VirtualNetwork $vnet
        $vnet | Set-AzVirtualNetwork
        Write-Host "[+] Created new VNet $vnetName" -ForegroundColor Green
    } else {
        Write-Host "[i] VNet $vnetName already exists. Reusing it..." -ForegroundColor Yellow
    }

    # Refresh VNet object
    $vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $ResourceGroupName

    # Check or create Public IP
    $pipName = "$VMName-PIP"
    $pip = Get-AzPublicIpAddress -Name $pipName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $pip) {
        $pip = New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Location $Location -Name $pipName -AllocationMethod Static
    } else {
        Write-Host "[i] Public IP $pipName already exists. Reusing it..." -ForegroundColor Yellow
    }

    # Create the VM (Debian 11, password auth, open port 80)
    Invoke-Retry -ScriptBlock {
        New-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Location $Location -Image "Debian11" -Size "Standard_B2s" -Credential $vmCredential -PublicIpAddressName $pipName -OpenPorts 80, 8080
    } -ActionName "Deploy VM $VMName"

    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
    Write-Host "[+] Debian Linux VM '$VMName' deployed successfully." -ForegroundColor Green
	
	# Install Apache and PHP
	Write-Host "[+] Installing necessary packages" -ForegroundColor Cyan
	Start-Sleep -Seconds 45
	# For some reason the one-liner isn't working so multiple lines
	Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString 'apt install apache2 -y ' # -y && systemctl enable apache2 && systemctl start apache2 && apt install php -y && apt install libapache2-mod-php -y'
	Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString 'systemctl enable apache2'
	Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString 'systemctl start apache2'
	Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString 'apt install php -y'
	Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString 'apt install libapache2-mod-php -y'
	
	Write-Host "[+] Building vulnerable PHP file" -ForegroundColor Cyan
	
	# Create a PHP file that allows us to RCE
$script = @'
sudo bash -c "cat > /var/www/html/info.php" << 'EOF'
<?php
// RCE Demo - TRAINING ONLY - DO NOT DEPLOY
// Access this inside your isolated lab network only!

if (isset($_GET["cmd"])) {
    // ⚠ Vulnerable: directly passes user input to shell
    $output = shell_exec($_GET["cmd"]);
    echo "<pre>$output</pre>";
} else {
    echo "<h2>RCE Demo</h2>";
    echo "<p>Usage: ?cmd=whoami</p>";
}
?>
EOF
'@
	Invoke-AzVMRunCommand -ResourceGroupName "TBH-Engineering" -Name $VMName -CommandId 'RunShellScript' -ScriptString $script
	
	Write-Host "[+] Building Index File..." -ForegroundColor Cyan
	# Create HTML that lists the HTML folder just cause...
	Invoke-AzVMRunCommand -ResourceGroupName "TBH-Engineering" -Name $VMName -CommandId 'RunShellScript' -ScriptString @'
echo "<html><head><title>Directory Listing</title></head><body><h1>Contents of /var/www/html</h1><pre>$(ls -lh /var/www/html)</pre></body></html>" | sudo tee /var/www/html/index.html
'@
	# Restart Apache
	Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString 'service apache2 restart'
	
	Write-Host "[+] Adding Privesc Vulnerability..." -ForegroundColor Cyan
	# Build vulnerable SUID
	Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString 'chmod u+s /usr/bin/find'
	
	# Add File with Users Credentials

$userscreds = @'
sudo bash -c "cat > /root/notes.txt" << 'EOF'
Note:
	Please make sure we chage Erins Password as he was in charge of the Applications
		Gracias canijo

User: erin.brown@tropicanabayhotels.com
Credentials: Br0wn3r!n2025
EOF
'@
	Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString $userscreds
	
	# Get Public IP
	Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name "$VMName-PIP" | Select-Object IpAddress
	
	# Setup dnsn
	# Make this randon so it doesn't take forever to tie the DNS to the IP
	$dnsLabel = "tbh-" + -join ((48..57) + (97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_})
	$pipName = "$VMName-PIP"
	$resourceGroup = "TBH-Engineering"
	
	# Get the Public IP object
	$pip = Get-AzPublicIpAddress -Name $pipName -ResourceGroupName $resourceGroup
	
	# Ensure DnsSettings exists
	if (-not $pip.DnsSettings) {
		$pip.DnsSettings = @{ DomainNameLabel = $dnsLabel }
	} else {
		$pip.DnsSettings.DomainNameLabel = $dnsLabel
	}
	
	# Update the Public IP with the DNS label
	Set-AzPublicIpAddress -PublicIpAddress $pip
	
	# Output the full DNS name
	Write-Host "[+] DNS FWDN Name:" -ForegroundColor Green
	(Get-AzPublicIpAddress -Name $pipName -ResourceGroupName $resourceGroup).DnsSettings.Fqdn

}

# --------------- Create new SPN --------------------
function Create-ApplicationGuardSPN {
    Write-Host "[*] Creating SPN..." -ForegroundColor Cyan

    # Check if SPN already exists
    $existingSP = Get-AzADServicePrincipal -DisplayName $spnName2 -ErrorAction SilentlyContinue
    if ($existingSP) {
        Write-Host "[=] SPN '$spnName2' already exists. Using existing SPN."
        $sp = $existingSP
    }
    else {
        $sp = Invoke-Retry -ScriptBlock { New-AzADServicePrincipal -DisplayName $spnName2 } -ActionName "Create SPN $spnName2"
        Start-Sleep -Seconds 7
    }

    # Retrieve the app registration associated with the SPN
    $app = Get-AzADApplication -DisplayName $spnName2 -ErrorAction SilentlyContinue
    if (-not $app) {
        Write-Warning "[-] Could not find an app registration for SPN $spnName2."
        return
    }

    # Add Application Owner using Microsoft Graph (best-effort)
    try {
        if (-not (Get-MgContext)) { Connect-MgGraph -NoWelcome | Out-Null }
        $graphUser = Get-MgUser -UserId "erin.brown@tropicanabayhotels.com"
        $appObject = Get-MgApplication -Filter "appId eq '$($app.AppId)'" -ConsistencyLevel eventual
        if ($appObject) {
            $ownerRef = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($graphUser.Id)" }
            New-MgApplicationOwnerByRef -ApplicationId $appObject.Id -BodyParameter $ownerRef
            Write-Host "[+] Added 'erin.brown@tropicanabayhotels.com' as Application Owner via Microsoft Graph." -ForegroundColor Green
        }
    } catch {
        Write-Warning "[-] Failed to add application owner via Graph: $_"
    }

    # --- Create a NEW client secret every time and PRINT it (no file I/O) ---
    $secret = Invoke-Retry -ScriptBlock { New-AzADAppCredential -ObjectId $app.Id } -ActionName "Create App Credential"

    $tenantId = (Get-ContextInfo).Tenant
    $clientId = $sp.AppId
    $clientSecret = $secret.SecretText

    Write-Host ""
    Write-Host "================= NEW SPN CREDENTIAL =================" -ForegroundColor Cyan
    Write-Host ("TenantId     : {0}" -f $tenantId)
    Write-Host ("ClientId     : {0}" -f $clientId)
    Write-Host ("ClientSecret : {0}" -f $clientSecret)  # <-- show the new secret on console
    if ($secret.EndDateTime) { Write-Host ("Expires      : {0:u}" -f $secret.EndDateTime) }
    Write-Host "======================================================"
    Write-Host ""

    # Return the values as an object too
    [pscustomobject]@{
        tenantId     = $tenantId
        clientId     = $clientId
        clientSecret = $clientSecret
        expiresOn    = $secret.EndDateTime
    }
}


# --------- Grant Permissions to Application Guard --------
function Grant-GroupWritePermissionToApp {
    [CmdletBinding()]
    param (
        [Parameter()][string]$AppDisplayName = "Application Guard",
        [Parameter()][string]$ResourceGroupName = "TBH-Engineering"   # <— RBAC scope (RG). Change if needed.
    )

    Write-Host "[*] Auto-consenting 'GroupMember.ReadWrite.All' for '$AppDisplayName'..." -ForegroundColor Cyan

    # Ensure you're connected to Graph
    try { $null = Get-MgContext -ErrorAction Stop } catch { throw "Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All','Directory.ReadWrite.All' first." }

    # 1) App, its SPN, and the Microsoft Graph SPN
    $app = (Get-MgApplication -Filter "displayName eq '$AppDisplayName'" -ConsistencyLevel eventual -ErrorAction Stop) | Select-Object -First 1
    if (-not $app) { Write-Warning "[-] App '$AppDisplayName' not found."; return }

    $spn = (Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ConsistencyLevel eventual -ErrorAction Stop) | Select-Object -First 1
    if (-not $spn) { Write-Warning "[-] Service principal for '$AppDisplayName' not found."; return }

    $graphSp = (Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop) | Select-Object -First 1
    if (-not $graphSp) { Write-Warning "[-] Microsoft Graph service principal not found."; return }

    # 2) Role IDs (Application permissions)
    $roleId_GroupMemberRW = [Guid]'dbaae8cf-10b5-4b86-a4a1-f871c94c6695' # GroupMember.ReadWrite.All
    $roleId_DirectoryRead = [Guid]'7ab1d382-f21e-4acd-a863-ba3e13f7da61' # Directory.Read.All

    # 3) Idempotent admin consent for BOTH roles
    $rolesToGrant = @(
        @{ Id = $roleId_GroupMemberRW; Name = 'GroupMember.ReadWrite.All' },
        @{ Id = $roleId_DirectoryRead ; Name = 'Directory.Read.All'       }
    )

    foreach ($r in $rolesToGrant) {
        $exists = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spn.Id -All -ErrorAction SilentlyContinue |
                  Where-Object { $_.ResourceId -eq $graphSp.Id -and $_.AppRoleId -eq $r.Id }

        if (-not $exists) {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spn.Id -BodyParameter @{
                PrincipalId = $spn.Id
                ResourceId  = $graphSp.Id
                AppRoleId   = $r.Id
            } | Out-Null
            Write-Host "[✓] Admin consent granted for '$($r.Name)'." -ForegroundColor Green
        } else {
            Write-Host "[=] Admin consent already present for '$($r.Name)'." -ForegroundColor Yellow
        }
    }

    # 4) RBAC (Az): Grant Reader on the Resource Group to the SPN (management-plane access)
    try { $null = Get-AzContext -ErrorAction Stop } catch { throw "Connect-AzAccount and select a subscription before assigning RBAC." }
    $subId = (Get-AzContext).Subscription.Id
    if (-not $subId) { throw "No Subscription selected in Az context. Run: Set-AzContext -Subscription <SUB_ID>" }

    $scope = "/subscriptions/$subId/resourceGroups/$ResourceGroupName"
    $rbacExists = Get-AzRoleAssignment -ObjectId $spn.Id -Scope $scope -RoleDefinitionName "Reader" -ErrorAction SilentlyContinue
    if (-not $rbacExists) {
        try {
            New-AzRoleAssignment -ObjectId $spn.Id -RoleDefinitionName "Reader" -Scope $scope -ErrorAction Stop | Out-Null
            Write-Host "[✓] RBAC: 'Reader' granted to '$AppDisplayName' on RG '$ResourceGroupName'." -ForegroundColor Green
        } catch {
            Write-Warning "[-] Failed to assign RBAC Reader on scope $scope`: $($_.Exception.Message)"
        }
    } else {
        Write-Host "[=] RBAC: 'Reader' already present on RG '$ResourceGroupName'." -ForegroundColor Yellow
    }
}


function New-AutomationFlagRunbook {
    [CmdletBinding(DefaultParameterSetName='Plain', SupportsShouldProcess)]
    param(
        # === Runbook behavior ===
        [Parameter(Mandatory=$true)]
        [string]$ServerUrl,

        # Creds (choose one style)
        [Parameter(ParameterSetName='Plain', Mandatory=$true)]
        [string]$Username,
        [Parameter(ParameterSetName='Plain', Mandatory=$true)]
        [string]$Password,

        [Parameter(ParameterSetName='Cred', Mandatory=$true)]
        [pscredential]$Credential,

        # === Infra ===
        [string]$ResourceGroupName     = "TBH-Engineering",
        [string]$Location              = "westus",
        [string]$AutomationAccountName = "BasicAuthFlag",
        [string]$RunbookName           = "Send-Flag",

        # === Access control ===
        # Entra group allowed to use THIS runbook (DisplayName or ObjectId GUID)
        [Parameter(Mandatory=$true)]
        [string]$AllowedGroup,

        # Remove any other role assignments at THIS runbook scope (not inherited ones)
        [switch]$Exclusive
    )

    # Resolve creds
    if ($PSCmdlet.ParameterSetName -eq 'Cred') {
        $User = $Credential.UserName
        $Pass = $Credential.GetNetworkCredential().Password
    } else {
        $User = $Username
        $Pass = $Password
    }

    # 1) Ensure RG + Automation Account exist (subscription comes from current Az context)
    New-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -Location $Location -ErrorAction SilentlyContinue | Out-Null

    # 2) Create the runbook code (Basic Auth + hardcoded TBH flag) and import it

$rbPath = Join-Path $env:TEMP "$RunbookName.ps1"
@'
param(
    [Parameter(Mandatory=$true)][string]$ServerUrl,
    [Parameter(Mandatory=$true)][string]$Username,
    [Parameter(Mandatory=$true)][string]$Password
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Build Basic Auth header
$pair    = "{0}:{1}" -f $Username, $Password
$bytes   = [Text.Encoding]::ASCII.GetBytes($pair)
$token   = [Convert]::ToBase64String($bytes)
$headers = @{ Authorization = "Basic $token" }

# Hardcoded flag value (no randomness)
$flag = "Flag TBH{Run_F0r5T_RuNB0oK}"

# Send as JSON
$body = @{ message = $flag; sentAt = (Get-Date).ToUniversalTime().ToString("o") } | ConvertTo-Json

try {
    $resp = Invoke-RestMethod -Uri $ServerUrl -Method Post -Headers $headers -ContentType "application/json" -Body $body -TimeoutSec 30
    Write-Output "Sent: $flag"
    if ($resp) { Write-Output "Server response:"; $resp | Out-String }
}
catch {
    Write-Warning "Request failed: $($_.Exception.Message)"
}
'@ | Set-Content -Path $rbPath -Encoding UTF8

    if (-not (Get-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $RunbookName -ErrorAction SilentlyContinue)) {
        Import-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $RunbookName -Type PowerShell -Path $rbPath | Out-Null
    }
    Publish-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $RunbookName | Out-Null

    # 3) RBAC: grant ONLY the chosen group at the RUNBOOK scope
    $ctx   = Get-AzContext
    $subId = $ctx.Subscription.Id
    $scope = "/subscriptions/$subId/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/$RunbookName"

    # Resolve group ObjectId from DisplayName or accept GUID directly
    if ($AllowedGroup -match '^[0-9a-fA-F-]{36}$') {
        $groupObjectId = $AllowedGroup
    } else {
        $matches = Get-AzADGroup -DisplayName $AllowedGroup -ErrorAction Stop
        if ($matches -is [array]) {
            # try exact display name match first
            $exact = $matches | Where-Object { $_.DisplayName -eq $AllowedGroup }
            if ($exact.Count -eq 1) { $groupObjectId = $exact.Id }
            else {
                throw "Group name '$AllowedGroup' is ambiguous. Provide the ObjectId."
            }
        } else {
            $groupObjectId = $matches.Id
        }
    }

    $roleName = "Automation Runbook Operator"   # permits reading runbook + creating jobs
    try {
        New-AzRoleAssignment -ObjectId $groupObjectId -RoleDefinitionName $roleName -Scope $scope -ErrorAction Stop | Out-Null
        Write-Host "[RBAC] Granted '$roleName' to group $AllowedGroup at scope: $scope"
    } catch {
        if ($_.Exception.Message -notmatch "already exists") { throw }
        else { Write-Host "[RBAC] Role assignment already exists." }
    }

    # Optionally remove any other role assignments at THIS scope (excludes inherited)
    if ($Exclusive.IsPresent) {
        $assignments = Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue
        foreach ($a in $assignments) {
            if ($a.ObjectId -ne $groupObjectId) {
                try {
                    Remove-AzRoleAssignment -Scope $scope -ObjectId $a.ObjectId -RoleDefinitionName $a.RoleDefinitionName -ErrorAction Stop | Out-Null
                    Write-Host "[RBAC] Removed assignment: $($a.RoleDefinitionName) for ObjectId $($a.ObjectId)"
                } catch {
                    Write-Warning "[RBAC] Could not remove $($a.RoleDefinitionName) for $($a.ObjectId): $($_.Exception.Message)"
                }
            }
        }
    }

    # 4) Start a one-time run with your parameters
    $job = Start-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $RunbookName -Parameters @{ ServerUrl=$ServerUrl; Username=$User; Password=$Pass }

    Write-Host "[OK] Runbook started. Check the job output in the Automation Account."
    return $job
}

function Main {
    Login-IfNeeded
    $ctx = Get-ContextInfo
    $global:subscriptionId = $ctx.SubId
    $global:tenantId = $ctx.Tenant
	
	# 1) Create a Linux VM
	Create-LinuxVM -ResourceGroupName "TBH-Engineering" -Location westus

	# 2)
	Create-ApplicationGuardSPN

	# 3) Grant ApplicationGuardSPN Permission
	Grant-GroupWritePermissionToApp
	
	# 4) Create a Runbook
	New-AutomationFlagRunbook -ServerUrl "http://localhost/" -Username admin -Password password -AllowedGroup "TBH RunBook Staff"
	
	Write-Host "Lab Completely Build" -ForegroundColor Green
}
Main