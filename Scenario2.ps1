# AzureRTLabs Lab Setup - Hybrid: Microsoft Graph for Directory Ops and Az for ARM Resources
# PowerShell v6+

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

    Write-Host "[*] Checking Azure CLI login status..."
    az login
}

function Get-ContextInfo {
    Write-Host "[*] Getting subscription and tenant information..."
    $context = Get-AzContext
    Start-Sleep -Seconds 2
    return @{ SubId = $context.Subscription.Id; Tenant = $context.Tenant.Id }
}

# --------------- Build a Storage Blob that Alice can Read
function Create-StorageAndBlob {
    Write-Host "[*] Checking for existing storage accounts..."
    $existingStorage = Get-AzStorageAccount -ResourceGroupName "TBH-Engineering" -ErrorAction SilentlyContinue | Where-Object { $_.StorageAccountName -like "tbhstorage*" }

    if ($existingStorage) {
        $storage = $existingStorage | Select-Object -First 1
        Write-Host "[=] Existing storage account found: $($storage.StorageAccountName)"
    } else {
        Write-Host "[+] Creating new Storage Account..."
        $name = "tbhstorage$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        $storage = Invoke-Retry -ScriptBlock { New-AzStorageAccount -Name $name -ResourceGroupName "TBH-Engineering" -Location $location -Sku Standard_LRS -Kind StorageV2 -AllowBlobPublicAccess $false } -ActionName "Create Storage Account"
        Start-Sleep -Seconds 5
    }

    $ctx = $storage.Context
    $container = Get-AzStorageContainer -Name $containerName -Context $ctx -ErrorAction SilentlyContinue
    if (-not $container) {
        Write-Host "[+] Creating private container: $containerName"
        Invoke-Retry -ScriptBlock { New-AzStorageContainer -Name $containerName -Context $ctx -Permission Off | Out-Null } -ActionName "Create Container $containerName"
    } else {
        Write-Host "[=] Container already exists: $containerName"
    }

    # Upload "youfoundme.txt"
    Set-Content -Path $blobFilePath -Value $blobContent
    Invoke-Retry -ScriptBlock { Set-AzStorageBlobContent -File $blobFilePath -Container $containerName -Blob "youfoundme.txt" -Context $ctx -Force | Out-Null } -ActionName "Upload Blob youfoundme.txt"

    # Create and upload dummy script
    $linuxScriptPath = "$env:TEMP\update.sh"
    $linuxScriptContent = @"
#!/bin/bash
echo "[*] Installing system updates..."
sleep 2
echo "[*] Authenticating..."
# Embedded credentials for Carol (simulated)
export ADMIN_USER="carol.lee@tropicanabayhotels.com"
export ADMIN_PASS="S!mm3r2025_Str0ng"
echo "[+] Update complete. System secured."
"@
    Set-Content -Path $linuxScriptPath -Value $linuxScriptContent -Encoding UTF8
    Invoke-Retry -ScriptBlock { Set-AzStorageBlobContent -File $linuxScriptPath -Container $containerName -Blob "update.sh" -Context $ctx -Force | Out-Null } -ActionName "Upload Blob update.sh"

    # Give Alice access to the blob
    $alice = Get-AzADUser -UserPrincipalName "alice.hill@tropicanabayhotels.com" -ErrorAction SilentlyContinue
    if ($alice) {
        Invoke-Retry -ScriptBlock {
            New-AzRoleAssignment -ObjectId $alice.Id -RoleDefinitionName "Storage Blob Data Reader" -Scope $storage.Id -ErrorAction SilentlyContinue | Out-Null
        } -ActionName "Assign Storage Blob Data Reader to Alice"
        Write-Host "[+] Alice granted Storage Blob Data Reader role." -ForegroundColor Green
    } else {
        Write-Warning "[-] Could not find Alice Hill to assign blob access."
    }

    $url = "https://$($storage.StorageAccountName).blob.core.windows.net/$containerName/update.sh"
    Write-Host "[+] Script uploaded. URL: $url" -ForegroundColor Cyan

    return $storage.StorageAccountName
}

# ---------------- Resource (Az) Functions ----------------
function Create-ResourceGroups {
    Write-Host "[*] Creating resource groups..."
    foreach ($rg in $TBHResourceGroups) {
        if (-not (Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue)) {
            Write-Host "[+] Creating resource group: $rg"
            Invoke-Retry -ScriptBlock { New-AzResourceGroup -Name $rg -Location $location | Out-Null } -ActionName "Create RG $rg"
            Start-Sleep -Seconds 3
        }
        else {
            Write-Host "[=] Resource group already exists: $rg"
        }
    }
}

# ---------------- Create Function (assign System Identity and deploy) ----------------
function Publish-FunctionApp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectFolder,
        [Parameter(Mandatory)][string]$FunctionAppName,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$StorageAccount,
        [string]$Location = 'westus'
    )

    # Prerequisites
    foreach ($tool in 'az','func') {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            Throw "Required tool '$tool' not found in PATH."
        }
    }
    if (-not (Test-Path $ProjectFolder)) { Throw "Project folder '$ProjectFolder' not found." }

    # Create (or reuse) resource group
    Write-Host "Ensuring resource group '$ResourceGroup'…" -ForegroundColor Cyan
    az group create --name "TBH-Engineering" --location $Location | Out-Null
	
	Start-Sleep -Seconds 10
	
    # Create (or reuse) storage account
    Write-Host "Ensuring storage account '$StorageAccount'…" -ForegroundColor Cyan
	az storage account create --name $StorageAccount --resource-group $ResourceGroup --location $Location --sku Standard_LRS --kind StorageV2 2>$null | Out-Null
	
	Start-Sleep -Seconds 10
	
	Write-Host "[!] Building Function" -ForegroundColor Cyan
	# Create Function
    az functionapp create --resource-group TBH-Engineering --consumption-plan-location westus --runtime python --runtime-version 3.12 --functions-version 4 --name $FunctionAppName --storage-account $StorageAccount --os-type Linux
	
	Start-Sleep -Seconds 10
    # Create (or reuse) the Python Function App
	# Zip Files
	Write-Host "[!] Compressing Function Files" -ForegroundColor Cyan
	Compress-Archive -Path "$ProjectFolder\FunctionApp\*" -DestinationPath "$env:TEMP\function.zip" -Force
	
	Start-Sleep -Seconds 5
	
	Write-Host "[!] Deploying" -ForegroundColor Green
	# Create the Deployment Source
	az functionapp deployment source config-zip --resource-group TBH-Engineering --name render --src "$env:TEMP\function.zip"
	
	Start-Sleep -Seconds 15
	
	# Set Location
	Set-Location -Path "$ProjectFolder\FunctionApp"
    
	# Publish your Python Jinja tester
    Write-Host "Publishing Python Function App…" -ForegroundColor Cyan
    
	func azure functionapp publish render
}

#---------------- Managed KeyVault that holds the Key for the DB ----------------
function Create-ManagedKeyVault {
    Write-Host "[*] Creating Managed Key Vault '$managedKeyVaultName'..." -ForegroundColor Cyan

    # 1) Create (or get) the vault
    $vault = Get-AzKeyVault -VaultName $managedKeyVaultName -ResourceGroupName $TBHResourceGroups[2] -ErrorAction SilentlyContinue
    if (-not $vault) {
        Invoke-Retry -ScriptBlock {
            New-AzKeyVault -Name $managedKeyVaultName `
                           -ResourceGroupName $TBHResourceGroups[2] `
                           -Location $location `
                           -Sku Standard
        } -ActionName "Create Key Vault" | Out-Null
        Start-Sleep -Seconds 6
        $vault = Get-AzKeyVault -VaultName $managedKeyVaultName -ResourceGroupName $TBHResourceGroups[2] -ErrorAction Stop
        Write-Host "[+] Key Vault created." -ForegroundColor Green
    } else {
        Write-Host "[=] Key Vault already exists: $managedKeyVaultName" -ForegroundColor Yellow
    }

    $vaultId = $vault.ResourceId
    if (-not $vaultId) { throw "Could not resolve ResourceId for Key Vault '$managedKeyVaultName'." }

    # Detect RBAC vs Access Policy mode (older vaults may not have RBAC enabled)
    $isRbac = $false
    try { if ($vault.EnableRbacAuthorization) { $isRbac = $true } } catch { $isRbac = $false }

    # 2) Grant you temporary Key Vault Administrator rights (RBAC) OR broad access policy (AP mode)
    $acctUpn = (Get-AzContext).Account.Id  # UPN / sign-in
    $me = $null
    try { $me = Get-AzADUser -UserPrincipalName $acctUpn -ErrorAction Stop } catch {}
    if (-not $me) {
        try { $mg = Get-MgUser -UserId $acctUpn -ErrorAction Stop; $me = [pscustomobject]@{ Id = $mg.Id; DisplayName = $mg.DisplayName } } catch {}
    }
    if (-not $me) { throw "Unable to resolve current user in Entra ID: $acctUpn" }

    if ($isRbac) {
        $hasAdmin = Get-AzRoleAssignment -ObjectId $me.Id -Scope $vaultId -RoleDefinitionName "Key Vault Administrator" -ErrorAction SilentlyContinue
        if (-not $hasAdmin) {
            Invoke-Retry -ScriptBlock {
                New-AzRoleAssignment -ObjectId $me.Id -RoleDefinitionName "Key Vault Administrator" -Scope $vaultId -ErrorAction Stop | Out-Null
            } -ActionName "Assign KV Admin to current user"
            Start-Sleep -Seconds 3
        }
        Write-Host "[=] You have (or were granted) 'Key Vault Administrator' via RBAC." -ForegroundColor Yellow
    } else {
        # Access Policy mode fallback
        Set-AzKeyVaultAccessPolicy -VaultName $managedKeyVaultName -ObjectId $me.Id -PermissionsToSecrets get,list,set | Out-Null
        Write-Host "[=] Access policy applied for you (get,list,set) — vault is in Access Policy mode." -ForegroundColor Yellow
    }

	# 3) Store DB credentials as a SINGLE secret (JSON payload inside "DB-password")
	$DBUser     = "sqladmin"
	$DBPassword = "gT7!pXq#8kJZ"
	
	$payloadJson = (@{ username = $DBUser; password = $DBPassword } | ConvertTo-Json -Compress)
	$secretValue = ConvertTo-SecureString -String $payloadJson -AsPlainText -Force
	
	Invoke-Retry -ScriptBlock {
		Set-AzKeyVaultSecret -VaultName $managedKeyVaultName -Name "DB-password" -SecretValue $secretValue -ContentType "application/json" -Tags @{ purpose = "sql-cred"; format = "json" } | Out-Null
	} -ActionName "Store DB Credentials in Key Vault (single secret)"
	
    Write-Host "[+] Secret 'DB-password' stored." -ForegroundColor Green

    # 4) Ensure Function App identity exists, then get principalId robustly
    try { Update-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $TBHResourceGroups[1] -IdentityType SystemAssigned -Force | Out-Null } catch {}
    try { az functionapp identity assign -g $TBHResourceGroups[1] -n $FunctionAppName 1>$null 2>$null } catch {}

    $principalId = $null
    for ($i=0; $i -lt 12 -and -not $principalId; $i++) {
        try {
            $fa = Get-AzFunctionApp -ResourceGroupName $TBHResourceGroups[1] -Name $FunctionAppName -ErrorAction SilentlyContinue
            if ($fa -and $fa.IdentityPrincipalId) { $principalId = $fa.IdentityPrincipalId }
        } catch {}
        if (-not $principalId) {
            try {
                $wa = Get-AzWebApp -ResourceGroupName $TBHResourceGroups[1] -Name $FunctionAppName -ErrorAction SilentlyContinue
                if ($wa -and $wa.Identity -and $wa.Identity.PrincipalId) { $principalId = $wa.Identity.PrincipalId }
            } catch {}
        }
        if (-not $principalId) {
            try {
                $j = az functionapp identity show -g $TBHResourceGroups[1] -n $FunctionAppName -o json 2>$null
                if ($j) { $obj = $j | ConvertFrom-Json; if ($obj.principalId) { $principalId = $obj.principalId } }
            } catch {}
        }
        if (-not $principalId) { Start-Sleep -Seconds 5 }
    }
    if (-not $principalId) { throw "Managed Identity principalId not available for Function '$FunctionAppName'." }

    # 5) Grant Function App read on secrets (RBAC or Access Policy)
    if ($isRbac) {
        $hasKVSecrets = Get-AzRoleAssignment -ObjectId $principalId -Scope $vaultId -RoleDefinitionName "Key Vault Secrets User" -ErrorAction SilentlyContinue
        if (-not $hasKVSecrets) {
            Invoke-Retry -ScriptBlock {
                New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Key Vault Secrets User" -Scope $vaultId -ErrorAction Stop | Out-Null
            } -ActionName "Assign KV Secrets User to Function MI"
        }
        Write-Host "[+] Function MI has 'Key Vault Secrets User' (RBAC) at vault scope." -ForegroundColor Green
    } else {
        # Access Policy mode fallback
        Set-AzKeyVaultAccessPolicy -VaultName $managedKeyVaultName -ObjectId $principalId -PermissionsToSecrets get,list | Out-Null
        Write-Host "[+] Function MI access policy applied (get,list) — vault is in Access Policy mode." -ForegroundColor Green
    }

    Start-Sleep -Seconds 2
    Write-Host "[✓] Managed Key Vault setup complete." -ForegroundColor Green
}

# ---------------- Static website that posts to the Function endpoint ----------------
function WebAppFromBlob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory=$true)]
        [string]$StorageAccountName,
        [Parameter(Mandatory=$true)]
        [string]$ContainerName,
        [Parameter(Mandatory=$true)]
        [string]$WebAppName,
        [string]$Location = "westus"
    )

    $tempFolder = Join-Path $env:TEMP "StaticWebContent_v6"
    if (Test-Path $tempFolder) { Remove-Item $tempFolder -Recurse -Force }
    New-Item -ItemType Directory -Path $tempFolder | Out-Null

@"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Static Site Form</title>
</head>
<body>
    <h1>Query Users</h1>
    <form method="POST" action="https://$FunctionAppName.azurewebsites.net/api/render">
        <label for="payload">Enter some text:</label><br />
        <input type="text" id="payload" name="payload" /><br /><br />
        <input type="submit" value="Submit" />
    </form>
</body>
</html>
"@ | Out-File -FilePath (Join-Path $tempFolder "index.html") -Encoding UTF8

@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8' />
    <title>404 - Not Found</title>
</head>
<body>
    <h1>404 - Page Not Found</h1>
    <p>The resource you requested could not be found.</p>
</body>
</html>
"@ | Out-File -FilePath (Join-Path $tempFolder "404.html") -Encoding UTF8

    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
    $ctx = $storageAccount.Context

    Enable-AzStorageStaticWebsite -Context $ctx -IndexDocument "index.html" -ErrorDocument404Path "404.html"

    $staticContainer = '$web'
    if (-not (Get-AzStorageContainer -Name $staticContainer -Context $ctx -ErrorAction SilentlyContinue)) {
        New-AzStorageContainer -Name $staticContainer -Context $ctx | Out-Null
    }

    Set-AzStorageBlobContent -File (Join-Path $tempFolder "index.html") -Container $staticContainer -Blob "index.html" -Context $ctx -Properties @{ "ContentType" = "text/html" } -Force | Out-Null
    Set-AzStorageBlobContent -File (Join-Path $tempFolder "404.html") -Container $staticContainer -Blob "404.html" -Context $ctx -Properties @{ "ContentType" = "text/html" } -Force | Out-Null

    $endpoint = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).PrimaryEndpoints.Web
    Write-Host "`nStatic website for '$WebAppName' is live at: $endpoint"
}

# ---------------- Setup SQL DB and seed data ----------------
function Setup-SQL{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ResourceGroupName = 'TBH-Engineering',
        [Parameter(Mandatory)][string] $Location = 'westus',
        [Parameter(Mandatory)][string] $SqlServerName = $SqlServerName,
        [Parameter(Mandatory)][string] $SqlAdminUser = $SqlAdminUser,
        [Parameter()][SecureString] $SqlAdminPass
    )

    if (-not $SqlAdminPass) {
        do {
            $SqlAdminPass = Read-Host "Enter a strong password for SQL admin '$SqlAdminUser'" -AsSecureString
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SqlAdminPass)
            )
        } while ($plain.Length -lt 12)
    }

    Write-Host "==> Ensuring Resource Group '$ResourceGroupName' in '$Location'…" -ForegroundColor Cyan
    if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
        Start-Sleep -Seconds 3
    } else { Write-Host "[=] Resource Group already exists." -ForegroundColor Yellow }

    Write-Host "==> Ensuring SQL Server '$SqlServerName'…" -ForegroundColor Cyan
    $server = Get-AzSqlServer -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName -ErrorAction SilentlyContinue
    if (-not $server) {
        $creds = New-Object System.Management.Automation.PSCredential($SqlAdminUser, $SqlAdminPass)
        $server = New-AzSqlServer -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName -Location $Location -SqlAdministratorCredentials $creds
        Start-Sleep -Seconds 15
    } else { Write-Host "[=] SQL Server already exists." -ForegroundColor Yellow }

    # Allow client IP (short allow)
    Write-Host "==> Adding firewall rule for current public IP…" -ForegroundColor Cyan
    $myIp = (Invoke-RestMethod 'https://api.ipify.org?format=json').ip
    if (-not (Get-AzSqlServerFirewallRule -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName -ErrorAction SilentlyContinue | Where-Object { $_.StartIpAddress -eq $myIp })) {
        New-AzSqlServerFirewallRule -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName -FirewallRuleName  "client-ip" -StartIpAddress $myIp -EndIpAddress $myIp | Out-Null
        Start-Sleep -Seconds 3
    } else { Write-Host "[=] Firewall rule for $myIp already exists." -ForegroundColor Yellow }

    # Create DB
    $databaseName = 'UsersDB'
    Write-Host "==> Ensuring database '$databaseName'…" -ForegroundColor Cyan
    $db = Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName -DatabaseName $databaseName -ErrorAction SilentlyContinue
    if (-not $db) {
        New-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName -DatabaseName $databaseName -RequestedServiceObjectiveName 'S0' | Out-Null
        Start-Sleep -Seconds 30
    } else { Write-Host "[=] Database already exists." -ForegroundColor Yellow }

    # Seed data via SQL auth (admin)
    $plainPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SqlAdminPass)
    )
    $connString = "Server=tcp:$SqlServerName.database.windows.net,1433;Initial Catalog=$databaseName;User ID=$SqlAdminUser;Password=$plainPass;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"

    Write-Host "==> Seeding dummy data…" -ForegroundColor Cyan
    Invoke-Sqlcmd -ConnectionString $connString -Query @"
IF OBJECT_ID('dbo.Users','U') IS NOT NULL DROP TABLE dbo.Users;
CREATE TABLE dbo.Users(
    Id           INT IDENTITY(1,1) PRIMARY KEY,
    UPN          NVARCHAR(100),
    DisplayName  NVARCHAR(100),
    [Password]   NVARCHAR(100)
);
INSERT INTO dbo.Users (UPN,DisplayName,[Password]) VALUES
 ('alice.hill@tropicanabayhotels.com','Alice Hill','Password123'),
 ('bob.smith@tropicanabayhotels.com','Bob Smith','SpR!ng2025_Cmplx'),
 ('carol.lee@tropicanabayhotels.com','Carol Lee','S!mm3r2025_Str0ng'),
 ('david.jones@tropicanabayhotels.com','David Jones','D@v1dJ0n35!'),
 ('erin.brown@tropicanabayhotels.com','Erin Brown','Br0wn3r!n2025'),
 ('frank.wright@tropicanabayhotels.com','Frank Wright','Wr1ght_F!22'),
 ('grace.chen@tropicanabayhotels.com','Grace Chen','Gr@c3Ch3n#1'),
 ('henry.kim@tropicanabayhotels.com','Henry Kim','H3nryK!m2025'),
 ('isabel.lopez@tropicanabayhotels.com','Isabel Lopez','L0p3z_Is@b3l'),
 ('admin','SuperSecret','FLAG{TBH_M4n4g3D_Id3nt17y}'),
 ('ethan.winters@tropicanabayhotels.com','Ethan Winters','R053W!Nt3r5');
"@

    Write-Host "`n==> Querying dbo.Users…" -ForegroundColor Green
    Invoke-Sqlcmd -ConnectionString $connString -Query "SELECT * FROM dbo.Users;" | Format-Table

    Write-Host "`n[✓] SQL setup complete." -ForegroundColor Green
}

# ---------------- ARM + T-SQL permissions for the Function's Managed Identity ----------------
function Enable-MI-ForSqlEnumerations {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$FunctionAppName,
        [Parameter(Mandatory)][string]$SqlServerName,
        [string]$DatabaseName = 'UsersDB'
    )

    # 0) Ensure the Function has a System-Assigned MI (idempotent) and resolve principalId (Az-only)
    try { Update-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -IdentityType SystemAssigned -Force | Out-Null } catch {}

    $miObjectId = $null
    for ($i=0; $i -lt 18 -and -not $miObjectId; $i++) {
        try {
            $fa = Get-AzFunctionApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ErrorAction SilentlyContinue
            if ($fa -and $fa.IdentityPrincipalId) { $miObjectId = $fa.IdentityPrincipalId }
        } catch {}
        if (-not $miObjectId) {
            try {
                $wa = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ErrorAction SilentlyContinue
                if ($wa -and $wa.Identity -and $wa.Identity.PrincipalId) { $miObjectId = $wa.Identity.PrincipalId }
            } catch {}
        }
        if (-not $miObjectId) { Start-Sleep -Seconds 5 }
    }
    if (-not $miObjectId) { throw "Managed Identity principalId not available yet for '$FunctionAppName'. Verify identity is enabled." }

    # Use the SP display name Azure SQL will see; fall back to the app name
    $sqlUserName = $FunctionAppName
    try {
        $sp = Get-AzADServicePrincipal -ObjectId $miObjectId -ErrorAction Stop
        if ($sp.DisplayName) { $sqlUserName = $sp.DisplayName }
    } catch {}

    # 1) Locate the SQL server
    $sqlServer = Get-AzSqlServer -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName -ErrorAction SilentlyContinue
    if (-not $sqlServer) {
        $sqlServer = Get-AzSqlServer | Where-Object { $_.ServerName -eq $SqlServerName } | Select-Object -First 1
        if (-not $sqlServer) { throw "SQL server '$SqlServerName' not found." }
    }

    # 1b) MANAGEMENT PLANE: allow ARM listing (fixes 'Microsoft.Sql/servers/databases/read' error)
    $scope = $sqlServer.ResourceId
    if (-not $scope) {
        $subId = (Get-AzContext).Subscription.Id
        $scope = "/subscriptions/$subId/resourceGroups/$($sqlServer.ResourceGroupName)/providers/Microsoft.Sql/servers/$($sqlServer.ServerName)"
    }

    $existing = Get-AzRoleAssignment -ObjectId $miObjectId -Scope $scope -RoleDefinitionName "Reader" -ErrorAction SilentlyContinue
    if (-not $existing) {
        if (Get-Command Invoke-Retry -ErrorAction SilentlyContinue) {
            Invoke-Retry -ScriptBlock {
                New-AzRoleAssignment -ObjectId $miObjectId -RoleDefinitionName "Reader" -Scope $scope -ErrorAction Stop | Out-Null
            } -ActionName "Assign Reader on SQL server to Function MI"
        } else {
            New-AzRoleAssignment -ObjectId $miObjectId -RoleDefinitionName "Reader" -Scope $scope -ErrorAction Stop | Out-Null
        }
        Write-Host "[✓] Reader assigned to MI at scope: $scope" -ForegroundColor Green
    } else {
        Write-Host "[=] Reader already assigned at scope: $scope"
    }

    # 2) DATA PLANE: ensure an Entra admin exists (needed to create AAD users)
    $currentAdmin = Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $sqlServer.ResourceGroupName -ServerName $sqlServer.ServerName -ErrorAction SilentlyContinue
    if (-not $currentAdmin) {
        $acctUpn = (Get-AzContext).Account.Id
        $me = $null
        try { $me = Get-AzADUser -UserPrincipalName $acctUpn -ErrorAction Stop } catch {}
        if (-not $me) { throw "Cannot resolve current user '$acctUpn' to set as SQL AAD admin." }

        Set-AzSqlServerActiveDirectoryAdministrator `
            -ResourceGroupName $sqlServer.ResourceGroupName `
            -ServerName $sqlServer.ServerName `
            -DisplayName $me.DisplayName `
            -ObjectId $me.Id | Out-Null
        Start-Sleep -Seconds 8
        Write-Host "[*] Set SQL AAD admin to '$($me.DisplayName)'."
    }

    # 3) DATA PLANE: create user for MI in master + DB and grant read
    $token = (Get-AzAccessToken -ResourceUrl "https://database.windows.net/").Token
    $fqdn  = "$($sqlServer.ServerName).database.windows.net"

    # master: presence enables DB enumeration via T-SQL
    $qMaster = @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$sqlUserName')
    CREATE USER [$sqlUserName] FROM EXTERNAL PROVIDER;
"@
    Invoke-Sqlcmd -ServerInstance $fqdn -Database "master" -AccessToken $token -Query $qMaster

    # target DB: grant read
    $qDb = @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$sqlUserName')
    CREATE USER [$sqlUserName] FROM EXTERNAL PROVIDER;
IF IS_ROLEMEMBER('db_datareader', N'$sqlUserName') <> 1
    ALTER ROLE db_datareader ADD MEMBER [$sqlUserName];
"@
    Invoke-Sqlcmd -ServerInstance $fqdn -Database $DatabaseName -AccessToken $token -Query $qDb

    Write-Host "[✓] MI '$sqlUserName' can ARM-list databases (Reader) and read '$DatabaseName' via T-SQL." -ForegroundColor Green
}

# ---------------- Main ----------------
function Main {
    Login-IfNeeded
    $ctx = Get-ContextInfo
    $global:subscriptionId = $ctx.SubId
    $global:tenantId = $ctx.Tenant

    # 1) Create storage + blob container + seed files
    $storageName = Create-StorageAndBlob

    # 2) Create resource groups
    Create-ResourceGroups

    # 3) Static website that posts to Function endpoint
    WebAppFromBlob -ResourceGroupName "TBH-Engineering" -StorageAccountName $storageName -ContainerName "web" -WebAppName "StaticSite$([Guid]::NewGuid().ToString('N').Substring(0,6))" -Location $location

    # 4) Create & publish Function App; enable System Assigned MI
	Publish-FunctionApp -ProjectFolder $ProjectFolder -FunctionAppName $FunctionAppName -StorageAccount "jinjastorage$([System.Guid]::NewGuid().ToString('N').Substring(0,6))" -ResourceGroup "TBH-Engineering" -Location $location

    # 5) Key Vault for DB secret; grant Function 'Key Vault Secrets User'
    Create-ManagedKeyVault

    # 6) Create SQL + DB + seed data
    $securePassword = 'gT7!pXq#8kJZ' | ConvertTo-SecureString -AsPlainText -Force
    Setup-SQL -ResourceGroupName "TBH-Engineering" -Location $location -SqlServerName $SqlServerName -SqlAdminUser $SqlAdminUser -SqlAdminPass $securePassword

    # 7) Enable MI to enumerate databases (ARM) and read UsersDB (T-SQL)
    Enable-MI-ForSqlEnumerations -ResourceGroupName "TBH-Engineering" -FunctionAppName $FunctionAppName -SqlServerName $SqlServerName

    Write-Host "`n[✓] Lab Completely Built" -ForegroundColor Green
}

Main
