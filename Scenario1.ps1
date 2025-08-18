# AzureRTLabs Lab Setup - Hybrid: Microsoft Graph for Directory Ops and Az for ARM Resources
# PowerShell v6

# For this to work correctly we need to be logged into Az Modules, AZ CLI, and Connect-MgGraph

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
            Write-Warning "[!] $ActionName failed on attempt $attempt. Error: $_"
            if ($attempt -lt $MaxAttempts) {
                Write-Host "Retrying $ActionName in $DelaySeconds seconds..."
                Start-Sleep -Seconds $DelaySeconds
            } else {
                Write-Warning "[✗] $ActionName failed after $MaxAttempts attempts."
                throw $_
            }
        }
    } while ($attempt -lt $MaxAttempts)
}

# ---------------- Login and Context ----------------
function Login-IfNeeded {
    Write-Host "[*] Checking Az PowerShell login status..."
    if (-not (Get-AzContext)) {
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
        Connect-MgGraph -NoWelcome -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.ReadWrite.All", "Group.ReadWrite.All", "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "Policy.ReadWrite.ApplicationConfiguration", "Organization.Read.All", "DelegatedPermissionGrant.ReadWrite.All", "Directory.AccessAsUser.All"| Out-Null
    }
}

function Get-ContextInfo {
    Write-Host "[*] Getting subscription and tenant information..."
    $context = Get-AzContext
    Start-Sleep -Seconds 3
    return @{ SubId = $context.Subscription.Id; Tenant = $context.Tenant.Id }
}

# ---------------- Create SPN Application ----------------

function Create-SPN {
    Write-Host "[*] Creating new SPN using Az module..."

    # Always create a new SPN (App + Service Principal)
    $sp = Invoke-Retry -ScriptBlock { New-AzADServicePrincipal -DisplayName $spName } -ActionName "Create SPN $spName"
    Start-Sleep -Seconds 7

    # Retrieve the app registration associated with the new SPN
    $app = Get-AzADApplication -DisplayName $spName -ErrorAction SilentlyContinue
    if (-not $app) {
        Write-Warning "[-] Could not find an app registration for SPN $spName."
        return
    }
	
    # Generate a new client secret
    $secret = Invoke-Retry -ScriptBlock {
	New-AzADAppCredential -ApplicationId $app.AppId
	} -ActionName "Create App Credential"


    # Output the SPN info
    $spnData = [pscustomobject]@{
        clientId     = $sp.AppId
        clientSecret = $secret.SecretText
    }

    Write-Host "[+] SPN Created:"
    Write-Host "    Client ID    : $($spnData.clientId)"
    Write-Host "    Client Secret: $($spnData.clientSecret)" -ForegroundColor Yellow

    return $spnData
}

# ---------------- Build Useres ---------------------

function Create-UsersAndGroups {
    Write-Host "[*] Creating users and groups..."
	$users = @(
        @{ UPN = "alice.hill@tropicanabayhotels.com"; DisplayName = "Alice Hill"; Password = "Password123" },
        @{ UPN = "bob.smith@tropicanabayhotels.com"; DisplayName = "Bob Smith"; Password = "SpR!ng2025_Cmplx" },
        @{ UPN = "carol.lee@tropicanabayhotels.com"; DisplayName = "Carol Lee"; Password = "S!mm3r2025_Str0ng" },
        @{ UPN = "david.jones@tropicanabayhotels.com"; DisplayName = "David Jones"; Password = "D@v1dJ0n35!" },
        @{ UPN = "erin.brown@tropicanabayhotels.com"; DisplayName = "Erin Brown"; Password = "Br0wn3r!n2025" },
        @{ UPN = "frank.wright@tropicanabayhotels.com"; DisplayName = "Frank Wright"; Password = "Wr1ght_F!22" },
        @{ UPN = "grace.chen@tropicanabayhotels.com"; DisplayName = "Grace Chen"; Password = "Gr@c3Ch3n#1" },
        @{ UPN = "henry.kim@tropicanabayhotels.com"; DisplayName = "Henry Kim"; Password = "H3nryK!m2025" },
        @{ UPN = "isabel.lopez@tropicanabayhotels.com"; DisplayName = "Isabel Lopez"; Password = "L0p3z_Is@b3l" },
        @{ UPN = "ethan.winters@tropicanabayhotels.com"; DisplayName = "Ethan Winters"; Password = "R053W!Nt3r5" }
    )

    foreach ($user in $users) {
        $existingUser = Get-AzADUser -UserPrincipalName $user.UPN -ErrorAction SilentlyContinue
        if ($existingUser) {
            Write-Host "[=] User already exists: $($user.UPN)"
            continue
        }
        try {
            $pwd = ConvertTo-SecureString -String $user.Password -AsPlainText -Force
            Invoke-Retry -ScriptBlock { New-AzADUser -DisplayName $user.DisplayName -UserPrincipalName $user.UPN -MailNickname ($user.UPN.Split("@")[0]) -AccountEnabled $true -Password $pwd -ForceChangePasswordNextLogin:$false | Out-Null } -ActionName "Create User $($user.UPN)"
            Write-Host "[+] Created user: $($user.UPN)"
            Start-Sleep -Seconds 3
        } catch {
            Write-Warning "[-] Could not create user $($user.UPN)"
        }
    }
 
    $groupName = "TBH All Staff"
    $group = Get-AzADGroup -DisplayName $groupName -ErrorAction SilentlyContinue
    if (-not $group) {
        $group = Invoke-Retry -ScriptBlock { New-AzADGroup -DisplayName $groupName -MailNickname "tbhstaff" -MailEnabled:$false -SecurityEnabled:$true } -ActionName "Create Group $groupName"
        Write-Host "[+] Created group: $groupName"
    } else {
        Write-Host "[=] Group already exists: $groupName"
    }
	
	# Build RunBook group
	
	$grouprunbookName = "TBH RunBook Staff"
    $group = Get-AzADGroup -DisplayName $grouprunbookName -ErrorAction SilentlyContinue
    if (-not $group) {
        $group = Invoke-Retry -ScriptBlock { New-AzADGroup -DisplayName $grouprunbookName -MailNickname "tbhrunbookstaff" -MailEnabled:$false -SecurityEnabled:$true } -ActionName "Create Group $grouprunbookName"
		Add-AzADGroupMember -TargetGroupObjectId $group.Id -MemberUserPrincipalName "henry.kim@tropicanabayhotels.com" -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] Created group: $grouprunbookName"
    } else {
        Write-Host "[=] Group already exists: $grouprunbookName"
    }

    foreach ($user in $users) {
        $member = Get-AzADGroupMember -GroupObjectId $group.Id -ErrorAction SilentlyContinue | Where-Object { $_.UserPrincipalName -eq $user.UPN }
        if (-not $member) {
            try {
                Invoke-Retry -ScriptBlock { Add-AzADGroupMember -TargetGroupObjectId $group.Id -MemberUserPrincipalName $user.UPN -ErrorAction SilentlyContinue | Out-Null } -ActionName "Add $($user.UPN) to $groupName"
                Write-Host "[+] Added $($user.UPN) to $groupName"
            } catch {
                Write-Warning "[-] Could not add $($user.UPN) to $groupName"
            }
        } else {
            Write-Host "[=] $($user.UPN) already in group $groupName"
        }
    }

    # Assign Reader role to TBH All Staff group
    $subscriptionId = (Get-AzContext).Subscription.Id
    Invoke-Retry -ScriptBlock { New-AzRoleAssignment -ObjectId $group.Id -RoleDefinitionName "Reader" -Scope "/subscriptions/$subscriptionId" -ErrorAction Stop } -ActionName "Assign Reader Role to TBH Staff Group"
    Write-Host "[+] Assigned Reader role to group '$groupName' at subscription scope."

    $selected = Get-AzADUser | Where-Object { $_.UserPrincipalName -like "*@tropicanabayhotels.com" } | Get-Random
    Write-Host "[i] (Simulated) Permissions User.Read.All and Directory.Read.All granted to: $($selected.UserPrincipalName)" -ForegroundColor Green
    Start-Sleep -Seconds 3
}

# ---------------- Resource (Az) Functions ----------------
function Create-ResourceGroups {
    Write-Host "[*] Creating resource groups..."
    foreach ($rg in $TBHResourceGroups) {
        if (-not (Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue)) {
            Write-Host "[+] Creating resource group: $rg"
            Invoke-Retry -ScriptBlock { New-AzResourceGroup -Name $rg -Location $location | Out-Null } -ActionName "Create RG $rg"
            Start-Sleep -Seconds 5
        }
        else {
            Write-Host "[=] Resource group already exists: $rg"
        }
    }
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

    # Create and upload malicious dummy script
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
    $alice = Get-AzADUser -UserPrincipalName "alice.hill@tropicanabayhotels.com"
    if ($alice) {
        Invoke-Retry -ScriptBlock {
            New-AzRoleAssignment -ObjectId $alice.Id -RoleDefinitionName "Storage Blob Data Reader" -Scope $storage.Id -ErrorAction SilentlyContinue | Out-Null
        } -ActionName "Assign Storage Blob Data Reader to Alice"
        Write-Host "[+] Alice granted Storage Blob Data Reader role." -ForegroundColor Green
    } else {
        Write-Warning "[-] Could not find Alice Hill to assign blob access."
    }

    $url = "https://$($storage.StorageAccountName).blob.core.windows.net/$containerName/update.sh"
    Write-Host "[+] Malicious script uploaded. URL: $url" -ForegroundColor Cyan
    Write-Host "[i] Only Alice has access to this blob, which now contains embedded credentials for Carol." -ForegroundColor Yellow

    return $storage.StorageAccountName
}

# ------------------ Assign permissions for Alice to Read the Blob ----------

function Assign-Reader-To-Alice {
    Write-Host "[*] Granting 'Reader' role to Alice on TBH-Engineering..."
    $alice = Get-AzADUser -UserPrincipalName "alice.hill@tropicanabayhotels.com"
    if ($alice) {
        try {
            Invoke-Retry -ScriptBlock {
                New-AzRoleAssignment -ObjectId $alice.Id `
                                     -RoleDefinitionName "Reader" `
                                     -Scope "/subscriptions/$subscriptionId/resourceGroups/TBH-Engineering" `
                                     -ErrorAction Stop | Out-Null
            } -ActionName "Assign Reader Role to Alice"
            Write-Host "[+] Reader role granted to Alice on TBH-Engineering." -ForegroundColor Green
        } catch {
            Write-Warning "[-] Failed to assign Reader role to Alice: $_"
        }
    } else {
        Write-Warning "[-] Alice not found."
    }
}

# ----------------- Build a Key Vault that holds the SPN Secret ------------

function Create-KeyVault {
    param (
        [Parameter(Mandatory=$true)][pscustomobject]$spnData  # <-- Accepts SPN object directly
    )

    Write-Host "[*] Creating Key Vault..."
    if (-not (Get-AzKeyVault -VaultName $keyVaultName -ErrorAction SilentlyContinue)) {
        Invoke-Retry -ScriptBlock { 
            New-AzKeyVault -Name $keyVaultName -ResourceGroupName "TBH-Finance" -Location $location -Sku Standard | Out-Null 
        } -ActionName "Create Key Vault"
        Start-Sleep -Seconds 10
        Write-Host "[+] Key Vault created."
    } else {
        Write-Host "[=] Key Vault already exists: $keyVaultName"
    }

	# Grant current user full secret permissions
    $me = Get-AzADUser -UserPrincipalName (Get-AzContext).Account.Id
    Invoke-Retry -ScriptBlock {New-AzRoleAssignment -ObjectId $me.Id -RoleDefinitionName "Key Vault Administrator" -Scope "/subscriptions/$subscriptionId/resourceGroups/TBH-Finance/providers/Microsoft.KeyVault/vaults/$keyVaultName" -ErrorAction SilentlyContinue | Out-Null} -ActionName "Assign Key Vault Administrator to current user"
    Start-Sleep -Seconds 15

    # Store client secret directly from SPN object
    if ($spnData.clientSecret -and $spnData.clientSecret -ne "") {
        $realSecret = ConvertTo-SecureString -String $spnData.clientSecret -AsPlainText -Force
        Invoke-Retry -ScriptBlock {
            Set-AzKeyVaultSecret -VaultName $keyVaultName -Name "SPN-ClientSecret" -SecretValue $realSecret | Out-Null
        } -ActionName "Store SPN Secret in Key Vault"
        Write-Host "[+] Stored actual SPN clientSecret in Key Vault as 'SPN-ClientSecret'" -ForegroundColor Green
    } else {
        Write-Warning "[-] SPN clientSecret is missing. Skipping secret storage."
    }

    # Grant Carol Lee access to read secrets
    $carol = Get-AzADUser -UserPrincipalName "carol.lee@tropicanabayhotels.com"
    if ($carol) {
        Invoke-Retry -ScriptBlock {
            Set-AzKeyVaultAccessPolicy -VaultName $keyVaultName -ObjectId $carol.Id -PermissionsToSecrets get, list -PassThru | Out-Null
        } -ActionName "Grant Carol read access to Key Vault"
        Write-Host "[+] Carol Lee granted read access to Key Vault secrets (access policy)." -ForegroundColor Green

        Invoke-Retry -ScriptBlock {
            New-AzRoleAssignment -ObjectId $carol.Id -RoleDefinitionName "Reader" `
                -Scope "/subscriptions/$subscriptionId/resourceGroups/$($TBHResourceGroups[2])/providers/Microsoft.KeyVault/vaults/$keyVaultName" `
                -ErrorAction SilentlyContinue | Out-Null
        } -ActionName "Assign Reader Role to Carol at vault scope"
        Write-Host "[+] Carol Lee granted Reader role at vault scope." -ForegroundColor Green

        Invoke-Retry -ScriptBlock {
            New-AzRoleAssignment -ObjectId $carol.Id -RoleDefinitionName "Key Vault Secrets User" `
                -Scope "/subscriptions/$subscriptionId/resourceGroups/$($TBHResourceGroups[2])/providers/Microsoft.KeyVault/vaults/$keyVaultName" `
                -ErrorAction SilentlyContinue | Out-Null
        } -ActionName "Assign Key Vault Secrets User role to Carol"
        Write-Host "[+] Carol Lee granted 'Key Vault Secrets User' role at vault scope." -ForegroundColor Green
    } else {
        Write-Warning "[-] Carol Lee not found. Cannot assign Key Vault access."
    }
}

# ---------------- Build a VM -----------------------

function Create-VM {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [string]$Location,
        [string]$VMName = "TBH-VM"
    )

    Write-Host "[*] Creating VM for Bob: $VMName in resource group $ResourceGroupName..." -ForegroundColor Cyan

    # Prompt for credentials to set as the VM administrator
	$username = "bob"
	$password = "SpR!ng2025_Cmplx" | ConvertTo-SecureString -AsPlainText -Force
	$vmCredential = New-Object System.Management.Automation.PSCredential($username, $password)


    # Create VM configuration
    $vmConfig = New-AzVMConfig -VMName $VMName -VMSize "Standard_DS1_v2"
    $vmConfig = Set-AzVMOperatingSystem -VM $vmConfig -Windows -ComputerName $VMName -Credential $vmCredential -ProvisionVMAgent -EnableAutoUpdate
    $vmConfig = Set-AzVMSourceImage -VM $vmConfig -PublisherName "MicrosoftWindowsDesktop" -Offer "Windows-10" -Skus "win10-21h2-pro-g2" -Version "latest"

    # Create a Virtual Network and Subnet specific for this VM
    $vnetName = "$VMName-VNet"
    $subnetName = "$VMName-Subnet"
    $vnet = Invoke-Retry -ScriptBlock { New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Location $Location -Name $vnetName -AddressPrefix "10.2.0.0/16" } -ActionName "Create VNet $vnetName"
    $vnet = Add-AzVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix "10.2.0.0/24" -VirtualNetwork $vnet
    $vnet | Set-AzVirtualNetwork

    # Refresh the VNet object to ensure the Subnets property is updated
    $vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $ResourceGroupName

    # Create a Public IP and NIC using the updated VNet object
    $pip = Invoke-Retry -ScriptBlock { New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Location $Location -Name "$VMName-PIP" -AllocationMethod Static } -ActionName "Create Public IP for $VMName"
    $nic = Invoke-Retry -ScriptBlock { New-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Location $Location -Name "$VMName-NIC" -SubnetId $vnet.Subnets[0].Id -PublicIpAddressId $pip.Id } -ActionName "Create NIC for $VMName"
    $vmConfig = Add-AzVMNetworkInterface -VM $vmConfig -Id $nic.Id

    # Explicitly set the security profile to a valid value ("Standard")
    $vmConfig = Set-AzVMSecurityProfile -VM $vmConfig -SecurityType "TrustedLaunch"

    # Deploy the VM
    Invoke-Retry -ScriptBlock { New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $vmConfig } -ActionName "Deploy VM $VMName"

    # Retrieve the deployed VM to get its resource ID
    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
    Write-Host "[+] VM '$VMName' deployed successfully."

    # Assign the custom role to Bob for this VM
    Write-Host "[*] Assigning custom role 'VM Command Executor' to Bob for VM $VMName..." -ForegroundColor Cyan
    $bob = Get-AzADUser -UserPrincipalName "bob.smith@tropicanabayhotels.com"
    if ($bob) {
        try {
            Invoke-Retry -ScriptBlock { New-AzRoleAssignment -ObjectId $bob.Id -RoleDefinitionName "VM Command Executor" -Scope $vm.Id | Out-Null } -ActionName "Assign Custom Role to Bob for $VMName"
            Write-Host "[+] Custom role assigned to Bob for VM '$VMName'." -ForegroundColor Green
        }
        catch {
            Write-Warning "[-] Failed to assign custom role to Bob: $_"
        }
    }
    else {
        Write-Warning "[-] Bob not found in Azure AD. Cannot assign custom role."
    }
	
	# Add a Flag to the Desktop of Administrator
	Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId "RunPowerShellScript" -ScriptString "echo 'FLAG{TBH_VM_C0MM4Nd_3xEcU7i0n}' > C:\Users\Public\Desktop\flag.txt"
}

# ---------------- SPN Permissions ----------------
function Grant-SPNAccess {
    param (
        [Parameter(Mandatory = $true)][pscustomobject]$spnData  # Object from your SPN creation (clientId, tenantId, clientSecret)
    )

    $clientId     = $spnData.clientId
    $tenantId     = $spnData.tenantId
    $clientSecret = "$($spnData.clientSecret)"

    Write-Host "`n[*] Processing SPN: $clientId" -ForegroundColor Cyan

    try {
        # Step 1: Get Application and SPN
        $app     = Get-MgApplication -Filter "appId eq '$clientId'" -ErrorAction Stop
        $spn     = Get-MgServicePrincipal -Filter "appId eq '$clientId'" -ErrorAction Stop
        $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop

        if (-not $app -or -not $spn -or -not $graphSp) {
            Write-Warning "[-] Could not retrieve App/SPN/Graph SP"
            return
        }

        # Step 2: Required Graph App permissions
        $permissions = @(
            @{ Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Type = "Role" }   # Directory.Read.All 
            @{ Id = "19dbc75e-c2e2-444c-a770-ec69d8559fc7"; Type = "Role" }   # Directory.ReadWrite.All 
			@{ Id = "741f803b-c850-494e-b5df-cde7c675a1ca"; Type = "Role" }   # User.ReadWrite.All
			@{ Id = "cc117bb9-00cf-4eb8-b580-ea2a878fe8f7"; Type = "Role" }   # User-PasswordProfile.ReadWrite.All
        )

        # Step 3: Update RequiredResourceAccess on App
        $requiredAccess = @(
            @{
                ResourceAppId  = $graphSp.AppId
                ResourceAccess = $permissions
            }
        )
        Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $requiredAccess
        Write-Host "[+] Graph permissions added to App Registration." -ForegroundColor Green

        # Step 4: Admin Consent by assigning AppRole to self (AppRoleAssignment)
        foreach ($perm in $permissions) {
            $roleId = $perm.Id
            $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spn.Id |
                        Where-Object { $_.ResourceId -eq $graphSp.Id -and $_.AppRoleId -eq $roleId }

            if (-not $existing) {
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spn.Id -BodyParameter @{
                    PrincipalId = $spn.Id
                    ResourceId  = $graphSp.Id
                    AppRoleId   = $roleId
                }
                Write-Host "[✓] Auto-consented: AppRole $roleId" -ForegroundColor Green
            }
            else {
                Write-Host "[=] AppRole $roleId already assigned. Skipping." -ForegroundColor Yellow
            }
        }

        # Step 5: Assign Azure RBAC: User Access Administrator
        try {
            $subscriptionId = (Get-AzContext).Subscription.Id
            Invoke-Retry -ScriptBlock {
                New-AzRoleAssignment -ObjectId $spn.Id -RoleDefinitionName "User Access Administrator" -Scope "/subscriptions/$subscriptionId" | Out-Null
            } -ActionName "RBAC Assignment"
            Write-Host "[+] Assigned 'User Access Administrator' at subscription scope." -ForegroundColor Green
        }
        catch {
            Write-Warning "[-] RBAC assignment failed: $($_.Exception.Message)"
        }

        # Step 6: Assign SPN to Directory Readers role (optional)
        try {
            $dirReaders = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Directory Readers" }
            if (-not $dirReaders) {
                $template = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq "Directory Readers" }
                if ($template) {
                    Enable-MgDirectoryRole -DirectoryRoleTemplateId $template.Id | Out-Null
                    Start-Sleep -Seconds 5
                    $dirReaders = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Directory Readers" }
                }
            }

            if ($dirReaders) {
                New-MgDirectoryRoleMemberByRef -DirectoryRoleId $dirReaders.Id -BodyParameter @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($spn.Id)"
                }
                Write-Host "[+] SPN added to 'Directory Readers' role." -ForegroundColor Green
            }
            else {
                Write-Warning "[-] Could not enable or find 'Directory Readers'."
            }
        }
        catch {
            if ($_.Exception.Message -match "object references already exist") {
                Write-Host "[=] SPN already in 'Directory Readers'. Skipping." -ForegroundColor Yellow
            }
            else {
                Write-Warning "[-] Directory Readers assignment failed: $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Warning "[-] Fatal error: $($_.Exception.Message)"
    }
}

# ---------------- VM Group ----------------

function Create-CustomRoleForVMExecution {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )

    Write-Host "[*] Creating custom role 'VM Command Executor'..." -ForegroundColor Cyan

    $roleDefinition = @{
        "Name"              = "VM Command Executor"
        "IsCustom"          = $true
        "Description"       = "Allows execution of commands on a Windows VM via runCommand"
        "Actions"           = @(
            "Microsoft.Compute/virtualMachines/runCommand/action"
        )
        "NotActions"        = @()
        "AssignableScopes"  = @(
            "/subscriptions/$SubscriptionId"
        )
    }

    $roleDefinitionJson = $roleDefinition | ConvertTo-Json -Depth 10
    $roleDefinitionFile = "$env:TEMP\vmCommandExecutorRole.json"
    $roleDefinitionJson | Out-File -FilePath $roleDefinitionFile -Encoding utf8

    try {
        Invoke-Retry -ScriptBlock { New-AzRoleDefinition -InputFile $roleDefinitionFile | Out-Null } -ActionName "Create Custom Role 'VM Command Executor'"
        Write-Host "[+] Custom role 'VM Command Executor' created." -ForegroundColor Green
    }
    catch {
        Write-Warning "[-] Failed to create custom role: $_"
    }
    Remove-Item $roleDefinitionFile -Force
}

function Main {
    Login-IfNeeded
    $ctx = Get-ContextInfo
    $global:subscriptionId = $ctx.SubId
    $global:tenantId = $ctx.Tenant

    if ($Action -eq "Destroy" -or $Action -eq "Reset") {
        Full-Destroy
        if ($Action -eq "Destroy") { return }
    }

    # 1) Create or retrieve SPN
    $spnData = Create-SPN

    # 2) Create resource groups
    Create-ResourceGroups

    # 3) Create users and groups
    Create-UsersAndGroups

    # 4) Create storage account + blob container
    $storageName = Create-StorageAndBlob
	
	# 4.1) Assign Alice permissions to Read Blob Container
	Assign-Reader-To-Alice

    # 5) Create Key Vault with Secrets
    Create-KeyVault -spnData $spnData

    # 6) Assign SPN permissions
	Grant-SPNAccess -spnData $spnData
	
	# 7) Create custom VM role
    Create-CustomRoleForVMExecution -SubscriptionId $global:subscriptionId

	# 9) Create VM for Bob
    Create-VM -ResourceGroupName "TBH-Engineering" -Location $location -VMName "TBH-VM"
	
	Write-Host "Lab Completely Build" -ForegroundColor Green
}
Main