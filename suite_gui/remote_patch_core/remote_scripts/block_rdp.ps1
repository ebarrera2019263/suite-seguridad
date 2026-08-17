# Ejecutado EN LA MAQUINA REMOTA via Invoke-Command -FilePath.
# Bloquea RDP entrante (TCP y UDP 3389) con reglas de firewall dedicadas.
# Desde Windows 8/Server 2012 RDP tambien usa transporte UDP 3389, asi que
# un escaneo UDP (nmap -sU) lo veria si solo se bloqueara TCP.
# Deliberadamente NO toca WinRM (5985/5986): esta misma herramienta necesita
# seguir pudiendo llegar a la maquina despues de este cambio.
$ErrorActionPreference = "Stop"
$ruleTcp = "AbyssalPatch-Block-RDP-Inbound"
$ruleUdp = "AbyssalPatch-Block-RDP-Inbound-UDP"
$errors = @()

try {
    if (-not (Get-NetFirewallRule -DisplayName $ruleTcp -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleTcp -Direction Inbound -Action Block `
            -Protocol TCP -LocalPort 3389 -Profile Any | Out-Null
    }
}
catch { $errors += "TCP: $($_.Exception.Message)" }

try {
    if (-not (Get-NetFirewallRule -DisplayName $ruleUdp -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleUdp -Direction Inbound -Action Block `
            -Protocol UDP -LocalPort 3389 -Profile Any | Out-Null
    }
}
catch { $errors += "UDP: $($_.Exception.Message)" }

$success = ($errors.Count -eq 0)
[PSCustomObject]@{
    Hostname = $env:COMPUTERNAME
    Action   = "block_rdp"
    Success  = $success
    Detail   = if ($success) {
        "Reglas de firewall activas: bloquean TCP y UDP 3389 entrante. WinRM no fue tocado."
    } else {
        "Bloqueo de RDP con errores: $($errors -join ' | ')"
    }
}
