# Revierte block_rdp.ps1: elimina AMBAS reglas (TCP y UDP) que bloqueaban RDP.
Remove-NetFirewallRule -DisplayName "AbyssalPatch-Block-RDP-Inbound" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "AbyssalPatch-Block-RDP-Inbound-UDP" -ErrorAction SilentlyContinue

[PSCustomObject]@{
    Hostname = $env:COMPUTERNAME
    Action   = "undo_block_rdp"
    Success  = $true
    Detail   = "Regla de bloqueo de RDP eliminada. RDP vuelve a estar accesible segun el resto de la configuracion del equipo."
}
