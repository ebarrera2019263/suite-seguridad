<#
.SYNOPSIS
    Crea y enlaza los GPOs de endurecimiento que NO tienen riesgo conocido de
    interrumpir impresoras compartidas ni aplicaciones internas legacy.

.DESCRIPTION
    Automatiza (via el modulo GroupPolicy y NetSecurity) la creacion de 5 GPOs:
      1) SEC-03 Deshabilitar Telnet Server
      2) SEC-08 Deshabilitar LLMNR
      3) SEC-11 Forzar proteccion en tiempo real de Windows Defender
      4) SEC-10 Firewall: bloquear puertos de Telnet/VNC/TeamViewer/AnyDesk entrantes
      5) SEC-13 Windows Update automatico (SOLO estaciones de trabajo)

    Deliberadamente NO crea (por riesgo documentado de romper impresoras o
    aplicaciones internas legacy -- aplicarlos aparte, app por app, despues de
    validar compatibilidad; ver GPO_HARDENING.md/pdf secciones 2, 3, 5, 6, 7, 9, 12):
      - SEC-01 Deshabilitar SMBv1
      - SEC-02 Exigir firma SMB
      - SEC-04 Deshabilitar TLS/SSL obsoleto y cifrados debiles
      - SEC-05 Deshabilitar cuenta Guest (requiere plantilla de seguridad, no registro)
      - SEC-06 Mantener UAC activo
      - SEC-07 Eliminar autologon
      - SEC-12 Politica de bloqueo de cuentas

.NOTES
    - Este script NO fue probado contra un Active Directory real: fue escrito
      en un entorno sandbox sin dominio disponible. Revisalo con tu equipo de
      IT antes de correrlo, y ejecutalo primero contra la OU piloto.
    - Requiere: PowerShell como Administrador de dominio (o con permisos
      delegados de creacion/edicion de GPO), en un equipo con RSAT instalado
      (modulos GroupPolicy y NetSecurity -- GroupPolicyManagementConsole
      feature). Se puede correr desde un Controlador de Dominio o desde una
      estacion de administracion con RSAT.
    - Nada se enlaza a produccion por defecto: el parametro -PilotOU es
      obligatorio y vos decidis a que OU apunta.

.PARAMETER PilotOU
    Distinguished Name de la OU de prueba donde se enlazaran los GPOs.
    Ejemplo: "OU=Piloto-Hardening,OU=Equipos,DC=empresa,DC=local"

.PARAMETER WorkstationsOU
    DN de la OU que contiene SOLO estaciones de trabajo (nunca servidores),
    usada para el GPO de Windows Update automatico. Si no se especifica, usa
    la misma OU piloto.

.PARAMETER DomainFQDN
    Nombre de dominio DNS completo (ej. empresa.local). Si no se especifica,
    se intenta detectar automaticamente.

.EXAMPLE
    .\create_gpos.ps1 -PilotOU "OU=Piloto-Hardening,DC=empresa,DC=local"
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$PilotOU,

    [Parameter(Mandatory = $false)]
    [string]$WorkstationsOU,

    [Parameter(Mandatory = $false)]
    [string]$DomainFQDN,

    # Subred(es) de gestion desde donde SI se permite RDP (ej. "10.0.10.0/24"
    # o varias separadas por coma). Si se especifica, se crea el GPO SEC-14 que
    # permite RDP solo desde ahi y lo bloquea del resto (queda invisible a un
    # scanner fuera de esa subred). Si se omite, SEC-14 no se crea (RDP sin tocar).
    [Parameter(Mandatory = $false)]
    [string[]]$RdpManagementSubnet
)

$ErrorActionPreference = "Stop"

if (-not $WorkstationsOU) { $WorkstationsOU = $PilotOU }

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " Este script va a crear GPOs y enlazarlos a:" -ForegroundColor Cyan
Write-Host "   OU piloto (general):      $PilotOU" -ForegroundColor Cyan
Write-Host "   OU estaciones (Update):   $WorkstationsOU" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
$confirm = Read-Host "Escriba 'confirmo' para continuar, o cualquier otra cosa para cancelar"
if ($confirm -ne "confirmo") {
    Write-Host "Cancelado por el usuario." -ForegroundColor Yellow
    return
}

try {
    Import-Module GroupPolicy -ErrorAction Stop
} catch {
    Write-Error "No se pudo cargar el modulo GroupPolicy. Instale RSAT: Group Policy Management. $_"
    return
}
try {
    Import-Module NetSecurity -ErrorAction Stop
} catch {
    Write-Error "No se pudo cargar el modulo NetSecurity (necesario para la regla de firewall). $_"
    return
}

if (-not $DomainFQDN) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $DomainFQDN = (Get-ADDomain).DNSRoot
    } catch {
        if ($env:USERDNSDOMAIN) {
            $DomainFQDN = $env:USERDNSDOMAIN
            Write-Host "Modulo ActiveDirectory no disponible; usando USERDNSDOMAIN detectado: $DomainFQDN" -ForegroundColor Yellow
        } else {
            Write-Error "No se pudo determinar el dominio. Especifique -DomainFQDN manualmente."
            return
        }
    }
}

function New-OrGetGPO {
    param([string]$Name)
    $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if (-not $gpo) {
        Write-Host "Creando GPO: $Name" -ForegroundColor Cyan
        $gpo = New-GPO -Name $Name
    } else {
        Write-Host "GPO ya existe, reutilizando: $Name" -ForegroundColor Yellow
    }
    return $gpo
}

function Add-GPOLinkSafe {
    param([string]$Name, [string]$Target)
    try {
        $existing = Get-GPInheritance -Target $Target -ErrorAction Stop
        if ($existing.GpoLinks.DisplayName -contains $Name) {
            Write-Host "  Ya estaba enlazado a $Target" -ForegroundColor DarkGray
            return
        }
    } catch { }
    try {
        New-GPLink -Name $Name -Target $Target -ErrorAction Stop | Out-Null
        Write-Host "  Enlazado a $Target" -ForegroundColor Green
    } catch {
        Write-Warning "  No se pudo enlazar '$Name' a $Target : $_"
    }
}

$results = @()

# ---------------------------------------------------------------------------
# 1) SEC-03 - Deshabilitar servidor Telnet (via registro del servicio TlntSvr)
# ---------------------------------------------------------------------------
try {
    $gpo = New-OrGetGPO "SEC-03 Deshabilitar Telnet Server"
    Set-GPPrefRegistryValue -Name $gpo.DisplayName -Context Computer -Action Update `
        -Key "HKLM\SYSTEM\CurrentControlSet\Services\TlntSvr" -ValueName "Start" -Type DWord -Value 4 | Out-Null
    Add-GPOLinkSafe -Name $gpo.DisplayName -Target $PilotOU
    $results += [pscustomobject]@{ GPO = $gpo.DisplayName; Estado = "OK" }
} catch {
    Write-Warning "Fallo SEC-03: $_"
    $results += [pscustomobject]@{ GPO = "SEC-03 Deshabilitar Telnet Server"; Estado = "FALLO: $_" }
}

# ---------------------------------------------------------------------------
# 2) SEC-08 - Deshabilitar LLMNR
# ---------------------------------------------------------------------------
try {
    $gpo = New-OrGetGPO "SEC-08 Deshabilitar LLMNR"
    Set-GPRegistryValue -Name $gpo.DisplayName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -ValueName "EnableMulticast" -Type DWord -Value 0 | Out-Null
    Add-GPOLinkSafe -Name $gpo.DisplayName -Target $PilotOU
    $results += [pscustomobject]@{ GPO = $gpo.DisplayName; Estado = "OK" }
} catch {
    Write-Warning "Fallo SEC-08: $_"
    $results += [pscustomobject]@{ GPO = "SEC-08 Deshabilitar LLMNR"; Estado = "FALLO: $_" }
}

# ---------------------------------------------------------------------------
# 3) SEC-11 - Forzar proteccion en tiempo real de Windows Defender
#    (si alguna maquina de la OU usa un antivirus de terceros, excluila con
#    Security Filtering despues de correr este script)
# ---------------------------------------------------------------------------
try {
    $gpo = New-OrGetGPO "SEC-11 Defender Proteccion en Tiempo Real"
    Set-GPRegistryValue -Name $gpo.DisplayName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
        -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 0 | Out-Null
    Add-GPOLinkSafe -Name $gpo.DisplayName -Target $PilotOU
    $results += [pscustomobject]@{ GPO = $gpo.DisplayName; Estado = "OK (revisar exclusion si hay AV de terceros)" }
} catch {
    Write-Warning "Fallo SEC-11: $_"
    $results += [pscustomobject]@{ GPO = "SEC-11 Defender Proteccion en Tiempo Real"; Estado = "FALLO: $_" }
}

# ---------------------------------------------------------------------------
# 4) SEC-10 - Firewall: bloquear Telnet/VNC/TeamViewer/AnyDesk entrantes
# ---------------------------------------------------------------------------
try {
    $fwName = "SEC-10 Firewall Bloquear Acceso Remoto No Autorizado"
    $gpo = New-OrGetGPO $fwName
    $policyStore = "$DomainFQDN\$fwName"
    $gpoSession = Open-NetGPO -PolicyStore $policyStore
    $existingRule = Get-NetFirewallRule -GPOSession $gpoSession -DisplayName "Bloquear Telnet-VNC-TeamViewer-AnyDesk entrantes" -ErrorAction SilentlyContinue
    if (-not $existingRule) {
        New-NetFirewallRule -GPOSession $gpoSession `
            -DisplayName "Bloquear Telnet-VNC-TeamViewer-AnyDesk entrantes" `
            -Direction Inbound -Action Block -Protocol TCP `
            -LocalPort 23, 5900, 5901, 5938, 7070, 6568 | Out-Null
    }
    Save-NetGPO -GPOSession $gpoSession
    Add-GPOLinkSafe -Name $fwName -Target $PilotOU
    $results += [pscustomobject]@{ GPO = $fwName; Estado = "OK" }
} catch {
    Write-Warning "Fallo SEC-10 (firewall): $_"
    $results += [pscustomobject]@{ GPO = "SEC-10 Firewall Bloquear Acceso Remoto No Autorizado"; Estado = "FALLO: $_" }
}

# ---------------------------------------------------------------------------
# 5) SEC-13 - Windows Update automatico -- SOLO estaciones de trabajo
# ---------------------------------------------------------------------------
try {
    $gpo = New-OrGetGPO "SEC-13 Windows Update Automatico (solo estaciones)"
    $auKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $auKey -ValueName "NoAutoUpdate" -Type DWord -Value 0 | Out-Null
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $auKey -ValueName "AUOptions" -Type DWord -Value 4 | Out-Null
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $auKey -ValueName "ScheduledInstallDay" -Type DWord -Value 0 | Out-Null
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $auKey -ValueName "ScheduledInstallTime" -Type DWord -Value 3 | Out-Null
    Add-GPOLinkSafe -Name $gpo.DisplayName -Target $WorkstationsOU
    $results += [pscustomobject]@{ GPO = $gpo.DisplayName; Estado = "OK (enlazado solo a $WorkstationsOU)" }
} catch {
    Write-Warning "Fallo SEC-13: $_"
    $results += [pscustomobject]@{ GPO = "SEC-13 Windows Update Automatico"; Estado = "FALLO: $_" }
}

# ---------------------------------------------------------------------------
# 6) SEC-14 - Firewall: restringir RDP (3389) a la subred de gestion
#    Solo se crea si se paso -RdpManagementSubnet. Windows evalua Allow antes
#    que Block, asi que RDP queda accesible SOLO desde la gestion e invisible
#    a un scanner fuera de esa subred. Cierra el gap "RDP sigue expuesto".
# ---------------------------------------------------------------------------
if ($RdpManagementSubnet -and $RdpManagementSubnet.Count -gt 0) {
    try {
        $fwName = "SEC-14 Firewall Restringir RDP"
        $gpo = New-OrGetGPO $fwName
        $policyStore = "$DomainFQDN\$fwName"
        $gpoSession = Open-NetGPO -PolicyStore $policyStore
        if (-not (Get-NetFirewallRule -GPOSession $gpoSession -DisplayName "Permitir RDP solo gestion" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -GPOSession $gpoSession -DisplayName "Permitir RDP solo gestion" `
                -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 `
                -RemoteAddress $RdpManagementSubnet | Out-Null
        }
        if (-not (Get-NetFirewallRule -GPOSession $gpoSession -DisplayName "Bloquear RDP resto" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -GPOSession $gpoSession -DisplayName "Bloquear RDP resto" `
                -Direction Inbound -Action Block -Protocol TCP -LocalPort 3389 | Out-Null
            New-NetFirewallRule -GPOSession $gpoSession -DisplayName "Bloquear RDP resto UDP" `
                -Direction Inbound -Action Block -Protocol UDP -LocalPort 3389 | Out-Null
        }
        Save-NetGPO -GPOSession $gpoSession
        Add-GPOLinkSafe -Name $fwName -Target $PilotOU
        $results += [pscustomobject]@{ GPO = $fwName; Estado = "OK (RDP permitido solo desde $($RdpManagementSubnet -join ', '))" }
    } catch {
        Write-Warning "Fallo SEC-14 (firewall RDP): $_"
        $results += [pscustomobject]@{ GPO = "SEC-14 Firewall Restringir RDP"; Estado = "FALLO: $_" }
    }
} else {
    Write-Host "SEC-14 (restringir RDP) omitido: no se paso -RdpManagementSubnet. RDP no fue tocado." -ForegroundColor DarkGray
}

Write-Host "`n=========================== RESUMEN ===========================" -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-String | Write-Host
Write-Host "Excluidos a proposito (riesgo para impresoras/apps -- ver GPO_HARDENING.md):" -ForegroundColor Yellow
Write-Host "  SMBv1, Firma SMB, NetBIOS, TLS/cifrados, UAC, Autologon, Bloqueo de cuentas, Cuenta Guest" -ForegroundColor Yellow
Write-Host "`nSiguiente paso: en un equipo de la OU piloto, correr 'gpupdate /force' y validar" -ForegroundColor Green
Write-Host "impresoras + aplicaciones internas antes de expandir a mas OUs." -ForegroundColor Green
