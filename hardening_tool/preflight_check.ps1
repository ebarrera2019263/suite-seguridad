<#
.SYNOPSIS
    Pre-chequeo de USO ACTUAL antes de aplicar IPHardeningTool.exe: muestra
    que esta usando el servidor hoy de lo que las correcciones tocarian, y
    activa auditoria para lo que no se puede ver de forma retroactiva
    (SMBv1, TLS/Schannel).

.DESCRIPTION
    Es de SOLO LECTURA salvo dos pasos explicitos que solo ACTIVAN LOGGING
    (no cambian ningun comportamiento del servidor, no rompen nada):
    auditoria de acceso SMB1 y logging detallado de Schannel. Ambos son
    reversibles y no requieren reinicio.

    Uso recomendado:
      1. Correr este script AHORA (te da una foto del uso actual + activa
         la auditoria para lo que necesita ventana de tiempo).
      2. Dejar pasar unos dias de uso normal del servidor.
      3. Volver a correr este mismo script -- la seccion de eventos
         Schannel/SMB1 va a mostrar todo lo que se conecto en el medio.
      4. Recien ahi, correr IPHardeningTool.exe y decidir con datos reales
         que aplicar y que no.

.PARAMETER SkipAuditLogging
    No activa el logging de SMB1/Schannel (por si ya los activaste en una
    corrida anterior y no queres reiniciar la ventana de medicion).

.PARAMETER EventDays
    Cuantos dias hacia atras revisar en los logs de eventos (default: 7).
#>
param(
    [switch]$SkipAuditLogging,
    [int]$EventDays = 7
)

$ErrorActionPreference = "Continue"
$transcriptPath = Join-Path $PSScriptRoot "preflight_check_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -ErrorAction SilentlyContinue | Out-Null

function Write-Section($title) {
    Write-Host "`n=== $title ===" -ForegroundColor Cyan
}

function Try-Run {
    param([scriptblock]$Block, [string]$OnFailMessage = "No se pudo determinar (permisos o SO no lo soporta).")
    try { & $Block } catch { Write-Host "  $OnFailMessage" -ForegroundColor Yellow }
}

Write-Host "PRE-CHEQUEO DE USO ANTES DE ENDURECER" -ForegroundColor Yellow
Write-Host "Equipo: $env:COMPUTERNAME | Fecha: $(Get-Date)`n"

# --- 1. Conexiones activas ahora mismo -------------------------------------
Write-Section "1. Conexiones TCP activas ahora (quien esta usando el servidor)"
Try-Run {
    Get-NetTCPConnection -State Established -ErrorAction Stop |
        Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess |
        ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                PuertoLocal  = $_.LocalPort
                IPRemota     = $_.RemoteAddress
                PuertoRemoto = $_.RemotePort
                Proceso      = if ($proc) { $proc.ProcessName } else { "?" }
            }
        } | Sort-Object PuertoLocal -Unique | Format-Table -AutoSize
}

# --- 2. Puertos escuchando + cobertura de firewall --------------------------
Write-Section "2. Puertos escuchando y si el firewall los permite"
Try-Run {
    $listening = Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Select-Object -ExpandProperty LocalPort -Unique | Sort-Object
    $fwRules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue

    foreach ($port in $listening) {
        $covered = $false
        foreach ($rule in $fwRules) {
            $filter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            if ($filter -and ($filter.LocalPort -contains "$port" -or $filter.LocalPort -eq "Any")) {
                $covered = $true
                break
            }
        }
        if ($covered) {
            Write-Host ("  Puerto {0,-6} CUBIERTO por regla de firewall" -f $port) -ForegroundColor Green
        }
        else {
            Write-Host ("  Puerto {0,-6} SIN REGLA -- se bloquearia si activas el firewall" -f $port) -ForegroundColor Red
        }
    }

    $anyProfileOff = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Enabled }
    if ($anyProfileOff) {
        Write-Host "  Aviso: el firewall esta deshabilitado en al menos un perfil ahora mismo -- por eso ningun trafico se bloquea todavia, aunque la tabla de arriba diga 'SIN REGLA'." -ForegroundColor Yellow
    }
}

# --- 3. SMB ------------------------------------------------------------------
Write-Section "3. SMB: version, firma, sesiones activas"
Try-Run {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    Write-Host "  SMBv1 (feature de Windows): $($smb1.State)"
}
Try-Run {
    Get-SmbServerConfiguration -ErrorAction Stop |
        Select-Object RequireSecuritySignature, EnableSMB1Protocol | Format-Table -AutoSize
}
Write-Host "  Sesiones SMB activas ahora (clientes conectados):"
Try-Run {
    Get-SmbSession -ErrorAction Stop | Select-Object ClientComputerName, ClientUserName, Dialect, NumOpens | Format-Table -AutoSize
}

if (-not $SkipAuditLogging) {
    Try-Run {
        Set-SmbServerConfiguration -AuditSmb1Access $true -Confirm:$false -ErrorAction Stop
        Write-Host "  Auditoria de acceso SMB1 ACTIVADA. En unos dias, revisa: Visor de Eventos > Aplicaciones y servicios > Microsoft > Windows > SMBServer > Audit" -ForegroundColor Green
    } "No se pudo activar la auditoria SMB1 (¿SMBv1 ya esta deshabilitado del todo?)."
}

# --- 4. TLS / Schannel ---------------------------------------------------------
Write-Section "4. TLS: protocolos vigentes y eventos Schannel recientes"
$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
$base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
foreach ($p in $protocols) {
    $serverPath = Join-Path (Join-Path $base $p) "Server"
    $enabled = (Get-ItemProperty -Path $serverPath -Name Enabled -ErrorAction SilentlyContinue).Enabled
    $status = if ($enabled -eq 0) { "deshabilitado explicitamente" }
              elseif ($enabled -eq 1) { "habilitado explicitamente" }
              else { "valor por defecto del SO (no forzado)" }
    Write-Host ("  {0,-10} {1}" -f $p, $status)
}

if (-not $SkipAuditLogging) {
    Try-Run {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Name "EventLogging" -Value 7 -Type DWord -ErrorAction Stop
        Write-Host "  Logging detallado de Schannel ACTIVADO. En unos dias, revisa: Visor de Eventos > Windows Logs > System, origen 'Schannel'" -ForegroundColor Green
    }
}

Write-Host "`n  Eventos Schannel de los ultimos $EventDays dia(s) (si hay, muestran que protocolo/cifrado nego cada cliente):"
Try-Run {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Schannel'; StartTime = (Get-Date).AddDays(-$EventDays) } -ErrorAction Stop |
        Select-Object TimeCreated, Id, Message -First 20 | Format-Table -Wrap -AutoSize
} "  (sin eventos Schannel registrados todavia -- normal si es la primera corrida; volve a correr este script en unos dias)"

# --- 5. RDP --------------------------------------------------------------------
Write-Section "5. RDP: NLA actual y sesiones"
Try-Run {
    $nla = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction Stop).UserAuthentication
    Write-Host "  NLA actual: $(if ($nla -eq 1) {'activo'} elseif ($nla -eq 0) {'inactivo'} else {'no definido'})"
}
Write-Host "  Sesiones RDP activas:"
Try-Run { quser 2>$null } "  (nadie conectado por RDP ahora, o el comando no esta disponible en esta edicion)"

# --- 6. Telnet -------------------------------------------------------------------
Write-Section "6. Telnet"
$telnetSvc = Get-Service TlntSvr -ErrorAction SilentlyContinue
if ($telnetSvc) {
    Write-Host "  Servicio Telnet: $($telnetSvc.Status)"
    Write-Host "  Conexiones activas en puerto 23:"
    Try-Run { Get-NetTCPConnection -LocalPort 23 -ErrorAction Stop | Format-Table -AutoSize }
}
else {
    Write-Host "  Servicio Telnet no instalado -- nada que romper aqui." -ForegroundColor Green
}

# --- 7. LLMNR / NetBIOS -----------------------------------------------------------
Write-Section "7. LLMNR / NetBIOS"
$llmnr = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast
Write-Host "  LLMNR: $(if ($llmnr -eq 0) {'ya deshabilitado'} else {'habilitado (valor por defecto)'})"
Write-Host "  Si todos los nombres relevantes resuelven por DNS, es seguro deshabilitarlo. Probalo con Resolve-DnsName <nombre>."

# --- 8. WinRM ------------------------------------------------------------------
Write-Section "8. WinRM"
Try-Run {
    $winrmSvc = Get-Service WinRM -ErrorAction Stop
    Write-Host "  Servicio WinRM: $($winrmSvc.Status)"
    if ($winrmSvc.Status -eq 'Running') {
        $allowBasic = (Get-Item WSMan:\localhost\Service\Auth\Basic -ErrorAction SilentlyContinue).Value
        Write-Host "  Auth basica actualmente: $allowBasic"
        Write-Host "  Revisa que herramientas de automatizacion/monitoreo te conectan por WinRM y si usan Basic auth (se romperian) o Kerberos/Negotiate (no se rompen)."
    }
}

# --- 9. Cuenta Guest / UAC / Defender (bajo riesgo, solo informativo) ------------
Write-Section "9. Cuenta Guest / UAC / Defender (bajo riesgo, solo informativo)"
Try-Run { Write-Host "  Guest habilitada: $((Get-LocalUser -Name Guest -ErrorAction Stop).Enabled)" }
$uac = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
Write-Host "  UAC: $(if ($uac -eq 0) {'deshabilitado'} else {'activo'})"
Try-Run { Write-Host "  Defender tiempo real: $((Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled)" }

Write-Host "`n=== LISTO ===" -ForegroundColor Cyan
Write-Host "Log completo guardado en: $transcriptPath" -ForegroundColor Cyan
Write-Host "Si se activo auditoria (SMB1/Schannel), volve a correr este mismo script en unos dias para ver los eventos acumulados ANTES de aplicar esos fixes puntuales en IPHardeningTool.exe." -ForegroundColor Yellow

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
