<#
.SYNOPSIS
    Auditoria CENTRAL de estado de parches del SO en toda la flota Windows.
    Para cada equipo reporta: SO y build, fecha de la ultima actualizacion
    instalada, y -lo mas importante- cuantas actualizaciones le FALTAN
    (segun el propio Agente de Windows Update de cada maquina, que es la
    fuente autoritativa, no el numero de version del banner).

.DESCRIPTION
    Es de SOLO LECTURA: no instala ni cambia nada, solo consulta. Se conecta
    a cada equipo por WinRM (Invoke-Command) y corre localmente en el la
    consulta al Agente de Windows Update (COM 'Microsoft.Update.Session',
    busqueda IsInstalled=0), a Get-CimInstance Win32_OperatingSystem y a
    Get-HotFix. Genera un reporte en consola + CSV + HTML, resaltando los
    equipos con actualizaciones criticas/importantes pendientes.

    Requisitos:
      - WinRM habilitado en los equipos objetivo (Enable-PSRemoting; suele
        venir por GPO en dominio).
      - Ejecutar como una cuenta con permisos de administrador en ellos
        (la sesion actual, o -Credential).
      - Cada equipo debe tener una fuente de actualizaciones configurada
        (WSUS o Microsoft Update) para que la busqueda de pendientes funcione.

    NOTA: la consulta al Agente de Windows Update puede tardar de 15s a 2min
    POR EQUIPO. Con muchos equipos, usar -ThrottleLimit para paralelizar.

.PARAMETER ComputerName
    Uno o mas nombres/IPs de equipos.

.PARAMETER File
    Archivo de texto con un nombre/IP por linea.

.PARAMETER FromAuditJson
    Ruta a un reporte JSON de ip_audit_tool: extrae los hosts 'activos' cuyo
    SO estimado es Windows y los usa como objetivos (reutiliza el inventario).

.PARAMETER Credential
    Credenciales alternativas (si la sesion actual no es admin en los destinos).

.PARAMETER ThrottleLimit
    Cuantos equipos consultar en paralelo (default 10).

.PARAMETER OutputDir
    Carpeta de salida para CSV/HTML (default: reportes_parches).

.EXAMPLE
    .\patch_audit.ps1 -File equipos.txt

.EXAMPLE
    .\patch_audit.ps1 -FromAuditJson reportes\reporte_20260812.json -ThrottleLimit 15

.EXAMPLE
    # Solo la maquina local (prueba rapida, sin WinRM)
    .\patch_audit.ps1 -ComputerName localhost
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [string]$File,
    [string]$FromAuditJson,
    [System.Management.Automation.PSCredential]$Credential,
    [int]$ThrottleLimit = 10,
    [string]$OutputDir = "reportes_parches"
)

$ErrorActionPreference = "Continue"

# --- Construir la lista de equipos -----------------------------------------
$targets = New-Object System.Collections.Generic.List[string]
if ($ComputerName) { $ComputerName | ForEach-Object { $targets.Add($_) } }
if ($File) {
    Get-Content -Path $File | ForEach-Object {
        $t = $_.Trim()
        if ($t -and -not $t.StartsWith("#")) { $targets.Add($t) }
    }
}
if ($FromAuditJson) {
    try {
        $data = Get-Content -Raw -Path $FromAuditJson | ConvertFrom-Json
        foreach ($h in $data.resultados) {
            if ($h.activo -and ("$($h.sistema_operativo)" -like "*Windows*" -or "$($h.tipo_dispositivo)" -like "*Servidor*")) {
                $targets.Add($h.ip)
            }
        }
    } catch {
        Write-Warning "No se pudo leer el JSON de auditoria: $_"
    }
}
$targets = $targets | Select-Object -Unique
if (-not $targets -or $targets.Count -eq 0) {
    Write-Host "No se indicaron equipos. Use -ComputerName, -File o -FromAuditJson." -ForegroundColor Red
    return
}

Write-Host "Consultando estado de parches en $($targets.Count) equipo(s)..." -ForegroundColor Cyan
Write-Host "(puede tardar; el Agente de Windows Update es lento por equipo)`n" -ForegroundColor DarkGray

# --- Bloque que corre EN CADA equipo remoto --------------------------------
$scriptBlock = {
    $result = [ordered]@{
        Hostname          = $env:COMPUTERNAME
        SO                = $null
        Build             = $null
        UltimaActualiz    = $null
        DiasSinParche     = $null
        Pendientes        = 0
        PendientesCriticas= 0
        KBsPendientes     = ""
        Estado            = "OK"
        Detalle           = ""
    }
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $result.SO = $os.Caption
        $result.Build = $os.Version
    } catch { $result.Detalle += "OS?; " }

    try {
        $last = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } |
            Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($last) {
            $result.UltimaActualiz = $last.InstalledOn.ToString("yyyy-MM-dd")
            $result.DiasSinParche = [int]((Get-Date) - $last.InstalledOn).TotalDays
        }
    } catch { $result.Detalle += "HotFix?; " }

    # Consulta autoritativa: que le FALTA instalar segun Windows Update.
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $search = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $pending = $search.Updates
        $result.Pendientes = $pending.Count
        $crit = 0
        $kbs = @()
        foreach ($u in $pending) {
            if ($u.MsrcSeverity -eq "Critical" -or $u.MsrcSeverity -eq "Important") { $crit++ }
            foreach ($kb in $u.KBArticleIDs) { $kbs += "KB$kb" }
        }
        $result.PendientesCriticas = $crit
        $result.KBsPendientes = ($kbs | Select-Object -Unique) -join ", "
    } catch {
        $result.Detalle += "WU-Agent no consultable ($($_.Exception.Message)); "
    }

    # Clasificacion de estado
    if ($result.PendientesCriticas -gt 0) {
        $result.Estado = "CRITICO ($($result.PendientesCriticas) criticas/importantes)"
    } elseif ($result.Pendientes -gt 0) {
        $result.Estado = "Pendiente ($($result.Pendientes) actualizaciones)"
    } elseif ($result.DiasSinParche -ne $null -and $result.DiasSinParche -gt 45) {
        $result.Estado = "Revisar (sin parches hace $($result.DiasSinParche) dias)"
    } else {
        $result.Estado = "OK"
    }
    [pscustomobject]$result
}

# --- Ejecutar contra la flota ----------------------------------------------
$invokeParams = @{
    ComputerName  = $targets
    ScriptBlock   = $scriptBlock
    ThrottleLimit = $ThrottleLimit
    ErrorAction   = "SilentlyContinue"
    ErrorVariable = "connErrors"
}
if ($Credential) { $invokeParams.Credential = $Credential }

$rows = @()
# La maquina local se consulta directo (no requiere WinRM contra si misma).
$localNames = @($env:COMPUTERNAME, "localhost", "127.0.0.1", ".")
$localTargets = $targets | Where-Object { $localNames -contains $_ }
$remoteTargets = $targets | Where-Object { $localNames -notcontains $_ }

if ($localTargets) {
    Write-Host "Consultando equipo local..." -ForegroundColor DarkGray
    $rows += & $scriptBlock
}
if ($remoteTargets) {
    $invokeParams.ComputerName = $remoteTargets
    $rows += Invoke-Command @invokeParams
}

# Equipos que no respondieron por WinRM
foreach ($err in $connErrors) {
    $unreachable = $err.TargetObject
    if ($unreachable) {
        $rows += [pscustomobject]@{
            Hostname = $unreachable; SO = "-"; Build = "-"; UltimaActualiz = "-"
            DiasSinParche = $null; Pendientes = $null; PendientesCriticas = $null
            KBsPendientes = ""; Estado = "INALCANZABLE (WinRM)"; Detalle = "$($err.Exception.Message)"
        }
    }
}

# --- Reporte ----------------------------------------------------------------
# @(...) fuerza array: con un solo equipo, PowerShell trataria el resultado
# como escalar y .Count quedaria en blanco en el resumen.
$rows = @($rows | Sort-Object -Property @{Expression={ if ($_.PendientesCriticas) {$_.PendientesCriticas} else {0} }; Descending=$true}, Hostname)

Write-Host "`n========================= ESTADO DE PARCHES =========================" -ForegroundColor Cyan
$rows | Format-Table Hostname, SO, Build, UltimaActualiz, Pendientes, PendientesCriticas, Estado -AutoSize | Out-String -Width 4096 | Write-Host

$conParche      = @($rows | Where-Object { $_.Estado -eq "OK" }).Count
$conPendientes  = @($rows | Where-Object { $_.Pendientes -gt 0 }).Count
$conCriticas    = @($rows | Where-Object { $_.PendientesCriticas -gt 0 }).Count
$inalcanzables  = @($rows | Where-Object { $_.Estado -like "INALCANZABLE*" }).Count
Write-Host "Resumen: $($rows.Count) equipos | $conParche al dia | $conPendientes con pendientes | $conCriticas con criticas | $inalcanzables inalcanzables" -ForegroundColor Yellow

# --- Exportar CSV + HTML ----------------------------------------------------
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath = Join-Path $OutputDir "parches_$stamp.csv"
$htmlPath = Join-Path $OutputDir "parches_$stamp.html"

$rows | Select-Object Hostname, SO, Build, UltimaActualiz, DiasSinParche, Pendientes, PendientesCriticas, KBsPendientes, Estado, Detalle |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$style = @"
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#0b1220;color:#e5e7eb;padding:20px;}
h1{color:#f9fafb;} table{border-collapse:collapse;width:100%;background:#111827;}
th,td{border:1px solid #374151;padding:6px 10px;font-size:13px;text-align:left;}
th{background:#1f2937;} tr:nth-child(even){background:#151f2e;}
.crit{background:#7f1d1d;color:#fff;font-weight:bold;} .pend{background:#b45309;color:#fff;}
.unr{background:#4b5563;color:#fff;} .ok{color:#22c55e;}
</style>
"@
$htmlRows = foreach ($r in $rows) {
    $cls = ""
    if ($r.Estado -like "CRITICO*") { $cls = "crit" }
    elseif ($r.Estado -like "Pendiente*") { $cls = "pend" }
    elseif ($r.Estado -like "INALCANZABLE*") { $cls = "unr" }
    "<tr class='$cls'><td>$($r.Hostname)</td><td>$($r.SO)</td><td>$($r.Build)</td><td>$($r.UltimaActualiz)</td><td>$($r.Pendientes)</td><td>$($r.PendientesCriticas)</td><td>$($r.KBsPendientes)</td><td>$($r.Estado)</td></tr>"
}
$html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'><title>Estado de parches</title>$style</head><body>
<h1>Estado de parches del SO - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</h1>
<p>$($rows.Count) equipos | $conParche al dia | $conPendientes con pendientes | <b>$conCriticas con criticas/importantes</b> | $inalcanzables inalcanzables</p>
<table><thead><tr><th>Equipo</th><th>SO</th><th>Build</th><th>Ultima actualiz.</th><th>Pendientes</th><th>Criticas</th><th>KBs pendientes</th><th>Estado</th></tr></thead>
<tbody>$($htmlRows -join "`n")</tbody></table></body></html>
"@
$html | Out-File -FilePath $htmlPath -Encoding UTF8

Write-Host "`nReporte CSV:  $csvPath" -ForegroundColor Green
Write-Host "Reporte HTML: $htmlPath" -ForegroundColor Green
Write-Host "`nPriorice los equipos en rojo (criticas/importantes pendientes) y los INALCANZABLES (revisar por que no responden por WinRM)." -ForegroundColor Yellow
