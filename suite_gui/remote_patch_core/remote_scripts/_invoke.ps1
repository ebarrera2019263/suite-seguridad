<#
Wrapper generico: ejecuta un script LOCAL (ScriptPath) EN LA MAQUINA REMOTA
(ComputerName) via WinRM (Invoke-Command). Si se pasa -Username, la
contrasena se lee de STDIN (no como argumento de linea de comandos) para
que no quede visible en el Administrador de tareas / listado de procesos
de otros usuarios mientras el subproceso esta vivo. Si no se pasa
-Username, usa las credenciales de la sesion actual (caso comun: quien
corre esta herramienta ya es administrador de dominio en las maquinas
destino).
#>
param(
    [Parameter(Mandatory = $true)][string]$ComputerName,
    [string]$Username,
    [Parameter(Mandatory = $true)][string]$ScriptPath
)

$ErrorActionPreference = "Stop"

try {
    if ($Username) {
        $plainPassword = [Console]::In.ReadLine()
        $securePass = ConvertTo-SecureString $plainPassword -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($Username, $securePass)
        Remove-Variable plainPassword -ErrorAction SilentlyContinue
        $result = Invoke-Command -ComputerName $ComputerName -Credential $cred -FilePath $ScriptPath -ErrorAction Stop
    }
    else {
        $result = Invoke-Command -ComputerName $ComputerName -FilePath $ScriptPath -ErrorAction Stop
    }
    Write-Output "RESULT:SUCCESS"
    $result | ConvertTo-Json -Compress -Depth 5
}
catch {
    Write-Output "RESULT:FAIL:$($_.Exception.Message)"
}
