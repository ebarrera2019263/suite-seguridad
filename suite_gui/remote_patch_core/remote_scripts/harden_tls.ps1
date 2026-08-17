# Ejecutado EN LA MAQUINA REMOTA via Invoke-Command -FilePath.
# Endurece TLS en el stack nativo de Windows (SCHANNEL):
#   1) Deshabilita SSLv2/SSLv3/TLS1.0/TLS1.1 (protocolos) en Cliente y Servidor.
#   2) Deshabilita cifrados/hashes debiles (RC4/DES/3DES/MD5/NULL) por REGISTRO
#      -> funciona en TODA version de Windows, incluidas 7/2008R2/2012/2012R2
#      donde Get-TlsCipherSuite NO existe. Antes, en esas versiones los cifrados
#      debiles quedaban intactos y nmap/testssl los seguia marcando.
#   3) Ademas, si Get-TlsCipherSuite existe (2016+), deshabilita las suites por
#      nombre como refuerzo.
# El objeto devuelto refleja el estado REAL (Success=$false si algo fallo).
#
# LIMITE: SCHANNEL solo afecta servicios que usan el stack TLS de Windows
# (IIS/HTTP.sys, RDP-TLS, WinRM-HTTPS, LDAPS). Servicios con TLS propio
# (Apache/nginx/OpenSSL, Java/JSSE, Node) NO se tocan aca -> hay que
# endurecerlos a nivel de aplicacion.

$ErrorActionPreference = "Stop"
$errors = @()

$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
$schannel = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# --- 1) Protocolos obsoletos (subclaves sin '/', se pueden usar PSDrive) -----
try {
    foreach ($proto in $protocols) {
        foreach ($side in @("Client", "Server")) {
            $path = "HKLM:\$schannel\Protocols\$proto\$side"
            New-Item -Path $path -Force | Out-Null
            New-ItemProperty -Path $path -Name "Enabled" -PropertyType DWord -Value 0 -Force | Out-Null
            New-ItemProperty -Path $path -Name "DisabledByDefault" -PropertyType DWord -Value 1 -Force | Out-Null
        }
    }
}
catch { $errors += "Protocolos: $($_.Exception.Message)" }

# --- 2) Cifrados/hashes debiles por REGISTRO (.NET, porque los nombres
#        llevan '/' literal, p.ej. 'RC4 128/128', que PSDrive interpretaria
#        como separador de ruta) --------------------------------------------
$weakCiphersReg = @("RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128", "DES 56/56", "Triple DES 168", "NULL")
$disabledByRegistry = @()
try {
    foreach ($name in $weakCiphersReg) {
        $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("$schannel\Ciphers\$name")
        $k.SetValue("Enabled", 0, [Microsoft.Win32.RegistryValueKind]::DWord)
        $k.Close()
        $disabledByRegistry += $name
    }
    # Hash MD5
    $kh = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("$schannel\Hashes\MD5")
    $kh.SetValue("Enabled", 0, [Microsoft.Win32.RegistryValueKind]::DWord)
    $kh.Close()
    $disabledByRegistry += "MD5"
}
catch { $errors += "Cifrados(registro): $($_.Exception.Message)" }

# --- 3) Refuerzo por nombre con Get-TlsCipherSuite (solo 2016+) --------------
$disabledBySuite = @()
$suiteCmdletAvailable = $true
try {
    $weakSuites = Get-TlsCipherSuite | Where-Object { $_.Name -match "RC4|DES|3DES|NULL|EXPORT|MD5" } |
        Select-Object -ExpandProperty Name
    foreach ($c in $weakSuites) {
        try {
            Disable-TlsCipherSuite -Name $c -ErrorAction Stop
            $disabledBySuite += $c
        }
        catch { $errors += "Disable-TlsCipherSuite $c : $($_.Exception.Message)" }
    }
}
catch {
    $suiteCmdletAvailable = $false  # cmdlet no existe (Windows < 2016): ya se cubrio por registro
}

$success = ($errors.Count -eq 0)
$detail = "Protocolos SSLv2/SSLv3/TLS1.0/1.1 deshabilitados via SCHANNEL. Cifrados/hashes debiles deshabilitados por registro: $($disabledByRegistry -join ', '). "
if ($suiteCmdletAvailable) {
    $detail += "Refuerzo por Get-TlsCipherSuite: $($disabledBySuite.Count) suite(s). "
}
else {
    $detail += "Get-TlsCipherSuite no disponible (Windows < 2016): cobertura de cifrados asegurada solo por registro. "
}
$detail += "REQUIERE REINICIO para que el nuevo estado de SCHANNEL sea visible a un scanner. NOTA: solo afecta el stack TLS nativo de Windows (IIS/RDP-TLS/WinRM-HTTPS/LDAPS); servicios con TLS propio (Apache/nginx/Java) se endurecen aparte."
if (-not $success) {
    $detail += " ADVERTENCIA: hubo errores -> $($errors -join ' | ')"
}

[PSCustomObject]@{
    Hostname                    = $env:COMPUTERNAME
    Action                      = "harden_tls"
    Success                     = $success
    ProtocolsDisabled           = $protocols
    WeakCiphersDisabledRegistry = $disabledByRegistry
    CipherSuiteCmdletAvailable  = $suiteCmdletAvailable
    WeakSuitesDisabledByName    = $disabledBySuite
    Errors                      = $errors
    Detail                      = $detail
}
