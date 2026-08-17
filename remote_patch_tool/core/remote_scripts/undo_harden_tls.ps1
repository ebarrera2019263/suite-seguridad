# Revierte harden_tls.ps1: quita las claves que deshabilitaban
# explicitamente los protocolos, volviendo al comportamiento por defecto
# del sistema operativo.
#
# LIMITE IMPORTANTE -- se refleja tambien en Detail (no solo aca en un
# comentario) para que quien lea el reporte lo sepa sin tener que abrir este
# script: si harden_tls.ps1 llego a deshabilitar suites POR NOMBRE con
# Disable-TlsCipherSuite (refuerzo adicional, solo Windows 2016+), ESTE
# script NO las reactiva. No hay forma de recuperar automaticamente cuales
# fueron sin haber guardado ese estado antes de aplicar el cambio.
$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
$base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

foreach ($proto in $protocols) {
    foreach ($side in @("Client", "Server")) {
        $path = Join-Path (Join-Path $base $proto) $side
        Remove-ItemProperty -Path $path -Name "Enabled" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $path -Name "DisabledByDefault" -ErrorAction SilentlyContinue
    }
}

# Quita tambien los Enabled=0 de cifrados/hashes que puso harden_tls.ps1 por
# registro, volviendo al default del SO. (Los nombres llevan '/' literal, por
# eso se borran con la API .NET, no con PSDrive.)
$schannel = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
$weakCiphersReg = @("RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128", "DES 56/56", "Triple DES 168", "NULL")
foreach ($name in $weakCiphersReg) {
    try { [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree("$schannel\Ciphers\$name", $false) } catch {}
}
try { [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree("$schannel\Hashes\MD5", $false) } catch {}

$suiteCmdletAvailable = [bool](Get-Command Get-TlsCipherSuite -ErrorAction SilentlyContinue)

$detail = "Valores explicitos de protocolos y cifrados/hashes por registro removidos (vuelve al default del SO)."
if ($suiteCmdletAvailable) {
    $detail += " ADVERTENCIA: este equipo soporta Disable-TlsCipherSuite (Windows 2016+). Si harden_tls llego a deshabilitar suites POR NOMBRE, ESTE undo NO las reactiva -- no hay forma de saber automaticamente cuales fueron. Si alguna app dejo de funcionar por una suite especifica, reactivarla a mano con: Enable-TlsCipherSuite -Name `"<nombre-de-la-suite>`""
}
$detail += " Nota: revertir REACTIVA cifrados/protocolos debiles; solo hacerlo si algo dejo de funcionar."

[PSCustomObject]@{
    Hostname                   = $env:COMPUTERNAME
    Action                     = "undo_harden_tls"
    Success                    = $true
    CipherSuiteCmdletAvailable = $suiteCmdletAvailable
    NamedSuitesReverted        = $false
    Detail                     = $detail
}
