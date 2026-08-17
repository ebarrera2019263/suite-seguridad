# Ejecutado EN LA MAQUINA REMOTA via Invoke-Command -FilePath. Solo confirma
# que WinRM responde y con que usuario efectivo.
[PSCustomObject]@{
    Hostname = $env:COMPUTERNAME
    EffectiveUser = "$env:USERDOMAIN\$env:USERNAME"
    Reachable = $true
}
