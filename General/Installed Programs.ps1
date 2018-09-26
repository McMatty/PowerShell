
$localCredentials = [System.Net.CredentialCache]::DefaultNetworkCredentials 
$webClient = New-Object Net.WebClient
$webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials 

$scriptBlock = { 
    $win32Installs = gwmi win32_product | Sort-object Vendor| Select Name, Vendor
    $regInstalls = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName}| Select @{Name="Name";Expression={$_.DisplayName}}, @{Name="Vendor";Expression={$_.Publisher}} 

    $regInstalls + $win32Installs |Sort-Object Vendor, Name | Select Name, Vendor -Unique | Format-Table
}

