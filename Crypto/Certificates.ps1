#Requires -RunAsAdministrator
function Get-ExportableCertificates
{    
    [cmdletbinding()]
    Param(
    [Parameter(Mandatory=$False)]
    [string[]]$Exclude = {"UserDS"}
    )
    #CSP & CNG are the way we access the crypto API. CSP is the legacy model where as CNG is the newer.
    #Older certs will be using the CSP
    Get-ChildItem -Path cert:\*\* -Exclude $Exclude | ? { if ($_.HasPrivateKey)
                                                        {
                                                             if($_.PrivateKey)
                                                             {
                                                                #Legacy certificate check for CSP. Nice and easy.
                                                                return $_.PrivateKey.CspKeyContainerInfo.Exportable
                                                             }
                                                             else
                                                             {                                                                                                                      
                                                                #CNG check
                                                                $subject = $_.Subject
                                                                $thumbprint = $_.Thumbprint 
                                                                $location = $_.PSParentPath.split("::")[2]
                                                                
                                                                try
                                                                {
                                                                    $cngPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($_)
                                                                }
                                                                catch
                                                                {
                                                                    Write-Verbose "Error inspecting cerfiticate with thumbprint: $thumbprint" 
                                                                    Write-Verbose "Subject name: $subject"       
                                                                    Write-Verbose "Location: $location"                                                               
                                                                    Write-Verbose $_.Exception.Message  
                                                                   
                                                                    return $false
                                                                }

                                                                if($cngPrivateKey -eq $null)
                                                                {
                                                                    Write-Verbose "Certificate has a private key but is not CSP and no CNG container could be found for it" 
                                                                    Write-Verbose "Certificate thumbprint: " $_.Thumbprint " Certificate friendly name (if available): " $_.FriendlyName 
                                                                }
                                                                return $cngPrivateKey.Key.ExportPolicy.HasFlag([System.Security.Cryptography.CngExportPolicies]::AllowExport)
                                                             }
                                                        }
                                                   } | select Thumbprint, Subject, Issuer, @{Name="Certificate Location";Expression={$_.PSParentPath.split("::")[2]}} -Unique
}

function Get-ExpiringCertificates
{
    [cmdletbinding()]
    Param(
    [Parameter(Mandatory=$True, Position=0)]
    [ValidateRange(0,90)]
 	[int]$DaysUntilExpired,  
 
    [Parameter(Mandatory=$False, Position=1)]
    [string[]]$Exclude = {"UserDS"}   
    )
    

    Get-ChildItem cert:\*\* -Exclude $Exclude | ? { ((Get-Date $_.NotAfter) - (Get-Date)).Days -le $DaysUntilExpired} | select Thumbprint, Subject, Issuer, NotAfter, @{Name="Certificate Location";Expression={$_.PSParentPath.split("::")[2]}} -Unique
}

function Get-CertificatesPermissionIssues
{         
    [cmdletbinding()]
    Param(
    [Parameter(Mandatory=$False)]
    [string[]]$Exclude = {"UserDS"}
    )

    Get-ChildItem cert:\*\* -Exclude $Exclude | ? { if ($_.HasPrivateKey)
                                                        {
                                                             if($_.PrivateKey)
                                                             {
                                                                #Legacy certificate check for CSP. Nice and easy.
                                                                return $false
                                                             }
                                                             else
                                                             {                                                                                                                      
                                                                #CNG check
                                                                $subject = $_.Subject
                                                                $thumbprint = $_.Thumbprint 
                                                                $location = $_.PSParentPath.split("::")[2]
                                                                
                                                                try
                                                                {
                                                                    $cngPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($_)
                                                                }
                                                                catch
                                                                {  
                                                                    return $true
                                                                }

                                                                return $false                                                                
                                                             }
                                                        }
                                                   } | select Thumbprint, Subject, Issuer, @{Name="Certificate Location";Expression={$_.PSParentPath.split("::")[2]}} -Unique
}

function Get-PrivateKey
{
    [cmdletbinding()]
    Param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [System.security.cryptography.x509certificates.x509certificate2]$Certificate)

    Process{
        if ($Certificate.HasPrivateKey)
        {
             if($Certificate.PrivateKey)
             {
                #Legacy certificate check for CSP. Nice and easy.
                return $Certificate.PrivateKey;
             }
             else
             {                                                                                                                      
                #CNG check
                $subject = $Certificate.Subject
                $thumbprint = $Certificate.Thumbprint 

                #Location only available if in windows key store
                if($Certificate.PSParentPath)
                {
                    $location = $Certificate.PSParentPath.split("::")[2]
                }
            
                try
                {
                    $cngPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
                }
                catch
                {
                    Write-Verbose "Error inspecting cerfiticate with thumbprint: $thumbprint" 
                    Write-Verbose "Subject name: $subject"       
                    Write-Verbose "Location: $location"                                                               
                    Write-Verbose $Certificate.Exception.Message  
               
                    return $null
                }

                if($cngPrivateKey -eq $null)
                {
                    Write-Verbose "Certificate has a private key but is not CSP and no CNG container could be found for it" 
                    Write-Verbose "Certificate thumbprint: " $_.Thumbprint " Certificate friendly name (if available): " $Certificate.FriendlyName 
                }

                return $cngPrivateKey.Key
             }
        }

        return $null
    }
}

function Crack-CertificatePassword
{
    [cmdletbinding()]
    Param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath,
    
    [Parameter(Mandatory=$false)]
    [string]$Password,

    [Parameter(Mandatory=$false)]
    [string]$PasswordListPath,

    [Parameter(Mandatory=$false)]
    [bool]$BruteForce
    )

    $passwordList = New-Object System.Collections.ArrayList($null)     

    if( -not (Test-Path $FilePath))
    {
        throw [System.IO.FileNotFoundException] "$pfxFile not found." 
    }  

    if( Test-Path $PasswordListPath)
    {
        [System.Collections.ArrayList]$passwordList = Get-Content -Path $PasswordListPath
    }       
    
    if($Password)
    {
        $passwordList.Add($Password) | Out-Null
    }   
    
    if($passwordList.Count -le 0)
    {
         throw [System.InvalidOperationException] "No password or passwordlist provided." 
    }     

    $pfxcert = new-object system.security.cryptography.x509certificates.x509certificate2  
    $foundPassword  = $passwordList | ? {
                                                try
                                                {                      
                                                    $pfxcert.Import([string]$FilePath, $_, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet)  
                                                }
                                                catch
                                                {
                                                    return $false
                                                }
                                                return $true
                                           } 
    $result = if($foundPassword){"Password: $foundPassword"} else {"Matching password not found"}
    return $result
}