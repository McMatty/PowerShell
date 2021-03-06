cls
$encoding 		= [System.Text.Encoding]::UTF8
$data 			= "String data to be encrypted"
$dataByteArray 	= $encoding.GetBytes($data)

$cert 			= Get-ChildItem cert:\currentuser\my | Where-Object {$_.hasPrivateKey -and $_.Subject -eq "CN=ssl.gstatic.com, O=DO_NOT_TRUST, OU=Created by http://www.fiddler2.com"}
#$cert 			= Get-ChildItem cert:\currentuser\my | Where-Object {$_.hasPrivateKey -and $_.Subject -eq "CN=CodeSigning"}
$encryptedData 	= $cert.PublicKey.Key.Encrypt($dataByteArray, $true)
$decryptedData 	= $cert.PrivateKey.Decrypt($encryptedData, $true)

Write-host $encoding.GetString($encryptedData)
Write-host ----------------------------------
Write-host $encoding.GetString($decryptedData)
# SIG # Begin signature block
# MIIECQYJKoZIhvcNAQcCoIID+jCCA/YCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU2g9W+AK2JkbNk+GaDHLu9Uz3
# lwKgggIlMIICITCCAYqgAwIBAgIQ5SBAwU7WzbRLZmLnGnZvoDANBgkqhkiG9w0B
# AQsFADAaMRgwFgYDVQQDEw9Mb2NhbE1hY2hpbmUgQ0EwHhcNMTUxMjMwMjIwMjM5
# WhcNMzkxMjMxMjM1OTU5WjAeMRwwGgYDVQQDExNTaWduaW5nIGNlcnRpZmljYXRl
# MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIt6NrjEXuKbUUFE9N6yCGsDrq
# xrIhVYMWCBe5QTTR1crU0yZVqinY7wk+0/pWUmAeFToJ4mAOSlh3l2o+NxhZeYdH
# WtH9VVCgwcPTneHArkJRTFzE7GgWdxBbZp+/eB9lGiscRqN43+Qwn7+RHIrlPPXX
# CBwZS8emdQjfCeoiHwIDAQABo2QwYjATBgNVHSUEDDAKBggrBgEFBQcDAzBLBgNV
# HQEERDBCgBA5RoRatNqxFRrcwxPjneHUoRwwGjEYMBYGA1UEAxMPTG9jYWxNYWNo
# aW5lIENBghAJb0YP5T2GmEyQHIMXFPn5MA0GCSqGSIb3DQEBCwUAA4GBADfAKyfL
# VaSRswprH6FYAF38YFCMzYr1vNm/tbD7ZirZMRNLAnazgLMr4PkiSGcwje3NZOFp
# 7sdvSYkq1nj0lmGx8L93Ta7E8sn3PmCtnep3I2O6g1QlUK7MwIzOyQR5/ZRWVSD9
# oZRJ0cvyhXKs4e0FZpk87+0hX8I+XluGUoSBMYIBTjCCAUoCAQEwLjAaMRgwFgYD
# VQQDEw9Mb2NhbE1hY2hpbmUgQ0ECEOUgQMFO1s20S2Zi5xp2b6AwCQYFKw4DAhoF
# AKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcN
# AQkEMRYEFKZmu8H6Dy7lcqI3/MHSdx68KdPcMA0GCSqGSIb3DQEBAQUABIGAk1Qx
# GiOEdOeUk91qoOCbRy9TG1LkdzonwzooOj8YhpOVKLmnmkcHMacIiPH+Ge6rnkpH
# 0Id6SISSTKmkA2XsL4+d3By9AIUefYLvMZ8ubB4WCwmgv21YFQWzP1qP7ovoOWAi
# sxExBI+DlL+hYStdcCxYYDK2nt9FQtx0qCkjoEU=
# SIG # End signature block
