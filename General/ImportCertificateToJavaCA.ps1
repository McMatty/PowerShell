$caDirectory 			= '\jre\lib\security\cacerts'
$javaBinDirectory 		= '\jre\bin'
$importCertificatePath 	= 'C:\Share\ContentInspection.cer'

if(Test-Path Env:JAVA_Home)
{
	$javaHome 				= (Get-ChildItem Env:JAVA_HOME).value
}

if(!($javaHome))
{
	Write-Host '"JAVA_HOME" not found. If Java has been installed please set the environment variable to its folder.'
}
else
{	$arguments =@("-importcert", "-file", "$importCertificatePath", "-keystore", "cacerts", "-storepass", "changeit", "-noprompt")
	& "$javaHome$javaBinDirectory\keytool.exe" $arguments | Write-Output
}


# SIG # Begin signature block
# MIIECQYJKoZIhvcNAQcCoIID+jCCA/YCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUGrUadZdEjXZf9d2bwDnm54+5
# lpWgggIlMIICITCCAYqgAwIBAgIQzjXhbgpHqqFEPkUS7GtfsjANBgkqhkiG9w0B
# AQsFADAaMRgwFgYDVQQDEw9Mb2NhbE1hY2hpbmUgQ0EwHhcNMTYwMTExMDE1ODQ1
# WhcNMzkxMjMxMjM1OTU5WjAeMRwwGgYDVQQDExNTaWduaW5nIGNlcnRpZmljYXRl
# MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtukcmbGe2ev8C/5glK9K35Drj
# 7eXAyZYFnGnPtNFVMLUVtvSCyoGZFfJjpP1aAIzI7BhN50d9z7zr7TrnakRnS8OO
# VloTUAnusOd8Wan2h8bvWazVGqu95PVhT0mrOWhxPEOtNf4PjFH3BFY6sfVeL98+
# m2Pg3m2ZOXLQqZ0S7wIDAQABo2QwYjATBgNVHSUEDDAKBggrBgEFBQcDAzBLBgNV
# HQEERDBCgBCoPI3S9zXE67y7QM8qjFXKoRwwGjEYMBYGA1UEAxMPTG9jYWxNYWNo
# aW5lIENBghCNa0l5HjJ/n0YbBtau6zmmMA0GCSqGSIb3DQEBCwUAA4GBADyzE8lI
# mK7T/U8GrnLVIk/75Ghf9TzCTCIo+JXWtxrmWWfHQoJxEu1xabqvmM8+ro11krXT
# NQXrRFmEbuovRUWtNClYkLOZNtf8TX+P61HKFVOv4RjaYcC2oSXQx+99w1LEJvRA
# CHm5PkwIp+mNgBxbIvWju4ljggHq46J4oxaTMYIBTjCCAUoCAQEwLjAaMRgwFgYD
# VQQDEw9Mb2NhbE1hY2hpbmUgQ0ECEM414W4KR6qhRD5FEuxrX7IwCQYFKw4DAhoF
# AKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcN
# AQkEMRYEFIgrHG6XecawzYTPnYDjYZs3pmIAMA0GCSqGSIb3DQEBAQUABIGAfrS/
# svZSwod0hz64RFASnhgpmozPV8NLBAdkqk3bDnYmxbbFDAZTk8g5fDFo1FGdTLw1
# reugnht9NfIQgmyqxjCcGoZwt5JBKaACb0a1tp3cZGXBmPZBZ4owei6AQApiz+9E
# liYwQXSfXlghH8js5iGJ5pK+8gFtgTzV+XLtG2Y=
# SIG # End signature block
