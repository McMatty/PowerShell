cls
$content = Get-Content "TrxToJunit.xslt" -Encoding Byte
$base64 = [System.Convert]::ToBase64String($content)
$base64
