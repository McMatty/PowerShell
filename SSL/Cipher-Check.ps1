cls
$openSSLPath = 'C:\Program Files\OpenSSL\bin\openssl.exe'
if(Test-Path $openSSLPath)
{
    & $openSSLPath s_client -connect secure.ami.co.nz:443
   
}
