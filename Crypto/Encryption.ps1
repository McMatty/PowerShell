function Encrypt-Script{
	<#
    .SYNOPSIS
        Encrypts a PowerShell script file
    .DESCRIPTION
        Extracts the contents from a PowerShell file encrypts the content and returns the encrypted version   
    .FUNCTIONALITY
        StackExchange
    .EXAMPLE
        Encrypt-Script "12345678" "Secret" "C:\Code\PowerShell\Crypto\Encryption.psm1"
        #Extract script content and generate and encrypted string includeding the IV     
    #>
	param(
	[ValidateLength(8,256)][string]$salt,
	[string]$secret,
	[string]$scriptPath
	)		
	
	$enc 					= New-Object System.Text.ASCIIEncoding
	$scriptContent 			= Get-Content -path $scriptPath
	[Byte[]]$scriptBytes 	= $enc.GetBytes($scriptContent)

	#####Encryption#####
	$ivBytes		= New-Object Byte[] 16
	$rng 			= [System.Security.Cryptography.RandomNumberGenerator]::Create()
	$rng.GetBytes($ivBytes)

	$derivedPassKey = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($enc.GetBytes($secret), $enc.GetBytes($salt),4001)
	$keyBytes		= $derivedPassKey.GetBytes(16)

	$key 			= New-Object System.Security.Cryptography.AesManaged
	$key.Mode		= [System.Security.Cryptography.CipherMode]::CBC
	$encryptor 		= $key.CreateEncryptor($keyBytes, $ivBytes)

	try
	{
		$stream = New-Object System.IO.MemoryStream
		try
		{
			$cryptoStream = New-Object System.Security.Cryptography.CryptoStream($stream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
			$cryptoStream.Write($scriptBytes, 0, $scriptBytes.Length)
			$cryptoStream.FlushFinalBlock()
			$output = $stream.ToArray()
		}
		finally
		{
			$cryptoStream.Dispose()
		}
	}
	finally
	{
		$stream.Dispose()
	}

	return [Convert]::ToBase64String($output) + "::" +	[Convert]::ToBase64String($ivBytes)
}


function Decrypt-Script{
	<#
    .SYNOPSIS
        Decrypts a PowerShell script string
    .DESCRIPTION
        Extracts the contents from a PowerShell file encrypts the content and returns the encrypted version   
    .FUNCTIONALITY
        StackExchange
    .EXAMPLE
        Decrypt-Script "12345678" "Secret" <encryptedString>
        #Decrypts <encryptedString> using the salt & password that was used to create the encrypted string. IV should be included in the string     
    #>
	param(
	[ValidateLength(8,256)][string]$salt,
	[string]$secret,
	[string]$encryptedString
	)	
	
	$encryptedContent, $ivContent 			= $encryptedString.Split("::")
		
	#####Decryption#####	
	$encryptedCipher 	= [Convert]::FromBase64String($encryptedContent)
	$ivBytes			= [Convert]::FromBase64String($ivContent)
	[Byte[]]$cipherByte = New-Object Byte[]($encryptedCipher.Length)

	$enc 				= New-Object System.Text.ASCIIEncoding
	$derivedPassKey 	= New-Object System.Security.Cryptography.Rfc2898DeriveBytes($enc.GetBytes($secret), $enc.GetBytes($salt),4001)
	$keyBytes			= $derivedPassKey.GetBytes(16)

	$key 				= New-Object System.Security.Cryptography.AesManaged
	$key.Mode			= [System.Security.Cryptography.CipherMode]::CBC
	$decryptor 			= $key.CreateDecryptor($keyBytes, $ivBytes)

	try
	{
		$stream = New-Object System.IO.MemoryStream($encryptedCipher, $true)
		try
		{
			$cryptoStream = New-Object System.Security.Cryptography.CryptoStream($stream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)						
			$cryptoStream.Read($cipherByte, 0, $cipherByte.Length)	| Out-Null				
		}
		finally
		{
			$cryptoStream.Dispose()
		}
	}
	finally
	{
		$stream.Dispose()
	}

	return $enc.GetString($cipherByte)	
}