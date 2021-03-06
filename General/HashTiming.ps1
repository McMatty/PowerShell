cls

Write-Host
Write-Host "***MD5***"
Measure-Command { 	
	$enc  = New-Object System.Text.ASCIIEncoding
	$MD5 = [System.Security.Cryptography.HashAlgorithm]::Create("MD5")
	
	for($i=0;$i -le 1000; $i++){			
		$derivedPassKey 	= $MD5.ComputeHash($enc.GetBytes($i))		
	}
}

Write-Host
Write-Host "***SHA1***"
Measure-Command { 	
	$enc  = New-Object System.Text.ASCIIEncoding
	$SHA1 = [System.Security.Cryptography.HashAlgorithm]::Create("SHA1")
	
	for($i=0;$i -le 100; $i++){			
		$derivedPassKey 	= $SHA1.ComputeHash($enc.GetBytes($i))		
	}
}

Write-Host
Write-Host "***SHA256***"
Measure-Command { 	
	$enc  = New-Object System.Text.ASCIIEncoding
	$SHA256 = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256")
	
	for($i=0;$i -le 100; $i++){			
		$derivedPassKey 	= $SHA256.ComputeHash($enc.GetBytes($i))		
	}
}

Write-Host
Write-Host "***PBKDF2***"
Measure-Command { 
	$salt = "1234567890poiuytrewqasdfghjkl;'zxcvbnm,./\"
	$enc  = New-Object System.Text.ASCIIEncoding
	
	for($i=0;$i -le 100; $i++){			
		$derivedPassKey 	= New-Object System.Security.Cryptography.Rfc2898DeriveBytes($enc.GetBytes($i), $enc.GetBytes($salt),4001)		
	}
}

[Reflection.Assembly]::LoadFile("C:\Users\User1\Documents\PowerShell\Bcrypt.net.dll") | Out-Null
Write-Host
Write-Host "***BCRYPT***"
Measure-Command { 
	$salt = "1234567890poiuytrewqasdfghjkl;'zxcvbnm,./\"
	$enc  = New-Object System.Text.ASCIIEncoding
	
	for($i=0;$i -le 100; $i++){			
		$derivedPassKey 	= [bcrypt.net.bcrypt]::hashpassword($1, 12)		
	}
}