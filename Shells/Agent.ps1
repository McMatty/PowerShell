function Run-CommandOnAgent
{
    Param(
    [String]
    $cmd, 
    $dataStream
    )

     $inputDataBytes = [System.Text.Encoding]::ASCII.GetBytes($cmd)
     $dataStream.Write($inputDataBytes, 0, $inputDataBytes.Length)
     $dataStream.Flush();
}

function Retrieve-File
{
}

function Load-Assembly
{
}

function TCP-Connection
{
    $socket = New-Object System.Net.Sockets.TcpListener('0.0.0.0', 4040)

    try
    {
        $socket.Start()
        $client         = $socket.AcceptTcpClient()
        $dataStream     = $client.GetStream()
        [byte[]] $bytes = 0..65535 | % {0}

        while(($i = $dataStream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $remoteOutput = [System.Text.Encoding]::ASCII.GetString($bytes, 0, $i )  
            try
            {
                #Blocking calls               
                Write-Host $remoteOutput -NoNewline
                $input       = Read-Host
                $stringValue = $input
               
                switch($input)
                {
                    "Retrieve-File"
                    {
                        #TCP strut + header?
                        break;
                    }
                    "Load-Assembly"
                    {
                        break;
                    }
                    default
                    {
                        Run-CommandOnAgent $stringValue $dataStream;
                        break;
                    }
                }
            }
            catch
            {               
                Write-Error $_
            } 
            
            #$inputDataBytes = [System.Text.Encoding]::ASCII.GetBytes($input)
            #$dataStream.Write($inputDataBytes, 0, $inputDataBytes.Length)
            #$dataStream.Flush();
        }
    }
    finally
    {
        $dataStream.Dispose()
        $client.Close()
        $socket.Stop()
    }
} 

TCP-Connection