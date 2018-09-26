$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0', 4040)
$caller   = New-Object System.Net.Sockets.TCPClient('10.72.138.55', 4141)

try
{ 
    $listener.Start()
    $listenerClient = $listener.AcceptTcpClient()
    $incomingStream = $listenerClient.GetStream()
    $outgoingStream = $caller.GetStream()        

    #Single thread while loop - CPU go bye bye. Could add a delay or look to removing the 
    while($true)
    {           
        if($outgoingStream.DataAvailable)
        {
            [byte[]] $bytes = 0..65535 | % {0}
            $outgoingStream.Read($bytes, 0, $bytes.Length)

            $incomingStream.Write($bytes, 0, $bytes.Length)
            $incomingStream.Flush();
        }

        if($incomingStream.DataAvailable)
        {
            [byte[]] $bytes = 0..65535 | % {0}
            $incomingStream.Read($bytes, 0, $bytes.Length)

            $outgoingStream.Write($bytes, 0, $bytes.Length)
            $outgoingStream.Flush();
        }       
    }
}
finally
{
    $incomingStream.Dispose()
    $outgoingStream.Dispose()
    $listenerClient.Close()

    $listener.Stop()
    $caller.Close()
} 
