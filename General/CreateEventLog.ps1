
function createEventLog([string]$eventLogName, [string]$eventSourceName)
{	
	$eventSourceExists 	= [System.Diagnostics.EventLog]::SourceExists($eventSourceName)
	
	if (! $eventSourceExists) {			
			New-EventLog -LogName $eventLogName -Source $eventSourceName	
			Write-Host -ForegroundColor DarkGreen "New event log created. Log Name: $eventLogName   Event Log Source: $eventSourceName"
	}
}

