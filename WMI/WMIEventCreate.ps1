cls

$query 				= "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name ='notepad.exe'"
$filterArgument 	= @{name="updater";EventNameSpace="root\CimV2";QueryLanguage="WQL";Query=$query}
$filter 			= Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments $filterArgument

$command 			= "$($Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -Command New-Item c:\temp\new_file.txt -type file"
$consumerArgument 	= @{name="updater";CommandLineTemplate=$command;RunInteractively="false"};
$consumer			= Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments $consumerArgument

$bindingResult 		= Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{filter=$filter;consumer=$consumer} 

