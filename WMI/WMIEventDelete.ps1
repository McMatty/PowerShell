##Removing WMI Subscriptions using Remove-WMIObject
#Filter
cls
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='updater'" | Remove-WmiObject -Verbose
 
#Consumer
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='updater'" | Remove-WmiObject -Verbose
 
#Binding
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%updater%'"  | Remove-WmiObject -Verbose