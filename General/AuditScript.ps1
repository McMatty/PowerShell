function retrieveFilterAction([string]$filterName)
{
      $actionFilterName       = "//configuration/system.serviceModel/routing/filters/filter[@name='{0}']" -f $filterName     
      $actionFilter           = $webConfig.SelectSingleNode($actionFilterName)
     
      return $actionFilter
}
 
function retrieveEndpointAddress([string]$endpointName)
{
      $routeName = "//configuration/system.serviceModel/client/endpoint[@name='{0}']" -f $endpointName
      [uri]$endpointAddress = $webConfig.SelectSingleNode($routeName).address
     
      return $endpointAddress.PathAndQuery
}
 
cls
$directory              = ''
$hostName               = ''
 
$requestFiles           = Get-ChildItem $directory "*.xml"
$hostfiles              = Get-ChildItem $directory "*.$hostName"
$routerConfig           = (Split-Path -Path $directory -Parent) + "\web.config"
 
[xml]$webConfig   = Get-Content $routerConfig
$routeTable             = $webConfig.SelectNodes('//configuration/system.serviceModel/routing/filterTables/filterTable/add')
 
[xml]$testFileXml       = Get-Content -Path $hostfiles.FullName
$routerTests            = $testFileXml.SelectNodes('//RouterTest')
 
if($routerTests.Count -ne $routeTable.Count)
{
      Write-Host "Number of filtered endpoints:" $routeTable.Count -ForegroundColor Red
      Write-Host "Number of router tests:"  $routerTests.Count -ForegroundColor Red
}
 
$testEntryObjectArray =@() 
foreach ($testEntry in $routerTests)
{
	 $testEntryObject = New-Object -TypeName PSObject
      Add-Member -InputObject $testEntryObject -MemberType NoteProperty -Name name -Value $testEntry.TestRequest.FileName
      Add-Member -InputObject $testEntryObject -MemberType NoteProperty -Name action -Value $testEntry.TestRequest.SoapAction
      Add-Member -InputObject $testEntryObject -MemberType NoteProperty -Name endpointRelativeAddress -Value $testEntry.PingResponse.Endpoints.RelativeEndpoint     
	 $testEntryObjectArray += $testEntryObject
}

$routeArray =@() 
foreach ($route in $routeTable)
{   
      $filterName       = "//configuration/system.serviceModel/routing/filters/filter[@name='{0}']" -f $route.filterName
      $filter           = $webConfig.SelectSingleNode($filterName)     
      $object           = New-Object -TypeName PSObject          
      Add-Member -InputObject $object -MemberType NoteProperty -Name name -Value $route.filterName
      Add-Member -InputObject $object -MemberType NoteProperty -Name action -Value ""
      Add-Member -InputObject $object -MemberType NoteProperty -Name endpointRelativeAddress -Value ""
      Add-Member -InputObject $object -MemberType NoteProperty -Name xpath -Value ""  
	  Add-Member -InputObject $object -MemberType NoteProperty -Name filterType -Value $filter.filterType 
     
      switch ($filter.filterType)
      {
            "XPath" {$object.xpath = $filter.filterData}
            "Action" {$object.action = $filter.filterData}
            "And" {
                  $actionFilter = retrieveFilterAction($filter.filter1)
                 
                  if($actionFilter -eq $null -or $actionFilter.filterType -ne 'Action')
                  {
                        $actionFilter = retrieveFilterAction($filter.filter2)                  
                  }
                 
                  $object.action = $actionFilter.filterData
            }
      }
     
      $object.endpointRelativeAddress = retrieveEndpointAddress($route.endpointName)     
     
      $routeArray += $object
}

$xpathEndpoints 		= $routeArray | Where-Object {$_.filterType -eq 'XPath'}
$endpointsWithTests 	= Compare-Object $routeArray $testEntryObjectArray -Property endpointRelativeAddress,action -PassThru -IncludeEqual -ExcludeDifferent
if($xpathEndpoints -ne $null)
{
	$endpointsWithTests 	= $endpointsWithTests + @(Compare-Object $xpathEndpoints $testEntryObjectArray -Property endpointRelativeAddress -PassThru -IncludeEqual -ExcludeDifferent)
}

if($endpointsWithTests -ne $null)
{
	$endpointsWithoutTests 	= Compare-Object $routeArray $endpointsWithTests -Property name -PassThru  

	Write-Host
	Write-Host "-----------Named endpoints with matching tests-----------" -ForegroundColor DarkGreen
	$endpointsWithTests | % {Write-Host $_.name -ForegroundColor DarkGreen}
}

Write-Host
Write-Host "-----------Named endpoints without matching tests--------" -ForegroundColor Red
$endpointsWithoutTests | % {Write-Host $_.name -ForegroundColor Red}