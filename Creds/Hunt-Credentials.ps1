<#
        .SYNOPSIS
        Looks for credentials recursively based of Microsofts CredScan regular expressions
        .DESCRIPTION
        Searches the path provided for file types matching those in which credentials
        .PARAMETER Path
        A string value for the search directory path to start at
        .PARAMETER Recurse
        A boolean value to indicate if the search is recursive and will continue down all child folders found in the search path. Defaults to true.
        .PARAMETER Exclude
        A string array of file wildcards to exclude from the search. By default .exe and .dll are excluded from being included. The format matches that of Get-ChildItem *.exe, *.dll
        .EXAMPLE
        Hunt-Credentials -Path "C:\" -Exclude *.js
        .OUTPUTS
        Console output on files with found credentials matched as well as credentials
        .NOTES       
        Minified js files currently destroy the regular expressions so its suggested to exclude these unless you have alot of time.
        Currently the entire XML object is embedded in the script less than ideal
#>
function Hunt-Credentials {
    [CmdletBinding()]
    param([string]$Path,
    [string[]]$Exclude,
    [bool]$Recurse=$true)
   
    # BLOCK 1: Create and open runspace pool, setup runspaces array with min and max threads
    $MAX_RUNSPACE = [int]$env:NUMBER_OF_PROCESSORS + 1
    $pool = [RunspaceFactory]::CreateRunspacePool(1, $MAX_RUNSPACE)        
    $pool.Open()
    [System.Collections.ArrayList]$runspaces = @()

    Write-Host "Searching begun at $(Get-Date)"
    Write-Host "[]======================================================[]"


    # BLOCK 2: Create the script block for processing match file content
    $scriptBlock = {
        Param(
            [string[]]$filePath,
            $contentSearcher
        )
            
        $results = @()       

        foreach ($file in $filePath) { 
            $fileContent = Get-Content -Path $file

            foreach ($searcher in $contentSearcher) {                    
                if (-not ($file | Select-String -Pattern $searcher.ResourceMatchPattern -Quiet)) {
                    continue
                }                    

                $match = $fileContent  | Select-String -Pattern $searcher.ContentSearchPatterns.string -AllMatches
                if ($match) {
                    $result             = @{}
                    $result.Filename    = $file                  
                    $result.Matches     = $match
                    $results            += $result
                }                    
            }

            $fileContent = $null
        }            
           
        $results
    }  

    try {
        # BLOCK 3 : Load all regex rules for file types + credential detection. Get all files on disk that match file type rules       
        $Exclude            = $Exclude + @("*.exe", "*.dll")
        $contentSearcher    = Select-Xml -XPath "//ContentSearcher" -Xml $contentSearcherXml  | Select-Object -ExpandProperty Node
        $files              = (Get-ChildItem -Recurse $Recurse -Path $Path -File  -ErrorAction SilentlyContinue -Exclude $Exclude)  | Sort-Object -Property Length 
        $matchingFiles      = [System.Collections.Queue]@(($files.FullName | Select-String -Pattern $contentSearcher.ResourceMatchPattern).Line)           

        # BLOCK 4 : Queue matching files to be processed via Runspacepool
        $totalFiles = $matchingFiles.Count
        $fileCount  = 0
        $waitCount  = 0
        Write-Host "Processing $totalFiles files" -ForegroundColor Green
        
        while ($matchingFiles.Count -gt 0) {
            
            while ($runspaces.Count -lt $MAX_RUNSPACE -and $matchingFiles.Count -gt 0) {           
                $filePath       = $matchingFiles.Dequeue()             
                $runspace       = Create-Runspace $scriptblock $filePath $contentSearcher $pool 
                $runspaces      += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke(); FilePath = $filePath }   
                $fileCount      += 1
            } 
            
            $finishedJobs = $runspaces | Where-Object {$_.Status.IsCompleted -eq $true}          

            foreach ($job in $finishedJobs) {
                $results = $job.Pipe.EndInvoke($job.Status)               
                $job.Pipe.Dispose()  
                $runspaces.Remove($job)
                
                foreach ($result in $results) {                    
                    foreach ($matchInfo in $result.Matches) {                   
                        Write-Host $result.Filename -ForegroundColor Green -NoNewLine
                        Write-Host "@Line::" $matchInfo.LineNumber $matchInfo.Matches -ForegroundColor Red
                    }
                }
            }    
            
            if ($finishedJobs.Count -lt 1) {
                Write-Verbose "Wait period $($waitCount * 100) milliseconds"
                $waitCount += 1
                Start-Sleep -Milliseconds ($waitCount * 100) 
            }
            else {    
                $waitCount = 0
                if ($runspaces.Count -ne 0) {                    
                    Write-Progress -Id 100 -Activity "Parsing files"  -Status "File $fileCount of $totalFiles" -PercentComplete (($fileCount / $totalFiles) * 100)                  
                    0..($MAX_RUNSPACE - 1) | ForEach-Object { 
                        if($_ -lt $runspaces.Count)
                        {
                            Write-Progress -Id $_ -Activity "Files $($runspaces[$_].FilePath)" -ParentId 100 
                        }
                        else 
                        {
                            Write-Progress -Id $_  -ParentId 100 -Completed $true
                        }
                    }
                    
                }
                Write-Verbose "$($runspaces.Count) runspaces running. $($matchingFiles.Count) files still to be processed"
            }            
        }
    }
    catch {
        Write-output $_.Exception.Message
    }  
    finally {  
        # BLOCK 5: Clean up 
        $pool.Close() 
        $pool.Dispose() 
    }

    Write-Host "[]======================================================[]"
    Write-Host "Searching ended at $(Get-Date)"  
}

function Create-Runspace {
    param($scriptblock,
        $processItem,
        $contentSearcher,
        $pool)

    $runspace = [PowerShell]::Create()
    $null = $runspace.AddScript($scriptblock)   
    $null = $runspace.AddArgument($processItem)               
    $null = $runspace.AddArgument($contentSearcher) 
    $null = $runspace.RunspacePool = $pool    
            
    $runspace
}

[xml]$contentSearcherXml = @'
<?xml version="1.0" encoding="utf-8"?>
<ArrayOfContentSearcher xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <ContentSearcher>
    <Name>KeyStoreFile</Name>
    <RuleId>CSCAN0010</RuleId>
    <ResourceMatchPattern>\.keystore$</ResourceMatchPattern>
    <MatchDetails>Found Android app signing keystore file.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secret file, use a secured secret store to save credentials.</Recommendation>
    <Severity>1</Severity>
  </ContentSearcher>
  <ContentSearcher>
    <Name>Base64EncodedCertificate</Name>
    <RuleId>CSCAN0020</RuleId>
    <ResourceMatchPattern>\.(?:cs|ini|json|ps1|publishsettings|template|trd|ts|xml)$</ResourceMatchPattern>
    <ContentPrevalidatePatterns>
      <string>MII[a-zA-Z0-9/+]{200}</string>
    </ContentPrevalidatePatterns>
    <ContentSearchPatterns>
      <string>['">;=]MII[a-z0-9/+]{200}</string>
    </ContentSearchPatterns>
    <MatchDetails>Found base64 encoded certificate with private key in source file.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>1</Severity>
    <SearchValidatorClassName>Microsoft.Security.CredentialScanner.ContentSearch.Base64EncodedCertValidator, Microsoft.Security.CredentialScanner.ContentSearch</SearchValidatorClassName>
  </ContentSearcher>
  <ContentSearcher>
    <Name>PublishSettings</Name>
    <RuleId>CSCAN0030</RuleId>
    <ResourceMatchPattern>\.publishsettings$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>userpwd="[a-z0-9/+]{60}"</string>
    </ContentSearchPatterns>
    <MatchDetails>Found app service deployment secrets in publish settings file.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
  </ContentSearcher>
  <ContentSearcher>
    <Name>StorageAccountKeyInCode</Name>
    <RuleId>CSCAN0041</RuleId>
    <ResourceMatchPattern>(?:\.(?:cs|js|ts|cpp)|policy_and_key\.hpp|AccountConfig\.h)$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>[^a-z0-9/\+\._\-\$,\\][a-z0-9/+]{86}==</string>
    </ContentSearchPatterns>
    <ContentSearchFilters>
      <ContentFilter>
        <Name>Key Patterns ContentFilters</Name>
        <Filters>
          <string>(?:prefix &lt;&lt;|guestaccesstoken|skiptoken|cookie|tsm|fake|example|badlyFormatted|Invalid|sha512|sha256|"input"|ENCRYPTED|"EncodedRequestUri"|looks like|myStorageAccountName|(0|x|\*){8,})</string>
        </Filters>
      </ContentFilter>
    </ContentSearchFilters>
    <MatchDetails>Found Azure storage account access key in source code.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
    <SearchValidatorClassName>Microsoft.Security.CredentialScanner.ContentSearch.Base64EncodedImageValidator, Microsoft.Security.CredentialScanner.ContentSearch</SearchValidatorClassName>
  </ContentSearcher>
  <ContentSearcher>
    <Name>SharedAccessSignatureInCode</Name>
    <RuleId>CSCAN0042</RuleId>
    <ResourceMatchPattern>(?:\.(?:cs|js|ts|cpp)|policy_and_key\.hpp|AccountConfig\.h)$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>[^a-z0-9/\+\._\-\$,\\][a-z0-9/+]{43}=[^{@\d%]</string>
      <string>[^a-z0-9/\+\._\-\$,\\][a-z0-9%]{43,53}%3d[^{a-z0-9%]</string>
    </ContentSearchPatterns>
    <ContentSearchFilters>
      <ContentFilter>
        <Name>Key Patterns ContentFilters</Name>
        <Filters>
          <string>(?:prefix &lt;&lt;|guestaccesstoken|skiptoken|cookie|tsm|fake|example|badlyFormatted|Invalid|sha512|sha256|"input"|ENCRYPTED|"EncodedRequestUri"|looks like|myStorageAccountName|(0|x|\*){8,})</string>
        </Filters>
      </ContentFilter>
    </ContentSearchFilters>
    <MatchDetails>Found Azure shared access signature in source code.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
    <SearchValidatorClassName>Microsoft.Security.CredentialScanner.ContentSearch.Base64EncodedImageValidator, Microsoft.Security.CredentialScanner.ContentSearch</SearchValidatorClassName>
  </ContentSearcher>
  <ContentSearcher>
    <Name>SqlConnectionStringInCode</Name>
    <RuleId>CSCAN0043</RuleId>
    <ResourceMatchPattern>(?:\.(?:cs|js|ts|cpp)|policy_and_key\.hpp|AccountConfig\.h)$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>.*(?:User ID|uid|UserId).*(?:Password|[^a-z]pwd)=[^'$%&gt;@";\[\{][^;/"\r\n ]{7,128}(?:;|")</string>
    </ContentSearchPatterns>
    <ContentSearchFilters>
      <ContentFilter>
        <Name>Key Patterns ContentFilters</Name>
        <Filters>
          <string>(?:prefix &lt;&lt;|guestaccesstoken|skiptoken|cookie|tsm|fake|example|badlyFormatted|Invalid|sha512|sha256|"input"|ENCRYPTED|"EncodedRequestUri"|looks like|myStorageAccountName|(?:0|x|\*){8,})</string>
        </Filters>
      </ContentFilter>
    </ContentSearchFilters>
    <MatchDetails>Found SQL connection string in source code.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
    <SearchValidatorClassName>Microsoft.Security.CredentialScanner.ContentSearch.Base64EncodedImageValidator, Microsoft.Security.CredentialScanner.ContentSearch</SearchValidatorClassName>
  </ContentSearcher>
  <ContentSearcher>
    <Name>PemFile</Name>
    <RuleId>CSCAN0060</RuleId>
    <ResourceMatchPattern>\.pem$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>-{5}BEGIN(?: (?:[dr]sa|ec|openssh))? PRIVATE KEY-{5}</string>
    </ContentSearchPatterns>
    <MatchDetails>Found PEM certificate file with private key.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secret file, use a secured secret store to save credentials.</Recommendation>
    <Severity>3</Severity>
  </ContentSearcher>
  <ContentSearcher>
    <Name>AspNetMachineKeyInConfig</Name>
    <RuleId>CSCAN0091</RuleId>
    <ResourceMatchPattern>\.(?:config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>&lt;machineKey[^&gt;]+(?:decryptionKey\s*\=\s*&quot;[a-fA-F0-9]{48,}|validationKey\s*\=\s*&quot;[a-fA-F0-9]{48,})[^&gt;]+&gt;</string>
      <string>(?:decryptionKey|validationKey)=&quot;[a-zA-Z0-9]+&quot;</string>
    </ContentSearchPatterns>
    <ContentSearchFilters>
      <ContentFilter>
        <Name>Key Patterns ContentFilters</Name>
        <Filters>
          <string>key\s*=\s*"[^"]*AppKey[^"]*"\s+value\s*=\s*"[a-z]+"</string>
          <string>key\s*=\s*"(?&lt;keygroup>[^"]*)"\s+value\s*=\s*"[^"]*\k&lt;keygroup>"</string>
          <string>value\s*=\s*"(?:[a-z]+(?: [a-z]+)+"|_+[a-z]+_+"|[a-z]+-[a-z]+-[a-z]+["-]|[a-z]+-[a-z]+"|[a-z]+\\[a-z]+"|\d+"|[^"]*ConnectionString")</string>
          <string>Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager</string>
          <string>value=&quot;(?:true|false|@\(api|ssh\-rsa 2048|invalid|to be|a shared secret|secreturi|clientsecret|Overr?idden by|someValue|SOME\-SIGNING\-KEY|TokenBroker|UNKNOWN|Client Secret of|Junk Credentials|Default\-|__BOOTSTRAPKEY_|CacheSecret|CatalogCert|CosmosCredentials|DeleteServiceCert|EmailCredentials|MetricsConnection|SangamCredentials|SubscriptionConnection|Enter_your_|My_Issuer|ScaleUnitXstoreSharedKey|private_powerapps|TestSecret|foo_|bar_|temp_|__WinfabricTestInfra|configured|SecretFor|Test|XSTORE_KEY|ServiceBusDiagnosticXstoreSharedKey|BoxApplicationKey|googleapps)</string>
          <string>(?:_AppKey&quot;|(?:(?:credential|password|token)s?|(?:Account|access)Key=)&quot;[\s\r\n]*/|Username&quot;|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name&quot;|Ref&quot;)|(Secret|Credential)s?(Name|Path)&quot;|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})</string>
        </Filters>
      </ContentFilter>
    </ContentSearchFilters>
    <MatchDetails>Found Asp.Net Machine Key in config file.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
    <SearchValidatorClassName>Microsoft.Security.CredentialScanner.ContentSearch.Base64EncodedImageValidator, Microsoft.Security.CredentialScanner.ContentSearch</SearchValidatorClassName>
  </ContentSearcher>
  <ContentSearcher>
    <Name>SqlConnectionStringInConfig</Name>
    <RuleId>CSCAN0092</RuleId>
    <ResourceMatchPattern>\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>(?:connectionstring|connString)[^=]*=["'][^"']*Password\s*=\s*[^\s;][^"']*(?:\x22|\x27)</string>
      <string>.*(?:User ID|uid|UserId).*(?:Password|[^a-z]pwd)=[^'$%&gt;@'";\[\{][^;/"]{7,128}(?:;|")</string>
    </ContentSearchPatterns>
    <ContentSearchFilters>
      <ContentFilter>
        <Name>Key Patterns ContentFilters</Name>
        <Filters>
          <string>key\s*=\s*"[^"]*AppKey[^"]*"\s+value\s*=\s*"[a-z]+"</string>
          <string>key\s*=\s*"(?&lt;keygroup>[^"]*)"\s+value\s*=\s*"[^"]*\k&lt;keygroup>"</string>
          <string>value\s*=\s*"(?:[a-z]+(?: [a-z]+)+"|_+[a-z]+_+"|[a-z]+-[a-z]+-[a-z]+["-]|[a-z]+-[a-z]+"|[a-z]+\\[a-z]+"|\d+"|[^"]*ConnectionString")</string>
          <string>Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager</string>
          <string>value=&quot;(?:true|false|@\(api|ssh\-rsa 2048|invalid|to be|a shared secret|secreturi|clientsecret|Overr?idden by|someValue|SOME\-SIGNING\-KEY|TokenBroker|UNKNOWN|Client Secret of|Junk Credentials|Default\-|__BOOTSTRAPKEY_|CacheSecret|CatalogCert|CosmosCredentials|DeleteServiceCert|EmailCredentials|MetricsConnection|SangamCredentials|SubscriptionConnection|Enter_your_|My_Issuer|ScaleUnitXstoreSharedKey|private_powerapps|TestSecret|foo_|bar_|temp_|__WinfabricTestInfra|configured|SecretFor|Test|XSTORE_KEY|ServiceBusDiagnosticXstoreSharedKey|BoxApplicationKey|googleapps)</string>
          <string>(?:_AppKey&quot;|(?:(?:credential|password|token)s?|(?:Account|access)Key=)&quot;[\s\r\n]*/|Username&quot;|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name&quot;|Ref&quot;)|(Secret|Credential)s?(Name|Path)&quot;|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})</string>
        </Filters>
      </ContentFilter>
    </ContentSearchFilters>
    <MatchDetails>Found Sql connection string in config file.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
    <SearchValidatorClassName>Microsoft.Security.CredentialScanner.ContentSearch.Base64EncodedImageValidator, Microsoft.Security.CredentialScanner.ContentSearch</SearchValidatorClassName>
  </ContentSearcher>
  <ContentSearcher>
    <Name>StorageAccountKeyInConfig</Name>
    <RuleId>CSCAN0093</RuleId>
    <ResourceMatchPattern>\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>[^a-z0-9/\+\._\-\$,\\][a-z0-9/+]{86}==</string>
    </ContentSearchPatterns>
    <ContentSearchFilters>
      <ContentFilter>
        <Name>Key Patterns ContentFilters</Name>
        <Filters>
          <string>key\s*=\s*"[^"]*AppKey[^"]*"\s+value\s*=\s*"[a-z]+"</string>
          <string>key\s*=\s*"(?&lt;keygroup>[^"]*)"\s+value\s*=\s*"[^"]*\k&lt;keygroup>"</string>
          <string>value\s*=\s*"(?:[a-z]+(?: [a-z]+)+"|_+[a-z]+_+"|[a-z]+-[a-z]+-[a-z]+["-]|[a-z]+-[a-z]+"|[a-z]+\\[a-z]+"|\d+"|[^"]*ConnectionString")</string>
          <string>Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager</string>
          <string>value=&quot;(?:true|false|@\(api|ssh\-rsa 2048|invalid|to be|a shared secret|secreturi|clientsecret|Overr?idden by|someValue|SOME\-SIGNING\-KEY|TokenBroker|UNKNOWN|Client Secret of|Junk Credentials|Default\-|__BOOTSTRAPKEY_|CacheSecret|CatalogCert|CosmosCredentials|DeleteServiceCert|EmailCredentials|MetricsConnection|SangamCredentials|SubscriptionConnection|Enter_your_|My_Issuer|ScaleUnitXstoreSharedKey|private_powerapps|TestSecret|foo_|bar_|temp_|__WinfabricTestInfra|configured|SecretFor|Test|XSTORE_KEY|ServiceBusDiagnosticXstoreSharedKey|BoxApplicationKey|googleapps)</string>
          <string>(?:_AppKey&quot;|(?:(?:credential|password|token)s?|(?:Account|access)Key=)&quot;[\s\r\n]*/|Username&quot;|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name&quot;|Ref&quot;)|(Secret|Credential)s?(Name|Path)&quot;|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})</string>
        </Filters>
      </ContentFilter>
    </ContentSearchFilters>
    <MatchDetails>Found Azure storage account key in config file.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
    <SearchValidatorClassName>Microsoft.Security.CredentialScanner.ContentSearch.Base64EncodedImageValidator, Microsoft.Security.CredentialScanner.ContentSearch</SearchValidatorClassName>
  </ContentSearcher>
  <ContentSearcher>
    <Name>SharedAccessSignatureInConfig</Name>
    <RuleId>CSCAN0094</RuleId>
    <ResourceMatchPattern>\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>[^a-z0-9/\+\._\-\$,\\][a-z0-9/+]{43}=[^{@]</string>
      <string>[^a-z0-9/\+\._\-\$,\\][a-z0-9%]{43,53}%3d[^a-z0-9%]</string>
    </ContentSearchPatterns>
    <ContentSearchFilters>
      <ContentFilter>
        <Name>Key Patterns ContentFilters</Name>
        <Filters>
          <string>key\s*=\s*"[^"]*AppKey[^"]*"\s+value\s*=\s*"[a-z]+"</string>
          <string>key\s*=\s*"(?&lt;keygroup>[^"]*)"\s+value\s*=\s*"[^"]*\k&lt;keygroup>"</string>
          <string>value\s*=\s*"(?:[a-z]+(?: [a-z]+)+"|_+[a-z]+_+"|[a-z]+-[a-z]+-[a-z]+["-]|[a-z]+-[a-z]+"|[a-z]+\\[a-z]+"|\d+"|[^"]*ConnectionString")</string>
          <string>Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager</string>
          <string>value=&quot;(?:true|false|@\(api|ssh\-rsa 2048|invalid|to be|a shared secret|secreturi|clientsecret|Overr?idden by|someValue|SOME\-SIGNING\-KEY|TokenBroker|UNKNOWN|Client Secret of|Junk Credentials|Default\-|__BOOTSTRAPKEY_|CacheSecret|CatalogCert|CosmosCredentials|DeleteServiceCert|EmailCredentials|MetricsConnection|SangamCredentials|SubscriptionConnection|Enter_your_|My_Issuer|ScaleUnitXstoreSharedKey|private_powerapps|TestSecret|foo_|bar_|temp_|__WinfabricTestInfra|configured|SecretFor|Test|XSTORE_KEY|ServiceBusDiagnosticXstoreSharedKey|BoxApplicationKey|googleapps)</string>
          <string>(?:_AppKey&quot;|(?:(?:credential|password|token)s?|(?:Account|access)Key=)&quot;[\s\r\n]*/|Username&quot;|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name&quot;|Ref&quot;)|(Secret|Credential)s?(Name|Path)&quot;|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})</string>
          <string>AccountKey\s*=\s*MII[a-z0-9/+]{43,}={0,2}</string>
        </Filters>
      </ContentFilter>
    </ContentSearchFilters>
    <MatchDetails>Found Azure shared access signature in config file.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
    <SearchValidatorClassName>Microsoft.Security.CredentialScanner.ContentSearch.Base64EncodedImageValidator, Microsoft.Security.CredentialScanner.ContentSearch</SearchValidatorClassName>
  </ContentSearcher>
  <ContentSearcher>
    <Name>GeneralSecretInConfig</Name>
    <RuleId>CSCAN0095</RuleId>
    <ResourceMatchPattern>\.(?:config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>&lt;add\skey=&quot;[^&quot;]+(?:key(?:s|[0-9])?|credentials?|secret(?:s|[0-9])?|password|token|KeyPrimary|KeySecondary|KeyOrSas|KeyEncrypted)&quot;\s*value\s*=&quot;[^&quot;]+&quot;[^&gt;]*/&gt;</string>
      <string>&lt;add\skey=&quot;[^&quot;]+&quot;\s*value=&quot;[^&quot;]*EncryptedSecret:[^&quot;]+&quot;\s*/&gt;</string>
      <string>value\s?=\s?&quot;(?:(?:(?:[a-z0-9+/]){4}){1,200})==&quot;</string>
      <string>&lt;Credential\sname="[^"]*(?:key(?:s|[0-9])?|credentials?|secret(?:s|[0-9])?|password|token|KeyPrimary|KeySecondary|KeyOrSas|KeyEncrypted)"(\s*value\s*="[^"]+".*?/&gt;|[^&gt;]*&gt;.*?&lt;/Credential&gt;)</string>
      <string>&lt;setting\sname="[^"]*Password".*[\r\n]*\s*&lt;value&gt;.+&lt;/value&gt;</string>
    </ContentSearchPatterns>
    <ContentSearchFilters>
      <ContentFilter>
        <Name>Key Patterns ContentFilters</Name>
        <Filters>
          <string>key\s*=\s*"[^"]*AppKey[^"]*"\s+value\s*=\s*"[a-z]+"</string>
          <string>key\s*=\s*"(?&lt;keygroup>[^"]*)"\s+value\s*=\s*"[^"]*\k&lt;keygroup>"</string>
          <string>value\s*=\s*"(?:[a-z]+(?: [a-z]+)+"|_+[a-z]+_+"|[a-z]+-[a-z]+-[a-z]+["-]|[a-z]+-[a-z]+"|[a-z]+\\[a-z]+"|\d+"|[^"]*ConnectionString")</string>
          <string>Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager</string>
          <string>value=&quot;(?:true|false|@\(api|ssh\-rsa 2048|invalid|to be|a shared secret|secreturi|clientsecret|Overr?idden by|someValue|SOME\-SIGNING\-KEY|TokenBroker|UNKNOWN|Client Secret of|Junk Credentials|Default\-|__BOOTSTRAPKEY_|CacheSecret|CatalogCert|CosmosCredentials|DeleteServiceCert|EmailCredentials|MetricsConnection|SangamCredentials|SubscriptionConnection|Enter_your_|My_Issuer|ScaleUnitXstoreSharedKey|private_powerapps|TestSecret|foo_|bar_|temp_|__WinfabricTestInfra|configured|SecretFor|Test|XSTORE_KEY|ServiceBusDiagnosticXstoreSharedKey|BoxApplicationKey|googleapps)</string>
          <string>(?:_AppKey&quot;|(?:(?:credential|password|token)s?|(?:Account|access)Key=)&quot;[\s\r\n]*/|Username&quot;|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name&quot;|Ref&quot;)|(Secret|Credential)s?(Name|Path)&quot;|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})</string>
          <string>AccountKey\s*=\s*MII[a-z0-9/+]{43,}={0,2}</string>
        </Filters>
      </ContentFilter>
    </ContentSearchFilters>
    <MatchDetails>Found password or symmetric key in config file.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
    <SearchValidatorClassName>Microsoft.Security.CredentialScanner.ContentSearch.Base64EncodedImageValidator, Microsoft.Security.CredentialScanner.ContentSearch</SearchValidatorClassName>
  </ContentSearcher>
  <ContentSearcher>
    <Name>ScriptPassword</Name>
    <RuleId>CSCAN0110</RuleId>
    <ResourceMatchPattern>(?:\.cmd|\.ps|\.ps1|\.psm1)$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>\s-Password\s+(?:&quot;[^&quot;]*&quot;|&apos;[^&apos;]*&apos;)</string>
      <string>\s-Password\s+[^$\(\)\[\{&lt;\-\r\n]+\s*(?:\r\n|\-)</string>
    </ContentSearchPatterns>
    <MatchDetails>Found password in script file.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
  </ContentSearcher>
  <ContentSearcher>
    <Name>ExternalApiSecret</Name>
    <RuleId>CSCAN0120</RuleId>
    <ResourceMatchPattern>\.cs$|\.cpp$|\.c$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>private\sconst\sstring\sAccessTokenSecret\s=\s".*";</string>
      <string>private\sconst\sstring\saccessToken\s=\s".*";</string>
      <string>private\sconst\sstring\sconsumerSecret\s=\s".*";</string>
      <string>private\sconst\sstring\sconsumerKey\s=\s".*";</string>
      <string>FacebookClient\(pageAccessToken\);</string>
      <string>pageAccessToken\s=\s".*";</string>
      <string>private\sstring\stwilioAccountSid\s=\s".*";</string>
      <string>private\sstring\stwilioAuthToken\s=\s".*";</string>
    </ContentSearchPatterns>
    <MatchDetails>Found external API secret in source code.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
  </ContentSearcher>
  <ContentSearcher>
    <Name>DomainPassword</Name>
    <RuleId>CSCAN0160</RuleId>
    <ResourceMatchPattern>\.cs$|\.c$|\.cpp$|\.ps1$|\.ps$|\.cmd$|\.bat$|\.log$|\.psd$|\.psm1$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>new(?:-object)?\s+System.Net.NetworkCredential\(?:.*?,\s*"[^"]+"</string>
    </ContentSearchPatterns>
    <ContentSearchFilters>
      <ContentFilter>
        <Name>Placeholder ContentFilters</Name>
        <Filters>
          <string>%1%</string>
          <string>\$MIGUSER_PASSWORD</string>
          <string>%miguser_pwd%</string>
        </Filters>
      </ContentFilter>
    </ContentSearchFilters>
    <MatchDetails>Found domain credential in source code.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
  </ContentSearcher>
  <ContentSearcher>
    <Name>GitCredential</Name>
    <RuleId>CSCAN0210</RuleId>
    <ResourceMatchPattern>\.gitCredentials$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>https?://.+:.+@\[^/].com</string>
    </ContentSearchPatterns>
    <MatchDetails>Found Git repo credentials.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>2</Severity>
  </ContentSearcher>
  <ContentSearcher>
    <Name>DefaultPasswordContexts</Name>
    <RuleId>CSCAN0220</RuleId>
    <ResourceMatchPattern>\.(?:cs|xml|config|json|ts|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>ConvertTo-SecureString(?:\s*-String)?\s*"[^"\r\n]+"</string>
      <string>new\sX509Certificate2\([^()]*,\s*"[^"\r\n]+"[^)]*\)</string>
      <string>AdminPassword\s*=\s*"[^"\r\n]+"</string>
      <string>&lt;password&gt;.+&lt;/password&gt;</string>
      <string>ClearTextPassword"?\s*[:=]\s*"[^"\r\n]+"</string>
      <string>certutil.*?\-p\s+(?&lt;quote&gt;["'])[^"'%]+\k&lt;quote&gt;</string>
      <string>certutil.*?\-p\s+[^"']\S*\s</string>
      <string>password\s*=\s*N?(?&lt;quote&gt;["'])[^"'\r\n]{4,}\k&lt;quote&gt;</string>
    </ContentSearchPatterns>
    <MatchDetails>Found password context in source code.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
    <SearchValidatorClassName>Microsoft.Security.CredentialScanner.ContentSearch.PasswordContextValidator, Microsoft.Security.CredentialScanner.ContentSearch</SearchValidatorClassName>
  </ContentSearcher>
  <ContentSearcher>
    <Name>SlackToken</Name>
    <RuleId>CSCAN0230</RuleId>
    <ResourceMatchPattern>\.(?:ps1|psm1|js|json|coffee|xml|js|md|html|py|php|java|ipynb|rb)$|hubot</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>xoxp-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+</string>
      <string>xoxb-[a-z0-9]+-[a-z0-9]+</string>
    </ContentSearchPatterns>
    <MatchDetails>Found Slack token in source code.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
  </ContentSearcher>
  <ContentSearcher>
    <Name>VstsPersonalAccessToken</Name>
    <RuleId>CSCAN0240</RuleId>
    <ResourceMatchPattern>\.(?:cs|ps1|bat|config|xml|json)$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>AccessToken.*?['="][a-z0-9]{52}(?:'|"|\s|[\r\n]+)</string>
      <string>[>|'|=|"][a-z0-9/+]{70}==</string>
      <string>password\s+[a-z0-9]{52}(?:\s|[\r\n]+)</string>
    </ContentSearchPatterns>
    <MatchDetails>Found VSTS personal access token in source code.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
    <SearchValidatorClassName>Microsoft.Security.CredentialScanner.ContentSearch.Base64EncodedVstsAccessTokenValidator, Microsoft.Security.CredentialScanner.ContentSearch</SearchValidatorClassName>
  </ContentSearcher>
  <ContentSearcher>
    <Name>OAuthToken</Name>
    <RuleId>CSCAN0250</RuleId>
    <ResourceMatchPattern>\.(?:config|js|json|txt|cs|xml|java|py)$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>eyj[a-z0-9\-_%]+\.eyj[a-z0-9\-_%]+\.[a-z0-9\-_%]+</string>
      <string>refresh_token["']?\s*[:=]\s*["']?(?:[a-z0-9_]+-)+[a-z0-9_]+["']?</string>
    </ContentSearchPatterns>
    <ContentSearchFilters>
      <ContentFilter>
        <Name>Key Patterns ContentFilters</Name>
        <Filters>
          <string>[:=]\s*["']?(?:base64-encoded|(?:[a-z]+-)+[a-z]+)["']?</string>
        </Filters>
      </ContentFilter>
    </ContentSearchFilters>
    <MatchDetails>Found JSON web token or refresh token in source code.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
    <SearchValidatorClassName>Microsoft.Security.CredentialScanner.ContentSearch.JsonWebTokenValidator, Microsoft.Security.CredentialScanner.ContentSearch</SearchValidatorClassName>
  </ContentSearcher>
  <ContentSearcher>
    <Name>AnsibleVault</Name>
    <RuleId>CSCAN0260</RuleId>
    <ResourceMatchPattern>\.yml$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>\$ANSIBLE_VAULT;[0-9]\.[0-9];AES256[\r\n]+[0-9]+</string>
    </ContentSearchPatterns>
    <MatchDetails>Found Ansible vault in source code.</MatchDetails>
    <Recommendation>Validate, rotate and remove the secrets in file, use a secured secret store to save credentials. </Recommendation>
    <Severity>3</Severity>
  </ContentSearcher>
</ArrayOfContentSearcher>
'@