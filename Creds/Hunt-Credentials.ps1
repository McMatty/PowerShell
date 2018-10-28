<#
        .SYNOPSIS
        Looks for credentials recursively based of Microsofts CredScan regular expressions
        .DESCRIPTION
        Searches the path provided recursively for file types matching those in which credentials
        .EXAMPLE
        Hunt-Credentials -Path "C:\"
        .INPUTS
        [string]
        .OUTPUTS
        [string]
        .NOTES
        Excludes *.dll, *.exe. 
        Minified js files currently destroy the regular expressions so its suggested to exclude these unless you have alot of time
#>
function Hunt-Credentials {
    [CmdletBinding()]
    param([string]$Path,
    [string[]]$Exclude)
   
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
                    $result = @{}
                    $result.Filename = $file                  
                    $result.Matches = $match
                    $results += $result
                }                    
            }
        }            
           
        $results
    }  

    try {
        # BLOCK 3 : Load all regex rules for file types + credential detection. Get all files on disk that match file type rules
        $rulesPath          = "C:\Temp\cred\Searchers\buildsearchers.xml"
        $Exclude            = $Exclude + @("*.exe", "*.dll")
        $contentSearcher    = Select-Xml -XPath "//ContentSearcher" -Path $rulesPath | Select-Object -ExpandProperty Node
        $files              = (Get-ChildItem -Recurse -Path $Path -File  -ErrorAction SilentlyContinue -Exclude $Exclude)  | Sort-Object -Property Length 
        $matchingFiles      = [System.Collections.Queue]@(($files.FullName | Select-String -Pattern $contentSearcher.ResourceMatchPattern).Line)           

        # BLOCK 4 : Queue matching files to be processed via Runspacepool
        $totalFiles = $matchingFiles.Count
        $fileCount  = 0
        $waitCount  = 0
        Write-Host "Processing $totalFiles files" -ForegroundColor Green
        
        while ($matchingFiles.Count -gt 0) {
            
            while ($runspaces.Count -lt $MAX_RUNSPACE -and $matchingFiles.Count -gt 0) {           
                $filePath = $matchingFiles.Dequeue()             
                $runspace = Create-Runspace $scriptblock $filePath $contentSearcher $pool 
                $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke(); FilePath = $filePath }   
                $fileCount += 1
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
                    $processingFiles = Split-Path $runspaces.FilePath -leaf
                    Write-Progress -Activity "Parsing files"  -Status "File $fileCount of $totalFiles" -PercentComplete (($fileCount / $totalFiles) * 100)
                    $displayCount = 0
                    $processingFiles | ForEach-Object {$displayCount+=1; Write-Progress -Id $displayCount -Activity "Files $_" }
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
        
        Write-Host "[]======================================================[]"
        Write-Host "Searching ended at $(Get-Date)"  
    }
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