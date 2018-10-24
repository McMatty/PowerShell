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
        None
#>
function Hunt-Credentials
{
    [CmdletBinding()]
    param([string]$Path)

    $rulesPath          = "C:\Temp\cred\Searchers\buildsearchers.xml"
    $contentSearcher    = Select-Xml -XPath "//ContentSearcher" -Path $rulesPath | Select-Object -ExpandProperty Node
    $files              = Get-ChildItem -Recurse -Path $Path -File  -ErrorAction SilentlyContinue -Exclude "*.dll", "*.exe"  
    $matchingFiles      =  ($files.FullName | Select-String -Pattern $contentSearcher.ResourceMatchPattern).Line

    if($matchingFiles){
        $matchingFiles | ForEach-Object { Get-Content -Path $_ | Select-String -Pattern $contentSearcher.ContentSearchPatterns.string -AllMatches}
    }
}

Hunt-Credentials -Path "C:\"