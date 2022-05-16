# PowerShell Module file for OpCon API
# Use Import-Module to use these functions inside another PS script
##################################################################################################

# For skipping self signed certificates in Powershell 7 (core)
function OpCon_SkipCerts
{
    if($PSVersionTable.PSVersion.Major -lt 6)
    {
        try
        {
            Add-Type -TypeDefinition  @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy
            {
                public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem)
                {
                    return true;
                }
            }
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
        catch
        { Write-Host "Error Ignoring Self Signed Certs" }
    }
    else 
    {
        try
        { $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck",$true) }
        catch
        { $null }   
    }
}

# Used if calling an API that is not local to the machine, **Powershell 3-5 only***
# Keeping this function for legacy purposes, but references the newer "all-in-one" version
function OpCon_IgnoreSelfSignedCerts
{
    OpCon_SkipCerts
}

#Get user/app token
function OpCon_Login
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$user
        ,[string] $password
        ,[string] $appname
    )

    #Builds user hashtable
    if($appname)
    {
        $body = @{
            "user"=@{
                "loginName"=$user;
                "password"=$password};
                "tokenType"=@{
                    "id"=$appname;
                    "type"="Application"
            }
        }
    }
    elseif($user -like "Win*Auth*")
    { 
        try
        {
            return Invoke-Restmethod -Method POST -Uri ($url + "/api/tokens") -ContentType "application/json" -UseDefaultCredentials
        }
        catch [Exception]
        {
            write-host $_
            write-host $_.Exception.Message
        }
    }
    else 
    {
        $body = @{
            "user"= @{
                "loginName"=$user;
                "password"=$password};
                "tokenType"=@{
                    "type"="User"
                }
        }        
    }
                
    try
    {
        return Invoke-Restmethod -Method POST -Uri ($url + "/api/tokens") -Body ($body | ConvertTo-Json) -ContentType "application/json"
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }
}
New-Alias "opc-login" OpCon_GetLogin

function OpCon_Errors($action)
{
    $ErrorActionPreference = $action
}

#Delete token from database
function OpCon_DeleteAPIToken
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
    )

    try
    {
        return Invoke-Restmethod -Method DELETE -Uri ($url + "/api/tokens") -Header @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }
}
New-Alias "opc-deleteapitoken" OpCon_DeleteAPIToken

<#
.SYNOPSIS

Gets a global property value from OpCon.

.OUTPUTS

ID, Value, Encryption of global property.

.EXAMPLE

C:\PS> opgp -Name "My Property"
#>
function OpCon_GetGlobalProperty
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[string] $id
        ,[string] $name
    )

    #Get property information
    If($id)
    {
        $uriget = $url + "/api/globalproperties/" + $id
    }
    ElseIf($name)
    {
        $uriget = $url + "/api/globalproperties?name=" + $name
    }
    Else
    {
        $uriget = $url + "/api/globalproperties"
    }

    try
    {
        return Invoke-Restmethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }
}
New-Alias "opc-getglobalproperty" OpCon_GetGlobalProperty
New-Alias "opc-getglobalproperties" OpCon_GetGlobalProperty
New-Alias "opc-getgp" OpCon_GetGlobalProperty

#Creates a new global property
function OpCon_CreateGlobalProperty
{   
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$name
        ,[Parameter(Mandatory=$true)] [string]$value
        ,[string] $encrypt = $false
    )

    #Get property information
    $body = @{
        "name" = $name;
        "value" = $value;
        "encrypted" = $encrypt
    }

    try
    { 
        return Invoke-Restmethod -Method POST -Uri ($url + "/api/globalproperties") -Headers @{"authorization" = $token} -Body ($body | ConvertTo-Json) -ContentType "application/json"  
    }
    catch [Exception]
    {
        write-host $_.Exception
        write-host $_.Exception.Message
    }
}
New-Alias "opc-createproperty" OpCon_CreateGlobalProperty

#Sets a global property to a value
function OpCon_SetGlobalProperty
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$value
        ,[string] $id
        ,[string] $name
    )

    If($name -or $id)
    {
        $property = OpCon_GetGlobalProperty -url $url -token $token -name $name -id $id

        $counter = 0
        $property | ForEach-Object{ $counter++ }

        if($counter -ne 1)
        {
            Write-Output "Too many or no properties found!"
            Exit 1
        }
        else 
        {
            $property[0].value = $value

            #Update property value
            try
            {
                return Invoke-Restmethod -Method PUT -Uri ($url + "/api/globalproperties/" + $property[0].id) -Headers @{"authorization" = $token} -Body ($property[0] | ConvertTo-Json) -ContentType "application/json"
            }
            catch [Exception]
            {
                write-output $_
                write-output $_.Exception.Message
            }       
        }
    }
    Else
    {
        Write-Output "Id or Name not specified!"
        Exit 1
    }
}
New-Alias "opc-setproperty" OpCon_SetGlobalProperty

#Get threshold
function OpCon_GetThreshold
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[string]$id
        ,[string]$name
    )

    #Changes the url based on if id/name provided
    If($id)
    {
        $uriget = $url + "/api/thresholds/" + $id
    }
    ElseIf($name)
    {
        $uriget = $url + "/api/thresholds?name=" + $name
    }
    Else
    {
        $uriget = $url + "/api/thresholds"
    }

    try
    {
        return Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }
}
New-Alias "opc-getthreshold" OpCon_GetThreshold

#Create threshold
function OpCon_CreateThreshold
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$name
        ,[Parameter(Mandatory=$true)] [string]$value
        ,[string] $description
    )

    $body = @{
        "name" = $name;
        "value" = $value;
        "description" = $description
    }
 
    try
    {
        return Invoke-RestMethod -Method POST -Uri ($url + "/api/thresholds") -Body ($body | ConvertTo-Json) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }
}
New-Alias "opc-createthreshold" OpCon_CreateThreshold

#Set threshold value
function OpCon_SetThreshold
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$value
        ,[string] $id
        ,[string] $name
        ,[string] $description
    )

    If($name -or $id)
    {
        if($name)
        { $threshold = OpCon_GetThreshold -url $url -token $token -name $name }
        else
        { $threshold = OpCon_GetThreshold -url $url -token $token -id $id }

        $counter = 0
        $threshold | ForEach-Object { $counter ++ }
    
        if($counter -ne 1)
        {
            Write-Output "0 or more than 1 threshold found matching name/id, cannot set value"
            Exit 1
        }
        else 
        {
            if($value.StartsWith("+"))
            {
                $value = $threshold[0].value + [convert]::ToInt32($value.SubString(1))
            }
            elseif($value.StartsWith("-"))
            {
                if($threshold[0].value -lt $value.SubString(1))
                { $value = 0 }
                else
                { $value = $threshold[0].value - [convert]::ToInt32($value.SubString(1)) }
            }
        
            if(!$description)
            { $description = "" }
        
            $body = @{
                "id" = $threshold[0].id;
                "name" = $name;
                "value" = $value;
                "description" = ""
            }
        
            try
            {
                return Invoke-RestMethod -Method PUT -Uri ($url + "/api/thresholds/" + $threshold[0].id) -Body ($body | ConvertTo-Json) -Headers @{"authorization" = $token} -ContentType "application/json"
            }
            catch [Exception]
            {
                Write-Output $_
                Write-Output $_.Exception.Message
            }
        }
    }
    Else
    {
        Write-Output "No name or id specified!"
        Exit 1
    }
}
New-Alias "opc-setthreshold" OpCon_SetThreshold

#Get resource
function OpCon_GetResource
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[string] $name
        ,[string] $id
    )

    #Changes the url based on if id/name provided
    If($id)
    {
        $uriget = $url + "/api/resources/" + $id
    }
    ElseIf($name)
    {
        $uriget = $url + "/api/resources?name=" + $name
    }
    Else
    {
        $uriget = $url + "/api/resources"
    }

    try
    {
        return Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-getresource" OpCon_GetResource

#Create resource
function OpCon_CreateResource
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$name
        ,[Parameter(Mandatory=$true)] [string]$value
        ,[string] $description
    )

    $resource = OpCon_GetResource -url $url -token $token -name $name
    $counter = 0
    $resource | ForEach-Object { $counter ++ }

    if($counter -eq 1)
    {
        Write-Output "Resource $name already exists"
        Exit 1
    }
    else 
    {
        $body = @{
            "name" = $name;
            "value" = $value;
            "description" = $description
        }
        
        try
        {
            return Invoke-RestMethod -Method POST -Uri ($url + "/api/resources") -Body ($body | ConvertTo-Json) -Headers @{"authorization" = $token} -ContentType "application/json"
        }
        catch [Exception]
        {
            Write-Output $_
            Write-Output $_.Exception.Message
        }       
    }
}
New-Alias "opc-createresouce" OpCon_CreateResource

#Set resource value
function OpCon_SetResource
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[int]$value
        ,[string] $id
        ,[string] $name
        ,[string] $description
        ,[string] $used
    )

    $resource = OpCon_GetResource -url $url -token $token -name $name -id $id

    $counter = 0
    $resource | ForEach-Object { $counter ++ }

    if($counter -ne 1)
    {
        Write-Output "More than 1 or no result, cannot set resource"
        Exit 1
    }
    else 
    {
        if($value)
        {
            if($value.StartsWith("+"))
            {
                $value = $resource[0].value + [convert]::ToInt32($value.SubString(1))
            }
            elseif($value.StartsWith("-"))
            {
                if($resource[0].value -lt $value.SubString(1))
                { $value = 0 }
                else
                { $value = $resource[0].value - [convert]::ToInt32($value.SubString(1)) }
            }
        }
        else
        { $value = $resource[0].value }

        if($used)
        {
            if($used.StartsWith("+"))
            {
                if(($resource[0].used + [convert]::ToInt32($used.SubString(1))) -gt $value)
                { $used = $value }
                else
                { $used = $resource[0].used + [convert]::ToInt32($used.SubString(1)) }
            }
            elseif($used.StartsWith("-"))
            {
                if($resource[0].used -lt $used.SubString(1))
                { $used = 0 }
                else
                { $value = $resource[0].inuse - [convert]::ToInt32($used.SubString(1)) }
            }
        }
        else
        { $used = $resource[0].used }

        If(!$description)
        { $description = "" }

        $body = @{
            "id" = $resource[0].id;
            "name" = $name;
            "value" = $value;
            "used" = $used;
            "description" = $description
        }
        
        try
        {
            return Invoke-RestMethod -Method PUT -Uri ($url + "/api/resources/" + $resource[0].id) -Body ($body | ConvertTo-Json) -Headers @{"authorization" = $token} -ContentType "application/json"
        }
        catch [Exception]
        {
            Write-Output $_
            Write-Output $_.Exception.Message
        }
    }
}
New-Alias "opc-setresource" OpCon_SetResource

#Gets information about an OpCon Agent
function OpCon_GetAgent
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[string] $id
        ,[string] $agentname
    )

    #If id is passed use it, otherwise name
    If($id)
    {
        $uriget = $url + "/api/machines/" + $id + "&extendedProperties=true"
    }
    ElseIf($agentname)
    {
        $uriget = $url + "/api/machines?name=" + $agentname + "&extendedProperties=true"
    }
    Else
    {
        $uriget = $url + "/api/machines?extendedProperties=true"
    }

    try
    {
        return Invoke-Restmethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-getagent" OpCon_GetAgent

#Starts or stops an OpCon agent based on parameters
function OpCon_ChangeAgentStatus
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$agentname
        ,[Parameter(Mandatory=$true)] [string]$action
    )

    $machine = OpCon_GetAgent -agentname $agentname -url $url -token $token
    if($machine.Count -eq 0)
    {
        Write-Output "No agent by that name!"
        Exit 1
    }
    else
    { 
        $machine = $machine[0]

        #Enable/Disable the machine
        $body = @{
            "machines"=@(
                @{
                    "id"=$machine.id;
                }
            );
            "action"=$action
        }

        try
        {
            $machineaction = Invoke-Restmethod -Method POST -Uri ($url + "/api/machineactions") -Headers @{"authorization" = $token} -Body ($body | ConvertTo-Json -Depth 5) -ContentType "application/json"
            Write-Output "Agent is $action!"
            
            return $machineaction
        }
        catch [Exception]
        {
            Write-Output $_.Exception
            write-Output $_.Exception.Message
        }
    }
}
New-Alias "opc-changeagentstatus" OpCon_ChangeAgentStatus


#Creates a new agent in OpCon
function OpCon_CreateAgent($agentname,$agenttype,$agentdescription,$agentsocket,$agentjors,$token,$url)
{
    $exists = OpCon_GetAgent -agentname $agentname -url $url -token $token
    if($exists.Count -eq 0)
    {
        #Assign Agent type # based off provided OS name
        $agenttypeid = switch ($agenttype) 
        { 
            "FILE TRANSFER" {"1"}
            "HP NONSTOP"    {"2"}
            "WINDOWS"       {"3"} 
            "OPENVMW"       {"4"} 
            "IBMI"          {"5"}
            "UNIX"          {"6"}
            "OS2200"        {"7"}
            "VSE"           {"8"}
            "MCP"           {"9"}
            "ZOS"           {"12"}
            "SAP R3"        {"13"}
            "SAP BW"        {"14"}
            "JEE"           {"16"}
            "JAVA"          {"17"}
            "TUXEDOART"     {"18"}
            "EASE"          {"19"}
            "ASYSCO AMT"    {"20"}
            "SQL"           {"21"}
            default         {"3"}
        }

        $body = @{
            "name"=$agentname;
            "type"=@{
                "id"=$agenttypeid;
                "description"=$agentdescription
            };
            "socket"=$agentsocket;
            "jorsPortNumber"=$agentjors
        }

        try
        {
            $machine = Invoke-RestMethod -Method POST -Uri ($url + "/api/machines") -Headers @{"authorization" = $token} -Body ($body | ConvertTo-Json -Depth 5) -ContentType "application/json"
            Write-Host "Machine added!`r`n"
        }
        catch [Exception]
        {
            Write-Host $_.Exception
            write-host $_.Exception.Message
        }
    }
    else
    { Write-Host "Agent with the same name already exists!`r`n" }

    return $machine
}
New-Alias "opc-createagent" OpCon_CreateAgent

#Updates a particular field on an existing agent
function OpCon_UpdateAgent($agentname,$token,$url,$field,$value)
{
    $agent = OpCon_GetAgent -agentname $agentname -url $url -token $token
    If($agent.PSobject.Properties.name -match $field)
    { 
        $agent.$field = $value 

        #Take the machine down
        $down = OpCon_ChangeAgentStatus -agentname $agentname -action "down" -url $url -token $token

        try
        {
            $update = Invoke-Restmethod -Method PUT -Uri ($url + "/api/machines/" + $agent.id) -Headers @{"authorization" = $token} -Body ($agent | ConvertTo-Json -Depth 4) -ContentType "application/json"
        }
        catch [Exception]
        {
            Write-Host $_.Exception
            write-host $_.Exception.Message
        }
        Write-Host $agentname "updated!`r`n"

        Sleep 3

        #Bring the updated machine back up
        $up = OpCon_ChangeAgentStatus -agentname $agentname -action "up" -url $url -token $token
        return $up[0]
    }
    else
    { Write-Host "invalid Machine property specified!" }
}
New-Alias "opc-updateagent" OpCon_UpdateAgent

#Get schedule information
function OpCon_GetSchedule($url,$token,$sname,$date)
{
    if(!$date)
    {
        if(!$sname)
        {
            $uriget = $url + "/api/dailyschedules?dates"
        }
        Else
        {
            $uriget = $url + "/api/dailyschedules?name=" + "$sname"
        }

        try
        {
            $getdates = Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json"
        }
        catch [Exception]
        {
            Write-Host $_
            Write-Host $_.Exception.Message
        }

        return $getdates
    }
    else
    {
        if($sname)
        {
            $uriget = $url + "/api/dailyschedules?name=" + "$sname" + "&dates=" + $date
        }
        Else
        {
            $uriget = $url + "/api/dailyschedules"
        }

        try
        {
            $getschedule = (Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json")
        }
        catch [Exception]
        {
            Write-Host $_
            Write-Host $_.Exception.Message
        }

        $count = 0
        $getschedule | ForEach-Object{ $count++}
        if($count -eq 0)
        {
            Write-Host "No schedules found!"
        }

        return $getschedule
    }
}
New-Alias "opc-getschedule" OpCon_GetSchedule


function OpCon_ScheduleAction($url,$token,$sname,$jname,$frequency,$reason,$action,$states,$date,$sid,$instanceProperties,[switch]$applyExceptions,[switch]$rebuildOnRestart)
{
    $action = switch ($action) 
    { 
        "JOB:ADD"             {"addjobs"}
        "SCHEDULE:RELEASE"    {"release"}
        "SCHEDULE:HOLD"       {"hold"} 
        "SCHEDULE:START"      {"start"} 
        "SCHEDULE:CANCEL"     {"close"}
        "JOB:HOLD"            {"holdjobs"}
        "JOB:CANCEL"          {"cancelJobs"}
        "JOB:SKIP"            {"skipJobs"}
        "JOB:KILL"            {"killJobs"}
        "JOB:START"           {"startJobs"}
        "JOB:RESTART"         {"restartJobs"}
        "JOB:FORCERESTART"    {"forceRestartJobs"}
        "JOB:RESTARTHLD"      {"restartJobsOnHold"}
        "JOB:RELEASE"         {"releaseJobs"}
        "JOB:GOOD"            {"markJobsFinishedOk"}
        "JOB:BAD"             {"markJobsFailed"}
        "JOB:FIXED"           {"markjobsfixed"}
        "JOB:UNDERREVIEW"     {"markjobsunderreview"}
    }  

    if(!$reason)
    { $reason = "Action performed by OpCon API at " + (Get-Date) }

    if($states)
    { 
        if($states -like "*;*")
        { $statesArray = $states.Split(";") }
        else 
        {
            $statesArray = @()
            $statesArray += $states    
        }
    }    

    if($date)
    { 
        if($date -like "*;*")
        { $dateArray = $date.Split(";") }
        else 
        {
            $dateArray = @()
            $dateArray += $date    
        }
    }
    else 
    { $dateArray = @((Get-Date -Format "yyyy-MM-dd")) } # Default to today

    if($sname)
    { 
        $sname = $sname.replace("[","?").replace("]","?").replace(" ","%20")

        if($sname -like "*;*")
        { $scheduleArray = $sname.Split(";") }
        else 
        {
            $scheduleArray = @()
            $scheduleArray += $sname    
        }
        
        for($x=0;$x -lt $scheduleArray.Count;$x++)
        {
            $counter = 0
            $idArray = @()
            for($y=0;$y -lt $dateArray.Count;$y++)
            {
                $schedule = OpCon_GetSchedule -url $url -token $token -sname $scheduleArray[$x] -date $dateArray[$y]
                $schedule | ForEach-Object{ $counter++ }

                If($counter -ne 1)
                { Write-Host "Too many results for schedule!`r`n" }
                Else
                { $idArray += $schedule[0].id }
                $counter = 0
            }
        }
    }
    elseif($sid)
    { 
        if($sid -like "*;*")
        { $idArray = $sid.Spit(";") }
        else 
        {
            $idArray = @()
            $idArray += $sid       
        }
    }
    else 
    { Write-Host "Schedule Name or Schedule Id not specified!" }   

    # Only necessary for job actions
    if($action -like "*jobs*")
    {
        # Only necessary if instance properties are specified
        if($instanceProperties)
        {
            $properties = @()

            if($instanceProperties -like "*;*")
            { $propertyArray = $instanceProperties.Split(";").Split("=") }
            else 
            { $propertyArray = $instanceProperties.Split("=") }

            for($z=0;$z -lt $propertyArray.Count;$z++)
            {
                $properties += [PSCustomObject]@{ "name" = $propertyArray[$z];"value" = $propertyArray[($z+1)] }
                
                if(($z+2) -le $propertyArray.Count)
                { $z++ }
            }
        } 

        if($jname -like "*;*")
        { $jobNames = $jname.Split(";") }
        else 
        {
            $jobNames = @()
            $jobNames += $jname
        }

        if($frequency -like "*;*")
        { $jobFrequencies = $frequency.Split(";") }
        else 
        {
            $jobFrequencies = @()
            $jobFrequencies += $frequency    
        }

        $jobObjects = @()
        for($x=0;$x -lt $jobNames.Count;$x++)
        { 
            $jobObjects += [PSCustomObject]@{ "id" = $jobNames[$x]
                                            ;"frequency" = $jobFrequencies[$x] }

            if($properties)
            { $jobObjects | Add-Member -MemberType NoteProperty -Name "instanceProperties" -Value $properties }
            
            if($applyExceptions)
            { $jobObjects | Add-Member -MemberType NoteProperty -Name "applyExceptions" -Value $true } 

            if($rebuildOnRestart -and ($action -like "*restart*"))
            { $jobObjects | Add-Member -MemberType NoteProperty -Name "rebuildOnRestartIfContainer" -Value $true }
        }   
    }

    $scheduleObjects = @()
    for($y=0;$y -lt $idArray.Count;$y++)
    {
        $schedule = [PSCustomObject]@{ "id"= $idArray[$y] }
            
        if($action -like "*jobs*")
        { $schedule | Add-Member -MemberType NoteProperty -Name "jobs" -Value $jobObjects }

        $scheduleObjects += $schedule
    }

    if($statesArray)
    { $body = [PSCustomObject]@{"scheduleActionItems" = $scheduleObjects;"action" = $action;"reason" = $reason;"states" = $statesArray } }
    else 
    { $body = [PSCustomObject]@{"scheduleActionItems" = $scheduleObjects;"action" = $action;"reason" = $reason } }

    try
    {
        $submit = Invoke-RestMethod -Method POST -Uri ($url + "/api/ScheduleActions") -Body ($body | ConvertTo-Json -Depth 10) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }
    
    # Get action statuses
    if(($submit.result -ne "success") -and ($submit.result -ne "failed"))
    {
        $timeout = 100
        While((($getAction.result -ne "success") -and ($getAction.result -ne "failed")) -and ($timeout -ne 0))
        {
            $getAction = OpCon_GetScheduleAction -url $url -token $token -id $submit.id
            Start-Sleep -Seconds 1
            $timeout--
        }
        Write-Host "Request took"(100-$timeOut)"seconds"
        Write-Host $action $getAction.result
    }
    else 
    { Write-Host $action $submit.result.result }
}
New-Alias "opc-scheduleaction" OpCon_ScheduleAction

#Gets information about a daily job
function OpCon_GetDailyJob($url,$token,$sname,$jname,$date,$id)
{   
    if($id)
    { $uriget = $url + "/api/dailyjobs/" + $id }
    else
    {
        if($date)
        { $uriget = $url + "/api/dailyjobs?scheduleName=" + $sname + "&dates=" + $date }
        else
        { $uriget = $url + "/api/dailyjobs?scheduleName=" + $sname }
    }

    try
    { $jobs = Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json" }
    catch [Exception]
    {
        Write-Host $_.Exception
        Write-Host $_.Exception.Message
    }

    if($jname)
    { $jobs = $jobs.Where({ $_.name -like "*$jname*" }) }

    return $jobs
}
New-Alias "opc-getdailyjob" OpCon_GetDailyJob

#Sends a job action to a job
function OpCon_JobAction($url,$token,$sname,$jname,$jobId,$date,$action,$reason)
{
    if($action)
    {
        if($action.IndexOf(":") -ge 0)
        {
            $action = switch ($action) 
                { 
                    "JOB:RELEASE"         {"release"}
                    "JOB:START"           {"start"} 
                    "JOB:GOOD"            {"markFinishedOk"}
                    "JOB:BAD"             {"markFailed"}
                    "JOB:HOLD"            {"hold"}
                    "JOB:CANCEL"          {"cancel"}
                    "JOB:SKIP"            {"skip"}
                    "JOB:KILL"            {"kill"}
                    "JOB:RESTARTFORCE"    {"forceRestart"}
                    "JOB:RESTART"         {"restart"}
                    "JOB:RESTARTHLD"      {"restartOnHold"}
                    "JOB:FIXED"           {"markjobsfixed"}
                    "JOB:UNDERREVIEW"     {"markjobsunderreview"}        
                }
        }

        if($jname -and $sname -or $jobId)
        {
            if(!$date)
            { $date = Get-Date -Format "yyyy/MM/dd" }

            $jobsArray = @()
            if(!$jobId)
            {
                $job = OpCon_GetDailyJob -url $url -token $token -sname $sname -jname $jname -date $date
    
                $counter = 0
                $job | ForEach-Object{ $counter++ }
                If($counter -ne 1)
                {
                    Write-Host "Too many results for job!`r`n"
                }
                else
                { $jobsArray += @{ id=$job[0].id; } }
            }
            else
            { $jobsArray += @{ id=$jobId } }
    
            $body = @{
                "action"=$action;
                "jobs"=$jobsArray;
                "reason"=$reason
            }
        
            try
            {
                $jobaction = (Invoke-RestMethod -Method POST -Uri ($url + "/api/jobactions") -Body ($body | ConvertTo-JSON) -Headers @{"authorization" = $token} -ContentType "application/json")
            }
            catch [Exception]
            {
                Write-Host $_
                Write-Host $_.Exception.Message
            }
        
            if($jobaction.result -eq "success")
            {
                return $jobaction
            }
            elseif($jobaction.result -eq "error")
            {
                Write-Host "Job action attempt had an error"
            }
            else
            {
                for($x = 0;$x -lt 20;$x++)
                {
                    $jobaction
                    $result = OpCon_GetJobAction -url $url -token $token -id $jobaction.id
                
                    if($result.result -eq "success")
                    { $x = 20 }
                    elseif($result.result -eq "error")
                    {
                        Write-Host "Job action attempt had an error"
                        $result
                    }
        
                    if($x -ne 20)
                    { Start-Sleep -s 3 }
                }
                return $result
            }
        }
        Else
        { Write-Host "Missing schedule or job name!" }
    }
    Else
    { Write-Host "No action specified!" }
}
New-Alias "opc-jobaction" OpCon_JobAction

#Get calendar
function OpCon_GetCalendar($url,$token,$name,$id)
{
    if($name -or $id)
    {
        if($name)
        { $uriget = $url + "/api/calendars?name=" + $name }
        
        if($id)
        { $uriget = $url + "/api/calendars/" + $id }

        try
        {
            $counter = 0
            $calendar = (Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json")
            $calendar | ForEach-Object{ $counter++ } 
            
            if($counter -eq 0)
            {
                Write-Host "No calendars found by supplied name/id!"
            }
        }
        catch [Exception]
        {
            Write-Host $_
            Write-Host $_.Exception.Message
        }

        return $calendar
    }
    else
    { Write-Host "No name or id specified!" }
}
New-Alias "opc-getcalendar" OpCon_GetCalendar

#Updates a calendar
function OpCon_UpdateCalendar($url,$token,$name,$id,$date)
{
    if($name -or $id)
    {
        $counter = 0
        
        if($name)
        { $calendar = OpCon_GetCalendar -url $url -token $token -name $name }
        if($id)
        { $calendar = OpCon_GetCalendar -url $url -token $token -id $id }

        $calendar | ForEach-Object{ $counter++ }

        if($counter -ne 1)
        { Write-Host "More than 1 or no calendars returned!" }
        else 
        {
            if($date)
            {
                if($calendar[0].dates)
                { 
                    if($date.IndexOf(";") -ge 0)
                    {
                        $date.Split(";") | ForEach-Object{ 
                            if($_ -notin $calendar[0].dates)
                            { 
                                if($null -eq $dateList)
                                { $dateList = $_ }
                                else 
                                { $dateList = $dateList + ";" + $_ }
                            }
                         }
                    }
                    else 
                    {
                        if($date -notin $calendar[0].dates)
                        { $dateList = $date }
                    }
                    
                    if($null -ne $dateList )
                    { 
                        $calendar[0].dates += $dateList 
                        $body = $calendar[0]

                        try
                        { $calendaradd = Invoke-RestMethod -Method PUT -Uri ($url + "/api/calendars/" + $calendar[0].id) -Body ($body | ConvertTo-JSON -Depth 7) -Headers @{"authorization" = $token} -ContentType "application/json" }
                        catch [Exception]
                        {
                            Write-Host $_
                            Write-Host $_.Exception.Message
                        }
                
                        return $calendaradd
                    }
                    else 
                    { Write-Host "Date/s $date already in calendar $name !" }
                }
                else 
                {
                    if(!$calendar[0].description)
                    { $description = "" }
                    else 
                    { $description = $calendar[0].description }
        
                    if(!$calendar[0].schedule)
                    {                     
                        $body = @{
                            "id" = $calendar[0].id;
                            "type" = $calendar[0].type;
                            "name" = $calendar[0].Name;
                            "dates" = @( $date );
                            "description" = $description
                        } 
                    }
                    else 
                    { 
                        $schedule = $calendar[0].schedule 
                        $body = @{
                            "id" = $calendar[0].id;
                            "type" = $calendar[0].type;
                            "schedule" = $schedule;
                            "name" = $calendar[0].Name;
                            "dates" = @( $date );
                            "description" = $description
                        }
                    }

                    try
                    { $calendaradd = Invoke-RestMethod -Method PUT -Uri ($url + "/api/calendars/" + $calendar[0].id) -Body ($body | ConvertTo-JSON -Depth 7) -Headers @{"authorization" = $token} -ContentType "application/json" }
                    catch [Exception]
                    {
                        Write-Host $_
                        Write-Host $_.Exception.Message
                    }
            
                    return $calendaradd
                }
            }
            else
            { Write-Host "No date specified!" }          
        }
    }
    else
    { Write-Host "No name or id specified!" }
}
New-Alias "opc-updatecalendar" OpCon_UpdateCalendar

#Creates a user calendar (api allows for holiday calendar based on a schedule too)
function OpCon_CreateCalendar($url,$token,$type,$name,$dates,$description)
{
    #Eventually could add in "holiday" calendars
    $type = 1

    $uripost = $url + "/api/calendars/"
    $body = [pscustomobject]@{ 
                                "type" = $type;
                                "name" = $name;
                                "dates" = $dates;
                                "description" = $description 
                             }

    try
    { $calendar = Invoke-RestMethod -Method POST -Uri $uripost -Body ($body | ConvertTo-Json -Depth 5) -Headers @{"authorization" = $token} -ContentType "application/json" }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $calendar
}
New-Alias "opc-createcalendar" OpCon_CreateCalendar

#Checks the status of the SAM service
function OpCon_SAMStatus($url,$token)
{
    try
    {
        $status = Invoke-Restmethod -Method GET -Uri ($url + "/api/ServiceStatus") -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_.Exception
        write-host $_.Exception.Message
    }
    
    return $status
}
New-Alias "opc-sam" OpCon_SAMStatus

#Checks the OpCon API Version
function OpCon_APIVersion($url)
{
    try
    {
        $version = Invoke-Restmethod -Method GET -Uri ($url + "/api/version") -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_.Exception
        write-host $_.Exception.Message
    }
    
    return $version
}
New-Alias "opc-apiversion" OpCon_APIVersion

#Function to remove an item from a Service Request choice dropdown
function OpCon_DeleteSSChoice($getdropdown,$url,$token,$buttonname,$removeitem,$id)
{
    if($id)
    { $get =  OpCon_GetSSButton -url $url -token $token -id $id }
    else 
    { $get = OpCon_GetSSButton -button $buttonname -url $url -token $token }
    if(@($get).Count -eq 1)
    { 
        $get = $get[0]

        #Get XML information for adding/deleting
        $details = [xml] $get.details

        $delete = ($details.request.variables.variable.choice.items.ChildNodes | Where-Object { $_.caption -like $removeitem }) | ForEach-Object { $_.ParentNode.RemoveChild($_) }

        #Shows list of entries
        $details.request.variables.variable.choice.items.ChildNodes

        #Set XML back
        $get.details = $details.InnerXml

        try
        {
            $update = Invoke-RestMethod -Method PUT -Uri ($url + "/api/ServiceRequests/" + $get.id) -Headers @{"authorization" = $token} -Body ($get | ConvertTo-Json -Depth 3) -ContentType "application/json"
        }
        catch [Exception]
        {
            Write-Host $_.Exception
            Write-Host $_.Exception.Message
        }

        return $update    
    }
    else
    { Write-Host "No button named $button!" }
}
New-Alias "opc-deletesschoice" OpCon_DeleteSSChoice

#Function to add entries to a Service Request choice selection
function OpCon_AddSSChoice($addname,$addvalue,$getdropdown,$url,$token,$buttonname,$id)
{
    if($id)
    { $get =  OpCon_GetSSButton -url $url -token $token -id $id }
    else 
    { $get = OpCon_GetSSButton -button $buttonname -url $url -token $token }

    if(@($get).Count -eq 1)
    {
        $get = $get[0]

        #Get XML information for adding/deleting
        $details = [xml] $get.details

        if(!($details.request.variables.variable.choice.items.ChildNodes | Where-Object{$_.caption -eq $addname}))
        {
            $xmlFrag = $details.CreateDocumentFragment()
            $xmlFrag.InnerXml="<item><caption>$addname</caption><value>$addvalue</value></item>"
            $add = ($details.request.variables.variable | Where-Object{$_.name -eq $getdropdown}) | ForEach-Object{$_.choice.items.AppendChild($xmlFrag)}     
            $sorted = ($details.request.variables.variable | Where-Object{$_.name -eq $getdropdown}).choice.items.item | Sort caption

            For($x = 0;$x -lt $sorted.length;$x++)
            {
                $delete = ($details.request.variables.variable.choice.items.ChildNodes | Where-Object { $_.caption -like $sorted[$x].caption }) | ForEach-Object { $_.ParentNode.RemoveChild($_) }
                $xmlFrag.InnerXml = "<item><caption>" + $sorted[$x].caption + "</caption><value>" + $sorted[$x].value + "</value></item>"
                $add = ($details.request.variables.variable | Where-Object{$_.name -eq $getdropdown}) | ForEach-Object{$_.choice.items.AppendChild($xmlFrag)} 
            }

            #Adds modified items back to original object
            $get.details = $details.InnerXml
            
            try
            {
                $update = Invoke-RestMethod -Method PUT -Uri ($url + "/api/ServiceRequests/" + $get.id) -Headers @{"authorization" = $token} -Body ($get | ConvertTo-Json -Depth 3) -ContentType "application/json"
            }
            catch [Exception]
            {
                Write-Host $_.Exception
                Write-Host $_.Exception.Message
            }

            return $update
        }
        else
        {
            Write-Host "Entry already exists!"
        }
    }
    else
    { Write-Host "No button named $button!" }
}
New-Alias "opc-addsschoice" OpCon_AddSSChoice

#Gets information about a Self Service button
function OpCon_GetSSButton($url,$token,$id,$button)
{
    if($id -or $button)
    {
        if($id)
        { $uriget = $url + "/api/ServiceRequests/" + $id }
        else 
        { $uriget = $url + "/api/ServiceRequests?name=" + $button }

        try
        {
            $getbutton = Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json"
            
            if($button)
            {
                $getbutton = Invoke-RestMethod -Method GET -Uri ($url + "/api/ServiceRequests/" + $getbutton.id) -Headers @{"authorization" = $token} -ContentType "application/json"
            }
        }
        catch [Exception]
        {
            Write-Host $_.Exception
            Write-Host $_.Exception.Message
        }
    
        return $getbutton
    }
    else
    { Write-Host "No button name or id specified!" }
}
#New-Alias "opgssb" OpCon_GetSSButton

#Gets a user from the OpCon database
function OpCon_GetUser($username,$url,$token)
{
    try
    {
        $user = Invoke-RestMethod -Method GET -Uri ($url + "/api/users?loginName=" + $username + "&includeDetails=true") -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_.Exception
		Write-Host $_.Exception.Message
    }

    return $user
}
New-Alias "opc-getuser" OpCon_GetUser

#Get a specific role
function OpCon_GetRole($url,$token,$id,$rolename)
{
    If($id)
    { $uriget = $url + "/api/roles/" + $id }
    ElseIf($rolename)
    { $uriget = $url + "/api/roles?name=" + $rolename }

    if($rolename -or $id)
    {
        try
        { $role = Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json" }
        catch [Exception]
        {
            Write-Host $_
            Write-Host $_.Exception.Message
        }
    }
    Else
    { Write-Host "No Id or Rolename specified" }

    return $role
}
New-Alias "opc-getrole" OpCon_GetRole

#Adds a specific role to a user in OpCon
function OpCon_AddUserRole($user,$rolename,$url,$token)
{
    $userinfo = OpCon_GetUser -username $user -url $url -token $token
    if($userinfo.Count -eq 0)
    {  Write-Host "User $user does not exist" }
    else 
    {
        $role = @(OpCon_GetRole -rolename $rolename -url $url -token $token)
        if($role.Count -eq 1)
        {
            $role = $role[0]
            if($userinfo[0].Roles -notcontains "$rolename") 
            { 
                $userinfo[0].Roles += ,@{id=$role.id;name=$rolename} 

                try
                { $user = Invoke-RestMethod -Method PUT -Uri ($url + "/api/users/" + $userinfo.id) -Headers @{"authorization" = $token} -Body ($userinfo[0] | ConvertTo-Json -Depth 4) -ContentType "application/json" }
                catch [Exception]
                { 
                    Write-Host $_
                    Write-Host $_.Exception.Message 
                }
            }
            else
            { Write-Host "Role $rolename already on user account, not adding" }
        }
        else
        { Write-Host "Role $rolename not found or multiple rolenames found!" }
    }

    return $user
}
New-Alias "opc-adduserrole" OpCon_AddUserRole

#Creates an OpCon user
function OpCon_CreateUser($url,$token,$username,$password,$roleid,$rolename,$email,$notes,$comment)
{
    $get = OpCon_Getuser -url $url -token $token -username $username
    if(@($get).Count -eq 1)
    { Write-host "User " $username " already exists" }
    else 
    {
        if(!$roleid -and $rolename)
        {
            $role = OpCon_GetRole -url $url -token $token -rolename $rolename
            if(@($role).Count -eq 1)
            { $roleid = $role[0].id }
        }

        #Create OpCon user account
        $post = '{"loginName":"' + $username + '","name":"' + $username + '","password":"' + $password + '","externalPassword":"' + $password + '","details":"' + $notes + '","moreDetails":"' + $comment + '","roles":[{"Id":' + $roleid + '}],"email":"' + $email + '"}'
        
        try
        { $create = Invoke-RestMethod -Method POST -Uri ($url + "/api/users") -Headers @{"authorization" = $token} -Body "$post" -ContentType "application/json" }
        catch [Exception]
        {
            Write-Host $_
            Write-Host $_.Exception.Message
        }
    }

    return $create
}
New-Alias "opc-createuser" OpCon_CreateUser
   
#Sets up a job to disable a created user
function OpCon_DisableDemoUser($url,$token,$username,$userid)
{   
    #Get "ADHOC" schedule information
    $scheduleinfo = OpCon_GetSchedule -url $url -token $token -sname "ADHOC" -date (Get-Date -Format "MM/dd/yyyy")

    #Make sure only 1 Adhoc schedule was returned
    If(@($scheduleinfo).Count -ne 1)
    { Write-Host "Too many results for schedule" }
    else 
    {
        #Submit JobAdd to disable user in the future
        $body = @{
            "scheduleActionItems"=@(
                @{
                    "id"=$scheduleinfo[0].id;
                    "jobs"=@(
                        @{
                            "id"="DISABLE OPCON USER";
                            "frequency"="OnRequest";
                            "instanceProperties"=@(
                                @{
                                    "name"="USERNAME";
                                    "value"=$username
                                };
                                @{
                                    "name"="id";
                                    "value"=$userid
                                }
                            )
                        }
                    )
                }
            );
            "action"="addjobs"
        }

        try
        {
            $addjob = Invoke-RestMethod -Method POST -Uri ($url + "/api/ScheduleActions") -Body ($body | ConvertTo-Json -Depth 7) -Headers @{"authorization" = $token} -ContentType "application/json"
        }
        catch [Exception]
        {
            Write-Host $_.Exception
            Write-Host $_.Exception.Message
        }

        return $addjob
    }
}

#Updates a field in an OpCon user
function OpCon_UpdateUser($url,$token,$username,$field,$value)
{
    if($username)
    {
        $getuser = OpCon_GetUser -username $username -url $url -token $token
        if($getuser.length -eq 0) # length of 0 indicates no user record exists
        { 
            Write-Host "User $username does not exist"
        }
        else 
        {
            $user = $getuser[0]
            $user.$field = $value

            try
            {
                $updateduser = Invoke-RestMethod -Method PUT -Uri ($url + "/api/users/" + $user.id) -Headers @{"authorization" = $token} -Body ($user | ConvertTo-Json) -ContentType "application/json"
            }
            catch [Exception]
            {
                Write-Host $_.Exception
                Write-Host $_.Exception.Message
            }

            return $updateduser
        }
    }
    else
    { Write-Host "No username provided!" }
}
New-Alias "opc-updateuser" OpCon_UpdateUser

#Get schedule information
function OpCon_GetDailyJobsCountByStatus($url,$token,$date = (Get-Date -format "yyyy-MM-dd"),$status)
{
    try
    {
        $count = Invoke-RestMethod -Method GET -Uri ($url + "/api/dailyjobs/count_by_status") -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_.Exception
        Write-Host $_.Exception.Message
    }

    return $count
}
New-Alias "opc-dailyjobscountbystatus" OpCon_GetDailyJobsCountByStatus

#Gets daily jobs by status and date (default todays date)
function OpCon_GetDailyJobsByStatus($url,$token,$date = (Get-Date -format "yyyy-MM-dd"),$status)
{
    try
    {
        $count = Invoke-RestMethod -Method GET -Uri ($url + "/api/dailyjobs?status=" + $status + "&dates=" + $date) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_.Exception
        Write-Host $_.Exception.Message
    }

    return $count
}
New-Alias "opc-dailyjobsbystatus" OpCon_GetDailyJobsByStatus

function OpCon_GetDailyJobsBySchedule
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$schedule
        ,[string] $date = (Get-Date -format "yyyy-MM-dd")
    )

    try
    {
        return Invoke-RestMethod -Method GET -Uri ($url + "/api/dailyjobs?scheduleName=" + $schedule) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_.Exception
        Write-output $_.Exception.Message
    }
}
New-Alias "opc-dailyjobsbyschedule" OpCon_GetDailyJobsBySchedule

#Gets a specific daily job based on the jobs id
function OpCon_GetSpecificDailyJob
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$jid
    )

    try
    {
        return Invoke-RestMethod -Method GET -Uri ($url + "/api/dailyjobs/" + $jid) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_.Exception
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-dailyjob" OpCon_GetSpecificDailyJob

#Attempts to get an output file from a job run
function OpCon_SubmitJobInstanceFileAction
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$sname
        ,[Parameter(Mandatory=$true)] [string]$jname
        ,[Parameter(Mandatory=$true)] [string]$path
        ,[Parameter(Mandatory=$true)] [string]$date
        ,[string] $jobnumber
    )

    if(!$jobnumber)
    {
        $jobnumber = (OpCon_GetDailyJob -url $url -token $token -sname $sname -jname $jname -date $date).jobNumber
    }

    $body = @{
        "action"="FILE";
        "jobInstanceActionItems"=@( 
            @{ 
                "id"=$jobnumber;
                "jorsRequestParameters"=$path
            } 
        )
    }

    try
    {
        return Invoke-RestMethod -Method POST -Uri ($url + "/api/jobinstanceactions") -Headers @{"authorization" = $token} -Body ($body | ConvertTo-Json -Depth 5 ) -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-jobinstancefileaction" OpCon_SubmitJobInstanceFileAction

#Attempts to get a list of output files from a job run
function OpCon_SubmitJobInstanceListAction
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$sname
        ,[Parameter(Mandatory=$true)] [string]$jname
        ,[Parameter(Mandatory=$true)] [string]$date
    )

    $jobnumber = (OpCon_GetDailyJob -url $url -token $token -sname $sname -jname $jname -date $date).jobNumber

    $body = @{
        "action"="LIST";
        "jobInstanceActionItems"=@( 
            @{ "id"=$jobnumber } 
        )
    }

    try
    {
        return Invoke-RestMethod -Method POST -Uri ($url + "/api/jobinstanceactions") -Headers @{"authorization" = $token} -Body ($body | ConvertTo-Json -Depth 5) -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-jobinstancelistaction" OpCon_SubmitJobInstanceListAction

#Gets information about a previously submitted job action
function OpCon_GetJobInstanceAction
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$id
    )

    try
    {
        return Invoke-RestMethod -Method GET -Uri ($url + "/api/jobinstanceactions/" + $id) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_.Exception
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-jobinstanceaction" OpCon_GetJobInstanceAction

#Standard function for returning job output, a custom function may be required if there are multiple output files
function OpCon_GetJobOutput($url,$token,$sname,$jname,$date)
{
    $list = OpCon_SubmitJobInstanceListAction -url $url -token $token -sname $sname -jname $jname -date $date
    $liststatus = OpCon_GetJobInstanceAction -url $url -token $token -id $list.id
    
    while((($liststatus.result -ne "success") -and ($liststatus.result -ne "failed")))
    { $liststatus = OpCon_GetJobInstanceAction -url $url -token $token -id $list.id }

    if($liststatus.result -eq "success")
    {
        $path = $liststatus.jobInstanceActionItems.files | ConvertTo-Json

        $output = OpCon_SubmitJobInstanceFileAction -url $url -token $token -jobnumber $liststatus.jobInstanceActionItems.id -path $path
        $outputstatus = OpCon_GetJobInstanceAction -url $url -token $token -id $output.id
        while((($outputstatus.result -ne "success") -and ($outputstatus.result -ne "failed")))
        {
            $outputstatus = OpCon_GetJobInstanceAction -url $url -token $token -id $output.id
        }
    
        if($outputstatus.result -eq "failed")
        {
            Write-Host "Problem loading data from jors file"
        }
    
        return $outputstatus
    }
    else
    {
        Write-Host "Problem getting job output file list"
    }
}
New-Alias "opc-joboutput" OpCon_GetJobOutput

#Gets a user from the OpCon database
function OpCon_GetUserByComment
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$comment
    )

    try
    {
        $user = Invoke-RestMethod -Method GET -Uri ($url + "/api/users?includeDetails=true") -Headers @{"authorization" = $token} -ContentType "application/json"

        return $user | Where-Object{ $_.moreDetails -like "*$comment*" }
    }
    catch [Exception]
    {
        Write-Output $_.Exception
		Write-Output $_.Exception.Message
    }

}
New-Alias "opc-userbycomment" OpCon_GetUserByComment

#Get vision tags
function OpCon_GetTags
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[string]$date = (Get-Date -format "yyyy-MM-dd")
    )

    try
    {
        $schedule = Invoke-RestMethod -Method GET -Uri ($url + "/api/vision/cards?dates=" + $date) -Headers @{"authorization" = $token} -ContentType "application/json"

        if($schedule.Count -eq 0)
        { Write-Output "No schedules found!" }
        else 
        { return $schedule }
    }
    catch [Exception]
    {
        Write-Output $_.Exeption
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-gettags" OpCon_GetTags

#Gets daily jobs by tag for a date
function OpCon_GetDailyJobsByTag
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[string] $date = (Get-Date -format "yyyy-MM-dd")
        ,[Parameter(Mandatory=$true)] [string]$tag
    )

    try
    {
        return Invoke-RestMethod -Method GET -Uri ($url + "/api/dailyjobs?tags=" + $tag + "&dates=" + $date) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_.Exception
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-dailyjobbytag" OpCon_GetDailyJobsByTag

#Get Agent count by status
function OpCon_GetAgentCountByStatus
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[string] $date = (Get-Date -format "yyyy-MM-dd")
    )

    try
    {
        return Invoke-RestMethod -Method GET -Uri ($url + "/api/machines/count_by_status") -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_.Exception
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-agentcountbystatus" GetAgentCountByStatus

#Get dependencies for a job
function OpCon_GetDependencyByJob
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[string]$jid
        ,[string]$sname
        ,[string]$jname
        ,[string]$date = (Get-Date -format "yyyy-MM-dd")
    )

    if(!$jid)
    {
        if(!$sname -or !$jname)
        {
            Write-Output "Error, if no job id supplied then schedule/job name required!"
            Exit 1
        }

        $jid = (OpCon_GetDailyJob -url $url -token $token -sname $sname -jname $jname -date $date).id
    }

    try
    {
        return Invoke-RestMethod -Method GET -Uri ($url + "/api/dailygraphedges/" + $jid) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_.Exception
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-getdependency" OpCon_GetDependencyByJob


#DEPRECATED (use OpCon_GetServiceRequestChoice) Function to get a Service Request choice dropdown
function OpCon_GetSSChoice($dropdown,$url,$token,$button)
{
    $get = OpCon_GetSSButton -button $button -url $url -token $token
    if(@($get).Count -eq 1)
    {
        $get = $get[0]

        #Get XML information for adding/deleting
        $details = [xml] $get.details

        return $details.request.variables.variable.choice.items.ChildNodes
    }
    else
    { Write-Host "No button named $button!" }
}
#New-Alias "opcssc" OpCon_GetSSChoice

#DEPRECATED (renamed as GetServiceRequestInput) Function to get a Service Request input field
function OpCon_GetSSInput($url,$token,$button)
{
    $get = OpCon_GetSSButton -button $button -url $url -token $token
    if(@($get).Count -eq 1)
    {
        $get = $get[0]

        #Get XML information for adding/deleting
        $details = [xml] $get.details

        return @($details.request.variables.variable)
    }
    else
    { Write-Host "No button named $button!" }
}

#Creates an OpCon Role
function OpCon_CreateRole($url,$token,$rolename,$inheritSchedule,$inheritMach,$inheritMachGroup,$permissions)
{ 
    #Check if role already exists
    if(OpCon_GetRole -url $url -token $token -rolename "$rolename")
    { Write-Host "Role already exists" }
    else
    {
        #Get role information
        $body = New-Object System.Object
        $body | Add-Member -type NoteProperty -name "name" -value "$rolename"
        if($inheritSchedule)
        {
            $body | Add-Member -type NoteProperty -name "inheritAllSchedulePrivileges" -value $inheritSchedule 
        }
        if($inheritMach)
        {
            $body | Add-Member -type NoteProperty -name "inheritAllMachinePrivileges" -value $inheritMach
        }
        if($inheritMachGroup)
        {
            $body | Add-Member -type NoteProperty -name "inheritAllMachineGroupPrivileges" -value $inheritMachGroup
        }
        if($permissions)
        {
            $body | Add-Member -type NoteProperty -name "permissions" -value $permissions
        }

        try
        {
            $role = Invoke-Restmethod -Method POST -Uri ($url + "/api/roles") -Headers @{"authorization" = $token} -Body ($body | ConvertTo-Json) -ContentType "application/json"
        }
        catch [Exception]
        {
            Write-Host $_
            write-host $_.Exception.Message
        }

        return $role
    }
}
New-Alias "opc-createrole" OpCon_CreateRole

#Creates a Service Request
function OpCon_CreateServiceRequest($url,$token,$name,$doc,$html,$details,$disable,$hide,$category,$categoryName,$roles,$object)
{
    try 
    {
        if($object)
        { $servicerequest = Invoke-Restmethod -Method POST -Uri ($url + "/api/ServiceRequests") -Headers @{"authorization" = $token} -Body ($object | ConvertTo-Json -Depth 5) -ContentType "application/json" }
        else 
        {
            if($categoryName)
            { $categoryObject = OpCon_GetServiceRequestCategory -url $url -token $token -category "$categoryName" }
            elseif($category)
            { $categoryObject = $category }

            #Build Service Request object
            $body = @{
                "name" = $name;
                "documentation" = $doc;
                "details" = $details;
                "disableRule" = $disable;
                "hideRule" = $hide;
                "serviceRequestCategory" = $categoryObject;
                "roles" = @($roles) # This is an array of role objects @{id,name} I have a function for getting roles if needed
            }
            
            $servicerequest = Invoke-Restmethod -Method POST -Uri ($url + "/api/ServiceRequests") -Headers @{"authorization" = $token} -Body ($body | ConvertTo-Json -Depth 5) -ContentType "application/json" 
        }
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }

    return $servicerequest
}
New-Alias "opc-createssbutton" OpCon_CreateServiceRequest

#Deletes a Service Request
function OpCon_DeleteServiceRequest($url,$token,$name)
{  
    $button = OpCon_GetSSButton -url $url -token $token -button "$name"
    
    #Check if button exists
    if($button)
    {
        try
        {
            $servicerequest = Invoke-Restmethod -Method DELETE -Uri ($url + "/api/ServiceRequests/" + $button.id) -Headers @{"authorization" = $token} -Body "{}" -ContentType "application/json"
        }
        catch [Exception]
        {
            write-host $_
            write-host $_.Exception.Message
        }

        return $servicerequest        
    }
    else
    { Write-Host "Service Request does not exist" }
}
New-Alias "opc-deletebutton" OpCon_DeleteServiceRequest

#Adds a role to a SS button
function OpCon_AddSSButtonRole($url,$token,$button,$rolename)
{    
    $rolecheck = "true"
    $getbutton = OpCon_GetSSButton -url $url -token $token -button $button
    $getbutton.roles | ForEach-Object{ If($_.name -eq $rolename)
                                       { $rolecheck = "false" }
                                     }
    If($rolecheck -eq "true")
    {
        $getrole = OpCon_GetRole -url $url -token $token -rolename $rolename
        $getbutton.roles += $getrole

        try
        {
            $update = Invoke-RestMethod -Method PUT -Uri ($url + "/api/ServiceRequests/" + $getbutton.id) -Body ($getbutton | ConvertTo-JSON) -Headers @{"authorization" = $token} -ContentType "application/json"
        }
        catch [Exception]
        {
            Write-Host $_
            Write-Host $_.Exception.Message
        }

        return $update
    }
    Else
    { Write-Host "Button already has role $rolename !" }
}
New-Alias "opc-addssbuttonrole" OpCon_AddSSButtonRole

#Updates a particular field on a SS button
function OpCon_UpdateSSButton($url,$token,$button,$field,$value)
{  
    $getbutton = OpCon_GetSSButton -url $url -token $token -button $button
    $getbutton.$field = $value

    try
    {
        $update = Invoke-RestMethod -Method PUT -Uri ($url + "/api/ServiceRequests/" + $getbutton.id) -Body ($getbutton | ConvertTo-Json -Depth 7) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $update
}
New-Alias "opc-updatessbutton" OpCon_UpdateSSButton

#Function to get a Service Request category/categories
function OpCon_GetServiceRequestCategory($url,$token,$category,$id)
{ 
    if($category)
    { $uriget = $url + "/api/ServiceRequestCategories?name=" + $category }
    elseif($id)
	{ $uriget = $url + "/api/ServiceRequestCategories/" + $id }
    else 
    { $uriget = $url + "/api/ServiceRequestCategories" }

    try
    {
        $categories = Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json"

		if($category)
		{ $categories = Invoke-RestMethod -Method GET -Uri ($url + "/api/ServiceRequestCategories/" + $categories.id) -Headers @{"authorization" = $token} -ContentType "application/json" }
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $categories
}
New-Alias "opc-getsscategory" OpCon_GetServiceRequestCategory

#Removes a specific role from a user in OpCon
function OpCon_RemoveUserRole($user,$rolename,$url,$token)
{
    $userinfo = OpCon_GetUser -username $user -url $url -token $token
    $role = @(OpCon_GetRole -rolename $rolename -url $url -token $token)
    if($role.Count -eq 1)
    {
        $role = $role[0]

        if($userinfo[0].Roles.name -contains "$rolename") 
        { 
            $userinfo[0].Roles = @($userinfo[0].Roles | Where-Object { $_.name -ne "$rolename" })
            $body = $userinfo[0] | ConvertTo-Json -Depth 4
    
            try
            {
                $result = Invoke-RestMethod -Method PUT -Uri ($url + "/api/users/" + $userinfo.id) -Headers @{"authorization" = $token} -Body $body -ContentType "application/json"
            }
            catch [Exception]
            {
                Write-Host $_
                Write-Host $_.Exception.Message
            }
        }
        else
        { Write-Host "Role $rolename is not on user account, not removing" }
    
        return $result
    }
    else
    { Write-Host "Role $rolename not found or multiple rolenames found!" }
}
New-Alias "opc-removerole" OpCon_RemoveUserRole

#Handles schedule builds
function OpCon_ScheduleBuild($url,$token,$schedules,$dates,$logfile,$overwrite,$properties,$hold,$namedInstance,$machineName)
{
    #Checks that a schedule name was provided
    if($schedules)
    {
        $scheduleArray = @()
        if($schedules -like "*;*")
        { $schedules.Split(";") | ForEach-Object{ $scheduleArray += [PSCustomObject]@{ "name" = $_ } } }
        else
        { $scheduleArray += [PSCustomObject]@{"name" = $schedules } }

        #Use todays date if none provided
        if($dates)
        {
            $dateArray = @()
            if($dates -like "*;*")
            { $dates.Split(";") | ForEach-Object{ $dateArray += $_ } }
            else
            { $dateArray += $dates }
        }
        else
        { $dateArray = @(Get-Date -Format "yyyy/MM/dd") }

        #Check to see if properties were provided
        if($properties)
        {
            $propertyArray = @()
            if($properties -like "*;*")
            {
                $properties.Split(";") | ForEach-Object{ 
                        $splitter = $_.Split(",") 
                        $propertyArray += @{ key=$splitter[0];value=$splitter[1] } 
                }
            }
            else
            {
                $splitter = $properties.Split(",")
                $propertyArray += @{ key=$splitter[0];value=$splitter[1] }
            }
        }

        if(!$overwrite)
        { $overwrite = $false }

        $body = New-Object System.Object
        $body | Add-Member -type NoteProperty -name "schedules" -value $scheduleArray
        $body | Add-Member -type NoteProperty -name "dates" -value $dateArray
        $body | Add-Member -type NoteProperty -name "properties" -value $propertyArray
        $body | Add-Member -type NoteProperty -name "logFile" -value $logfile
        $body | Add-Member -type NoteProperty -name "overwrite" -value $overwrite
        $body | Add-Member -type NoteProperty -name "hold" -value $hold
        $body | Add-Member -type NoteProperty -name "namedInstance" -value $namedInstance
        $body | Add-Member -type NoteProperty -name "machineName" -value $machineName 

        try
        {
            $build = (Invoke-RestMethod -Method POST -Uri ($url + "/api/schedulebuilds") -Body ($body | ConvertTo-JSON -Depth 7) -Headers @{"authorization" = $token} -ContentType "application/json")
        }
        catch [Exception]
        {
            Write-Host $_
            Write-Host $_.Exception.Message
        }

        $wait = 15
        for($x=1;$x -lt $wait;$x++)
        {
            $status = OpCon_ScheduleBuildStatus -url $url -token $token -id $build.id
            If($status.message -eq "Completed")
            { $x = $wait }
            Else
            { Start-Sleep -Seconds 1 }
        }

        If($status.error)
        { Write-host $status.message }
        else
        { return $status }
    }
    else
    { Write-Host "No schedule name/s provided!" }
}
New-Alias "opc-schbuild" OpCon_ScheduleBuild
New-Alias "opc-schedulebuild" OpCon_SCheduleBuild

#Checks the status of a Schedule Build
function OpCon_ScheduleBuildStatus
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[string] $id
    )

    try
    {
        return Invoke-RestMethod -Method GET -Uri ($url + "/api/schedulebuilds/" + $id) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-schbuildstatus" OpCon_ScheduleBuildStatus
New-Alias "opc-schedulebuildstatus" OpCon_ScheduleBuildStatus

#Gets a count of schedules by status
function OpCon_ScheduleCountByStatus($url,$token,$dates,$name,$failedJobs,$categories)
{  
    $uriget = $url + "/api/dailyschedules/count_by_status"

    #Get property information
    If($dates)
    {
        If($uriget.IndexOf("?") -ge 0)
        { $uriget = $uriget + "&dates=" + $dates }
        Else
        { $uriget = $uriget + "?dates=" + $dates }
    }

    If($name)
    {
        If($uriget.IndexOf("?") -ge 0)
        { $uriget = $uriget + "&name=" + $name }
        Else
        { $uriget = $uriget + "?name=" + $name }
    }

    If($failedJobs)
    {
        If($uriget.IndexOf("?") -ge 0)
        { $uriget = $uriget + "&failedJobs=" + $failedJobs }
        Else
        { $uriget = $uriget + "?failedJobs=" + $failedJobs }
    }

    If($categories)
    {
        If($uriget.IndexOf("?") -ge 0)
        { $uriget = $uriget + "&categories=" + $categories }
        Else
        { $uriget = $uriget + "?categories=" + $categories }
    }

    try
    {
        $countByStatus = (Invoke-Restmethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }
    
    return $countByStatus
}
New-Alias "opc-schcountbystatus" OpCon_ScheduleCountByStatus
New-Alias "opc-schedulecountbystatus" OpCon_ScheduleCountByStatus

#Gets schedule properties
function OpCon_GetScheduleProperty($url,$token,$id,$name,$schedule,$date = (Get-Date -Format "yyyy/MM/dd"))
{ 
    If($id -or $schedule)
    {
        $uriget = $url + "/api/dailyschedules/"

        if($id)
        { $uriget = $uriget + $id + "/properties" }
        else
        {  
            $getsid = OpCon_GetSchedule -url $url -token $token -date $date -sname $schedule
            $uriget = $uriget + $getsid.id + "/properties"
        }

        If($name)
        { $uriget = $uriget + "/" + $name }

        try
        {
            $properties = Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json"
        }
        catch [Exception]
        {
            Write-Host $_
            Write-Host $_.Exception.Message
        }
    
        return $properties
    }
    Else
    { Write-Host "Not enough schedule information!" }
}
New-Alias "opc-getschprop" OpCon_GetScheduleProperty
New-Alias "opc-getscheduleprop" OpCon_GetScheduleProperty
New-Alias "opc-getscheduleproperty" OpCon_GetScheduleProperty

#Gets access codes
function OpCon_GetAccessCode
{  
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[string] $id
        ,[string] $name
    )

    #Get property information
    If($id)
    { $uriget = $url + "/api/AccessCodes/" + $id }
    ElseIf($name)
    { $uriget = $url + "/api/AccessCodes?name=" + $name }
    Else
    { $uriget = $url + "/api/AccessCodes" }

    try
    {
        return Invoke-Restmethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        write-output $_
        write-output $_.Exception.Message
    }
}
New-Alias "opc-getaccesscode" OpCon_GetAccessCode

#Creates a new access code
function OpCon_CreateAccessCode
{    
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$name
    )

    #Setup body
    $body = @{ "name" = $name }

    try
    {
        return Invoke-Restmethod -Method POST -Uri ($url + "/api/AccessCodes") -Headers @{"authorization" = $token} -Body ($body | ConvertTo-Json) -ContentType "application/json"
    }
    catch [Exception]
    {
        write-output $_
        write-output $_.Exception.Message
    }
}
New-Alias "opc-createaccesscode" OpCon_CreateAccessCode

#Sets a new name for an access code
function OpCon_SetAccessCode($url,$token,$id,$oldName,$name)
{
    If($oldname -or $id)
    {
        $accessCode = OpCon_GetAccessCode -url $url -token $token -name $oldname -id $id

        $counter = 0
        $accessCode | ForEach-Object{ $counter++ }

        if($counter -ne 1)
        { Write-Host "Too many or no access codes found!" }
        else 
        {
            #Set new name
            If($name)
            {
                $accessCode[0].name = $name

                #Update access code
                try
                {
                    $update = Invoke-Restmethod -Method PUT -Uri ($url + "/api/AccessCodes/" + $accessCode[0].id) -Headers @{"authorization" = $token} -Body ($accessCode[0] | ConvertTo-Json) -ContentType "application/json"
                }
                catch [Exception]
                {
                    write-host $_
                    write-host $_.Exception.Message
                }

                return $update 
            }
            Else
            { Write-Host "Name not specified!" }           
        }
    }
    Else
    { Write-Host "Id or Name not specified!" }
}
New-Alias "opc-updateaccesscode" OpCon_SetAccessCode

#Gets a batch user or list of users
function OpCon_GetBatchUser($url,$token,$id,$ids,$loginName,$roleName,$includeRoles)
{  
    #Get batchusers
    If($ids -or $loginName -or $roleName -or $includeRoles)
    {
        $uriget = $url + "/api/batchusers?"

        If($ids)
        { $uriget = $uriget + "ids=" + $ids }
        ElseIf($loginName)
        { $uriget = $uriget + "loginName=" + $loginName }
        ElseIf($roleName)
        { $uriget = $uriget + "roleName=" + $roleName }
        ElseIf($includeRoles)
        { $uriget = $uriget + "includeRoles=" + $includeRoles }
    }
    ElseIf($id)
    { $uriget = $url + "/api/batchusers/" + $id }
    Else
    { $uriget = $url + "/api/batchusers" }

    try
    {
        $batchUsers = Invoke-Restmethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }
    
    return $batchUsers
}
New-Alias "opc-getbatchuser" OpCon_GetBatchUser

#Creates a new batch user
function OpCon_CreateBatchUser($url,$token,$platformName,$loginName,$password,$roleNames)
{
    #Assign Agent type # based off OS name
    If($platformName)
    {
        $platformArray = @("NA","FILE TRANSFER","HP NONSTOP","WINDOWS","OPENVMW","IBMI","UNIX","OS2200","VSE","MCP","NA","NA","ZOS","SAP R3","SAP BW","NA","JEE","JAVA","TUXEDOART","EASE","ASYSCO AMT","SQL")
        for($x=0;$x -lt $platformArray.Count;$x++)
        {
            If($platformArray[$x] -eq $platformName)
            { $platformId = $x }
        }
    
        if((!$platformId) -or ($platformId -eq "NA"))
        { Write-Host "Invalid platform" }

        $platformObject = @{ id=$platformId;name=$platformName }
    }
    Else
    {
        Write-Host "No platform name specified!"
    }
    
    #Get role id
    If($roleNames)
    {
        $roleIdArray = @()
        $roleNameArray = $roleNames.Split(",")
        for($x=0;$x -lt $roleNameArray.Count;$x++)
        {
            $roleObject= OpCon_GetRole -url $url -token $token -rolename $roleNameArray[$x]
            if($roleObject)
            {
                $roleIdArray += @{ id=$roleObject.id;name=$roleObject.name }
            }
            else
            { Write-Host "Role" $roleNameArray[$x] "not found!" }
        }
    }

    #Verify login name
    If(!$loginName)
    { Write-Host "No login name specified" }
    ElseIf(!$password)
    { Write-Host "Password not specified!" }
    else 
    {
         #Builds Batch User object
        $body = New-Object System.Object
        $body | Add-Member -type NoteProperty -name "loginName" -value $loginName
        $body | Add-Member -type NoteProperty -name "roles" -value $roleIdArray
        $body | Add-Member -type NoteProperty -name "password" -value $password 
        $body | Add-Member -type NoteProperty -name "platform" -value $platformObject

        try
        {
            $batchUser = Invoke-Restmethod -Method POST -Uri ($url + "/api/batchusers") -Headers @{"authorization" = $token} -Body ($body | ConvertTo-Json -Depth 7) -ContentType "application/json"
        }
        catch [Exception]
        {
            write-host $_
            write-host $_.Exception.Message
        }

        return $batchUser   
    }
}
New-Alias "opc-newbatchuser" OpCon_CreateBatchUser

#Allows for updating a batch use with new roles
function OpCon_SetBatchUser($url,$token,$loginName,$roleNames)
{
    If($loginName)
    {
        $user = OpCon_GetBatchUser -url $url -token $token -loginName $loginName

        $counter = 0
        $user | ForEach-Object{ $counter++ }

        if($counter -ne 1)
        { Write-Host "Too many or no properties found!" }
    }
    Else
    { Write-Host "loginName not specified!" }

    $hdr = @{"authorization" = $token}

    #Set Values
    If($roleNames)
    {
        $roleIdArray = @()
        $roleNameArray = $roleNames.Split(",")
        for($x=0;$x -lt $roleNameArray.Count;$x++)
        {
            $roleObject= OpCon_GetRole -url $url -token $token -rolename $roleNameArray[$x]
            if($roleObject)
            {
                $roleIdArray += @{ id=$roleObject.id;name=$roleObject.name }
            }
            else
            { Write-Host "Role" $roleNameArray[$x] "not found!" }
        }
        $user[0] | Add-Member -type NoteProperty -name "roles" -value @($roleObject)
        #$user[0].roles = $roleObject
    }
    Else
    {
        $user[0] | Add-Member -type NoteProperty -name "roles" -value @()
    }
    
    #Update property value
    $uriput = $url + "/api/batchusers/" + $user[0].id
    try
    {
        $update = (Invoke-Restmethod -Method PUT -Uri $uriput -Headers $hdr -Body ($user[0] | ConvertTo-Json) -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }

    return $update
}
New-Alias "opc-updatebatchuser" OpCon_SetBatchUser

#Starts or stops an OpCon agent based on parameters *New version of ChangeAgentStatus*
function OpCon_MachineAction($url,$token,$agentName,$action)
{
    $machine = OpCon_GetAgent -agentname $agentName -url $url -token $token

    $count = 0
    $machine | ForEach-Object{ $count++ }

    if($count -eq 0)
    { Write-Host "No agent by that name!" }
    else
    { $machine = $machine[0] }

    #Enable/Disable the machine
    $machinesArray = @()
    $machinesArray += @{ id=$machine.id }

    $body = @{
        "machines" = $machinesArray;
        "action" = $action
    }

    try
    {
        $machineaction = (Invoke-Restmethod -Method POST -Uri ($url + "/api/machineactions") -Headers @{"authorization" = $token} -Body ($body | ConvertTo-Json) -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        write-host $_.Exception.Message
    }

    if($machineaction.result -eq "success")
    { return $machineaction }
    elseif($machineaction.result -eq "error")
    { Write-Host "Machine action attempt had an error" }
    else
    {
        for($x = 0;$x -lt 20;$x++)
        {
            $result = OpCon_GetMachineAction -url $url -token $token -id $machineaction.id
        
            if($result.result -eq "success")
            { $x = 20 }
            elseif($result.result -eq "error")
            {
                Write-Host "Machine action attempt had an error"
                $result
            }

            if($x -ne 20)
            { Start-Sleep -s 3 }
        }
        return $result
    }
}
New-Alias "opc-machaction" OpCon_MachineAction
New-Alias "opc-machineaction" OpCon_MachineAction

#Gets information about an OpCon Agent
function OpCon_GetMachineAction
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$id
    )

    #Validates id is passed
    try
    {
        return Invoke-Restmethod -Method GET -Uri ($url + "/api/machineactions/" + $id) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-getmachaction" OpCon_GetMachineAction
New-Alias "opc-getmachineaction" OpCon_GetMachineAction

#Gets information about a submitted Job Action
function OpCon_GetJobAction
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$id
    )

    #Validates id is passed
    try
    {
        return Invoke-Restmethod -Method GET -Uri ($url + "/api/jobactions/" + $id) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }
}
New-Alias "opc-getjobaction" OpCon_GetJobAction

#Function to get a Service Request choice dropdown
function OpCon_GetServiceRequestChoice($url,$token,$button,$dropdown)
{
    $details = OpCon_GetServiceRequestInput -url $url -token $token -button $button
    
    if($dropdown)
    {
        $result = $details | Where-Object{ $_.type -eq "CHOICE" -and $_.name -eq "$dropdown" }
        if($result)
        {
            return $result.choice.items.ChildNodes
        }
        else
        { Write-Host "No dropdowns called $dropdown" }
    }
    else
    { Write-Host "No dropdown specified!" }
}
New-Alias "opc-getsschoice" OpCon_GetServiceRequestChoice

#Function to get all Service Request choice dropdowns
function OpCon_GetAllServiceRequestChoice($url,$token,$button)
{
    $details = OpCon_GetServiceRequestInput -url $url -token $token -button $button
    
    $result = $details | Where-Object{ $_.type -eq "CHOICE" }
    if($result)
    { 
        $choices = @()
        $result | ForEach-Object{ 
                                    $choiceName = $_.name
                                    ($result | Where-Object{$_.name -eq $choiceName}).choice.items.ChildNodes | ForEach-Object{ 
                                                                                                                                $choices += [pscustomobject]@{"id"=$choices.Count;"name"=$choiceName;"caption"=$_.caption;"value"=$_.value}
                                    } 
        }
        
        #return $result.choice.items.ChildNodes 
        return $choices
    }
    else
    { Write-Host "No dropdowns found for $button"   }
}
New-Alias "opc-getallsschoice" OpCon_GetAllServiceRequestChoice

#Function to get a Service Request input field
function OpCon_GetServiceRequestInput($url,$token,$button,$input)
{
    $get = OpCon_GetSSButton -button $button -url $url -token $token
    if(@($get).Count -eq 1)
    {
        $get = $get[0]
    }
    else
    {
        Write-Host "No button named $button!"
    }

    #Get XML information for adding/deleting
    $details = [xml] $get.details

    return @($details.request.variables.variable)
}
New-Alias "opc-getssinput" OpCon_GetServiceRequestInput

#Gets information about all Self Service button
function OpCon_GetAllSSButtons($url,$token)
{
    try
    {
        $getbutton = Invoke-RestMethod -Method GET -Uri ($url + "/api/ServiceRequests") -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
		Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $getbutton
}

#Gets information about a Self Service button
function OpCon_GetServiceRequest($url,$token,$id,$button)
{
    if($id)
    { $uriget = $url + "/api/ServiceRequests/" + $id }
    elseif($button)
    { $uriget = $url + "/api/ServiceRequests?name=" + $button }
    else 
    { $uriget = $url + "/api/ServiceRequests" }

    try
    {
        $getbutton = Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json"

        if($button)
        { $getbutton = Invoke-RestMethod -Method GET -Uri ($url + "/api/ServiceRequests/" + $getbutton.id) -Headers @{"authorization" = $token} -ContentType "application/json" }
    }
    catch [Exception]
    {
		Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $getbutton
}
New-Alias "opc-getssbutton" OpCon_GetServiceRequest

#Function to get all Service Request categories
function OpCon_GetAllServiceRequestCategories($url,$token)
{
    try
    { $categories = Invoke-RestMethod -Method GET -Uri ($url + "/api/ServiceRequestCategories?name=") -Headers @{"authorization" = $token} -ContentType "application/json" }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $categories
}
New-Alias "opc-getallcategories" OpCon_GetAllServiceRequestCategories

#Updates a Self Service category
function OpCon_OverwriteServiceRequestCategory($url,$token,$category,$destCategory,$destCategoryId)
{
	if($destCategory)
	{
		$oldCategory = (OpCon_GetServiceRequestCategory -url $url -token $token -category $destCategory).id
	}
	elseif($destCategoryId)
	{
		$oldCategory = (OpCon_GetServiceRequestCategory -url $url -token $token -id $destCategoryId).id
	}
	else
	{
		$oldCategory = $category.id
	}

	$category.id = $oldCategory
    try
    {
        $update = Invoke-RestMethod -Method PUT -Uri ($url + "/api/ServiceRequestCategories/" + $oldCategory) -Body ($category | ConvertTo-Json -Depth 7) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
		If($_.Exception.Message -like "*Not Found*")
		{
			Write-Host "Category "$category.name" not found in destination, skipping"
		}
		Else
		{
			Write-Host $_
			Write-Host $_.Exception.Message
		}
    }

    return $update
}
New-Alias "opc-overwritesscategory" OpCon_OverwriteServiceRequestCategory

#Updates a particular field on a SS button
function OpCon_OverwriteServiceRequest($url,$token,$button,$destButton,$destButtonId)
{
	if($destButton)
	{ $oldButton = (OpCon_GetServiceRequest -url $url -token $token -button $destButton).id	}
	elseif($destButtonId)
	{ $oldButton = (OpCon_GetServiceRequest -url $url -token $token -id $destButtonId).id }
	else
	{ $oldButton = $button.id }

	$button.id = $oldButton
    try
    {
        $update = Invoke-RestMethod -Method PUT -Uri ($url + "/api/ServiceRequests/" + $oldButton) -Body ($button | ConvertTo-Json -Depth 7) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
		If($_.Exception.Message -like "*Not Found*")
		{
			Write-Host "Source button "$button.name" not found in destination, skipping"
		}
		Else
		{
			Write-Host $_
			Write-Host $_.Exception.Message
		}
    }

    return $update
}
New-Alias "opc-overwritessbutton" OpCon_OverwriteServiceRequest

#Gets information about all Self Service button
function OpCon_GetAllServiceRequests($url,$token)
{
    try
    {
        $getbutton = Invoke-RestMethod -Method GET -Uri ($url + "/api/ServiceRequests?name=") -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
		Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $getbutton
}
New-Alias "opc-getssbuttons" OpCon_GetAllServiceRequests

# Gets Daily Vision Workspaces
function OpCon_GetDailyVisionWorkspaces
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
    )

    try
    {
        return Invoke-Restmethod -Method GET -Uri ($url + "/api/dailyvisionworkspaces") -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-getdailyvision" OpCon_GetDailyVisionWorkspaces

# Gets Master Vision Workspaces
function OpCon_GetMasterVisionWorkspaces
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
    )

    try
    {
        return Invoke-Restmethod -Method GET -Uri ($url + "/api/mastervisionworkspaces") -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-getmastervision" OpCon_GetMasterVisionWorkspaces

# Updates Master Vision workspaces based on passed in object
function OpCon_UpdateMasterVisionWorkspaces
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$id
        ,[Parameter(Mandatory=$true)] [string]$workspaceObj
    )

    try
    {
        return Invoke-Restmethod -Method PUT -Uri ($url + "/api/mastervisionworkspaces/" + $id) -Body ($workspaceObj | ConvertTo-Json -Depth 15) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-updatemastervision" OpCon_UpdateMasterVisionWorkspaces

# Gets OpCon server options
function OpCon_GetServerOptions
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
    )

    try
    {
        return Invoke-Restmethod -Method GET -Uri ($url + "/api/serverOptions") -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-serveroptions" OpCon_GetServerOptions

# Updates Server Options
function OpCon_UpdateServerOptions
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$optionsObj
    )

    try
    {
        return Invoke-Restmethod -Method PUT -Uri ($url + "/api/serverOptions") -Body ($optionsObj | ConvertTo-Json -Depth 5) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-updateserveroptions" OpCon_UpdateServerOptions

#Gets information about a submitted Schedule Action
function OpCon_GetScheduleAction
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$id
    )

    try
    {
        return Invoke-RestMethod -Method GET -Uri ($url + "/api/ScheduleActions/" + $id) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}

#Function to add entries to a Service Request choice selection
function OpCon_AddSSChoiceMassImport($addname,$addvalue,$getdropdown,$url,$token,$buttonname)
{
    $get = OpCon_GetSSButton -button $buttonname -url $url -token $token
    if(@($get).Count -eq 1)
    {
        $get = $get[0]

        #Get XML information for adding/deleting
        $details = [xml] $get.details
        $xmlFrag = $details.CreateDocumentFragment()

        # Creates one big list of all the items for the dropdown
        For($x=0;$x -lt $addname.Count;$x++)
        { $newEntries = $newEntries + "<item><caption>" + $addname[$x] + "</caption><value>" + $addvalue[$x] + "</value></item>" }
            
        $xmlFrag.InnerXml = $newEntries
        $add = ($details.request.variables.variable | Where-Object{$_.name -eq $getdropdown}) | ForEach-Object{$_.choice.items.AppendChild($xmlFrag)}     
            
        #Adds modified items back to original object
        $get.details = $details.InnerXml
        
        $uriput = $url + "/api/ServiceRequests/" + $get.id
        $body = $get | ConvertTo-Json -Depth 3
            
        try
        {
            $update = Invoke-RestMethod -Method PUT -Uri $uriput -Headers @{"authorization" = $token} -Body $body -ContentType "application/json"
        }
        catch [Exception]
        {
            Write-Host $_
            Write-Host $_.Exception.Message
        }

        return $update
    }
    else
    { Write-Host "No button named $button!" }
}
New-Alias "opc-ssaddmasschoice" OpCon_AddSSChoiceMassImport

#Updates all the calendar dates
function OpCon_UpdateAllCalendarDates($url,$token,$name,$id,$dates)
{
    if($name -or $id)
    {
        $counter = 0
        
        if($name)
        { $calendar = OpCon_GetCalendar -url $url -token $token -name $name }
        if($id)
        { $calendar = OpCon_GetCalendar -url $url -token $token -id $id }

        $calendar | ForEach-Object{ $counter++ }

        if($counter -ne 1)
        {
            Write-Host "More than 1 or no calendars returned!"
        }
        else 
        {
            if($dates)
            {
                $dates = $dates | Select-Object -Unique
                $uriput = $url + "/api/calendars/" + $calendar[0].id
                $calendar[0].dates = $dates
        
                try
                {
                    $calendaradd = Invoke-RestMethod -Method PUT -Uri $uriput -Body ($calendar[0] | ConvertTo-JSON -Depth 7) -Headers @{"authorization" = $token} -ContentType "application/json"
                }
                catch [Exception]
                {
                    Write-Host $_
                    Write-Host $_.Exception.Message
                }
        
                return $calendaradd
            }
            else
            { Write-Host "No date/s specified!" }            
        }
    }
    else
    { Write-Host "No name or id specified!" }
}
New-Alias "opc-updateallcalendars" OpCon_ReadLogErrors

#Gets daily jobs
function OpCon_GetDailyJobs
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[string] $filter
    )

    if($filter)
    { $uriget =  $url + "/api/dailyjobs?" + $filter }
    else
    { $uriget = $url + "/api/dailyjobs" }

    try
    {
        return Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-getdailyjobs" OpCon_GetDailyJobs

# Gets scripts by name
function OpCon_GetScripts
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$scriptname
    )

    try
    {
        return Invoke-RestMethod -Method GET -Uri ($url + "/api/scripts?ScriptName=" + $scriptname.Replace(" ","%20")) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_.Exception
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-getscripts" OpCon_GetScripts

# Gets all the versions of a script
function OpCon_GetScriptVersions
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$id
    )

    try
    {
        return Invoke-RestMethod -Method GET -Uri ($url + "/api/scripts/" + $id) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_.Exception
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-getscriptversion" OpCon_GetScriptVersions

# Gets the details of a specific script version
function OpCon_GetScript
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$versionId
    )

    try
    {
        return Invoke-RestMethod -Method GET -Uri ($url + "/api/scriptVersions/" + $versionId) -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_.Exception
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-getscript" OpCon_GetScript

function OpCon_GetDailyJobFiltered
{   
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[string] $id
        ,[string] $filter
    )

    if($id)
    { $uriget = $url + "/api/dailyjobs/" + $id + $filter }
    elseif($filter)
    { $uriget = $url + "/api/dailyjobs?" + $filter }
    else
    { $uriget = $url + "/api/dailyjobs" }

    try
    { return Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json" }
    catch [Exception]
    {
        Write-Output $_.Exception
        Write-Output $_.Exception.Message
    }
}
New-Alias "opc-getdailyjobfiltered" OpCon_GetDailyJobFiltered

function OpCon_UpdateBatchUser
{  
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$field
        ,[Parameter(Mandatory=$true)] [string]$value
        ,[string] $id
    )

    $user = OpCon_GetBatchUser -url $url -token $token -id $id

    if($field -eq "password")
    { $user | Add-Member -type NoteProperty -name "password" -value $value }
    else 
    { $user.$field = $value }

    #Update batch user
    try
    {
        return Invoke-Restmethod -Method PUT -Uri ($url + "/api/batchusers/" + $id) -Headers @{"authorization" = $token} -Body ($user | ConvertTo-JSON -Depth 5) -ContentType "application/json"
    }
    catch [Exception]
    {
        write-output $_
        write-output $_.Exception.Message
    }
}

#Get a specific role
function OpCon_GetRoles
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
    )

    try
    {
        return Invoke-RestMethod -Method GET -Uri ($url + "/api/roles?name=") -Headers @{"authorization" = $token} -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Output $_
		Write-Output $_.Exception.Message
    }
}

function OpCon_PropertyExpression
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$expression
    )

    try
    { return Invoke-RestMethod -Method POST -Uri ($url + "/api/PropertyExpression") -Body (@{"Expression" = $expression} | ConvertTo-JSON) -Headers @{"authorization" = $token} -ContentType "application/json" }
    catch [Exception]
    {
        Write-Output $_
		Write-Output $_.Exception.Message
    }
}

function OpCon_Reports
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$limit
        ,[Parameter(Mandatory=$true)] [string]$status
    )

    try
    { return Invoke-RestMethod -Method GET -Uri ($url + "/api/dailyjobs?&status=$status&limit=$limit") -Headers @{"authorization" = $token} -ContentType "application/json" }
    catch [Exception]
    {
        Write-Output $_
		Write-Output $_.Exception.Message
    }
}

function OpCon_EventToAPI
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$opconUser
        ,[Parameter(Mandatory=$true)] [string]$opconEvent
    )

    try
    { 
        $body = @{
            "loginName"=$opconUser;
            "events"= @(
                @{
                    "id"=0;
                    "eventString"=$opconEvent
                }
            )
        }
        invoke-restmethod -uri ($url + "/api/opconEventsCollection") -Body ($body | ConvertTo-Json -Depth 5) -Headers @{"Authorization"=$token} -ContentType "application/json" -Method POST
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message
    }
}

function OpCon_RunScriptRepositoryScript
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$script
        ,[string]$version
    )

    try 
    {
        $versions = (Invoke-RestMethod -Method GET -Uri ($url + "/api/scripts?IncludeVersions=true&scriptname=" + $script) -Headers @{"authorization" = $token} -ContentType "application/json").versions
        
        if($versions)
        {
            # Set the "latest" to highest number of version
            if($version -eq "latest"){ $versions = ((($versions).version | Measure-Object -Maximum).Maximum) }
            
            # Run the script
            Invoke-Expression ((Invoke-RestMethod -uri ($url + "/api/scriptVersions/" + $versions.Where({ $_.version -eq $version }).id) -method GET -headers @{"authorization" = $token }).content)
        }
    }
    catch [Exception]
    {
        Write-Output $_
        Write-Output $_.Exception.Message   
    }
}


function OpCon_GetIncidents
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$job
        ,[Parameter(Mandatory=$true)] [string]$schedule
        ,[Parameter(Mandatory=$true)] [string]$date
    )

    try 
    {
        $jobID = (invoke-restmethod -Uri ($url + "/dailyjobs?JobName=" + $job + "&ScheduleName=" + $schedule + "&Dates=" + $date) -Headers @{"Authorization"=$token} -Method GET).uid

        return Invoke-RestMethod -Uri ($url + "/dailyjobs/" + $jobID + "/incidentTickets") -Method GET -Headers @{"authorization"=$token}
    }
    catch [Exception]
    {
        Write-Output $_.Exception
        Write-Output $_.Exception.Message
    }
}

function OpCon_ManageIncident
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$job
        ,[Parameter(Mandatory=$true)] [string]$schedule
        ,[Parameter(Mandatory=$true)] [string]$date
        ,[Parameter(Mandatory=$true)] [string]$ticketId
        ,[Parameter(Mandatory=$true)] [string]$ticketUrl
        ,[Parameter(Mandatory=$true)] [string]$option
        ,[string] $incidentId
    )

    try 
    {
        $jobID = (invoke-restmethod -Uri ($url + "/dailyjobs?JobName=" + $job + "&ScheduleName=" + $schedule + "&Dates=" + $date) -Headers @{"Authorization"=$token} -Method GET).uid

        if($option -eq "add")
        { 
            $body = @{
                "id"=0;
                "ticketId"=$ticketId;
                "ticketUrl"=$ticketUrl
            }

            return invoke-restmethod -Uri ($url + "/dailyjobs/" + $jobID + "/incidentTickets") -Body ($body | ConvertTo-Json) -Method POST -Headers @{"Authorization"=$token} -ContentType "application/json"
        }
        elseif($option -eq "update")
        {
            $body = @{
                "id"=$id;
                "ticketId"=$ticketId;
                "ticketUrl"=$ticketUrl
            }

            return invoke-restmethod -Uri ($url + "/dailyjobs/" + $jobID + "/incidentTickets/" + $id) -Body ($body | ConvertTo-Json) -Method PUT -Headers @{"Authorization"=$token} -ContentType "application/json"
        }
        elseif($option -eq "delete")
        {
            return invoke-restmethod -Uri ($url + "/dailyjobs/" + $jobID + "/incidentTickets/" + $id) -Method Delete -Headers @{"Authorization"=$token} -ContentType "application/json"
        }
    }
    catch [Exception]
    {
        Write-Output $_.Exception
        Write-Output $_.Exception.Message
    }
}

#Gets information about a Self Service button
function OpCon_GetServiceRequest
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[string]$button
        ,[int]$id
    )

    if($id -or $button)
    {
        if($id)
        { $uriget = $url + "/api/selfServiceRequests/" + $id.ToString() }
        elseif($button) 
        { $uriget = $url + "/api/selfServiceRequests?name=" + $button }

        try
        {
            return Invoke-RestMethod -Method GET -Uri $uriget -Headers @{"authorization" = $token} -ContentType "application/json"
        }
        catch [Exception]
        {
            Write-Host $_.Exception
            Write-Host $_.Exception.Message
        }
    }
    else
    { 
        Write-Host "No button name or id specified!" 
        Exit 1
    }
}

function OpCon_ManageServiceRequestChoice
{
    Param(
        [Parameter(Mandatory=$true)] [string]$url
        ,[Parameter(Mandatory=$true)] [string]$token
        ,[Parameter(Mandatory=$true)] [string]$button
        ,[Parameter(Mandatory=$true)] [string]$option
        ,[Parameter(Mandatory=$true)] [string]$dropdown
        ,[array] $items
    )

    $buttonDetails = OpCon_GetServiceRequest -url $url -token $token -button "$button"
    $newItems = New-object -TypeName System.Collections.ArrayList

    if($option -eq "add")
    {
        ($buttonDetails.request.variables.Where({ $_.type -eq "CHOICE" -and $_.name -eq "$dropdown" })).choice.items | ForEach-Object{ 
            $newItems.Add([pscustomobject]@{ "caption"=$_.caption;"value"=$_.value } ) | Out-Null 
        }
        $items | ForEach-Object{ $newItems.Add([pscustomobject]@{"caption"=$_.caption;"value"=$_.value} ) | Out-Null }
    }
    elseif($option -eq "update")
    {
        $items | ForEach-Object{ $newItems.Add([pscustomobject]@{"caption"=$_.caption;"value"=$_.value} ) | Out-Null }
    }
    elseIf($option -eq "remove")
    {
        ($buttonDetails.request.variables.Where({ $_.type -eq "CHOICE" -and $_.name -eq "$dropdown" })).choice.items | ForEach-Object{ 
            if($_.caption -notin $items.caption )
            { $newItems.Add([pscustomobject]@{ "caption"=$_.caption;"value"=$_.value } ) | Out-Null }
        }
    }
    else 
    {
        Write-Output "Invalid -option specified only add, remove, or update are valid"
        Exit 1    
    }

    ($buttonDetails.request.variables.Where({ $_.type -eq "CHOICE" -and $_.name -eq "$dropdown" })).choice.items = $newItems | Sort-Object -Property caption -Unique

    try
    {
        Invoke-RestMethod -uri ($url + "/api/selfServiceRequests/" + $buttonDetails.id) -method PUT -body ($buttonDetails | ConvertTo-Json -Depth 7) -headers @{"Authorization"=$token} -ContentType "application/json" 
    }
    catch [Exception]
    {
        Write-Output $_.Exception
        Write-Output $_.Exception.Message
    }
}