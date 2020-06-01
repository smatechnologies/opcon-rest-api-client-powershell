<#
#PowerShell Module file for OpCon API

Module notes:
-Updated Module Version to 19.0
-Various bug fixes
-Added functions for getting scripts/versions
#>

function OpCon_ModuleAPIVersion
{
    Write-Host "******************************`r`nWritten for OpCon Release 19.0`r`n******************************"
}

##################################################################################################
#Used if calling an API that is not local to the machine
function OpCon_IgnoreSelfSignedCerts
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
      }
    catch
    {
        Write-Host "Error Ignoring Self Signed Certs"
        Exit 102
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

#Get user/app token
function OpCon_Login($url,$user,$password,$appname)
{
    if($pscore)
    { 
        try
        {
            $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck",$true)
            $PSDefaultParameterValues.Add("Invoke-WebRequest:SkipCertificateCheck",$true)
        }
        catch
        { $null }
    }

    $uripost = $url + "/api/tokens"

    #Builds user hashtable
    if($appname)
    {
        $body = @{"user"=
                        @{"loginName"=$user;"password"=$password};
                        "tokenType"=
                                    @{"id"=$appname;"type"="Application"}
                    }
    }
    else 
    {
        $body = @{"user"=
                        @{"loginName"=$user;"password"=$password};
                        "tokenType"=
                                    @{"type"="User"}
                    }        
    }
                
    try
    {
        $apiuser = Invoke-Restmethod -Method POST -Uri $uripost -Body ($body | ConvertTo-Json) -ContentType "application/json"
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }

    return $apiuser
}

#Delete token from database
function OpCon_DeleteAPIToken($url,$token)
{
    $hdr = @{"authorization" = $token}

    $uridelete = $url + "/api/tokens"
    try
    {
        $apitokendelete = (Invoke-Restmethod -Method DELETE -Uri $uridelete -Header $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }

    return $apitokendelete
}

<#
.SYNOPSIS

Gets a global property value from OpCon.

.OUTPUTS

ID, Value, Encryption of global property.

.EXAMPLE

C:\PS> opgp -Name "My Property"
#>
function OpCon_GetGlobalProperty($url,$token,$id,$name)
{
    $hdr = @{"authorization" = $token}
    
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
        $globalproperty = Invoke-Restmethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }
    
    return $globalproperty
}
New-Alias "opgp" OpCon_GetGlobalProperty

#Creates a new global property
function OpCon_CreateGlobalProperty($name,$value,$encrypt,$url,$token)
{
    $hdr = @{"authorization" = $token}
    
    #Get property information
    $body = New-Object System.Object
    $body | Add-Member -type NoteProperty -name "name" -value $name
    $body | Add-Member -type NoteProperty -name "value" -value $value
    $body | Add-Member -type NoteProperty -name "encrypted" -value $encrypt 

    $uripost = $url + "/api/globalproperties"
    try
    {
        $globalproperty = (Invoke-Restmethod -Method POST -Uri $uripost -Headers $hdr -Body ($body | ConvertTo-Json) -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }

    return $globalproperty
}
New-Alias "opcp" OpCon_CreateGlobalProperty

#Sets a global property to a value
function OpCon_SetGlobalProperty($url,$token,$id,$name,$value)
{
    If($name -or $id)
    {
        $property = OpCon_GetGlobalProperty -url $url -token $token -name $name -id $id

        $counter = 0
        $property | ForEach-Object{ $counter++ }

        if($counter -ne 1)
        {
            Write-Host "Too many or no properties found!"
        }
    }
    Else
    {
        Write-Host "Id or Name not specified!"
    }

    $hdr = @{"authorization" = $token}
    
    #Set Value
    If($value)
    {
        $property[0].value = $value
    }
    Else
    {
        Write-Host "Value not specified!"
    }

    #Update property value
    $uriput = $url + "/api/globalproperties/" + $property[0].id
    try
    {
        $update = (Invoke-Restmethod -Method PUT -Uri $uriput -Headers $hdr -Body ($property[0] | ConvertTo-Json) -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }

    return $update
}
New-Alias "opsp" OpCon_SetGlobalProperty

#Get threshold
function OpCon_GetThreshold($url,$token,$name,$id)
{
    $hdr = @{"authorization" = $token}

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
        $threshold = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $threshold
}
New-Alias "opgt" OpCon_GetThreshold

#Create threshold
function OpCon_CreateThreshold($url,$token,$name,$value,$description)
{
    $hdr = @{"authorization" = $token}

    $body = New-Object System.Object
    $body | Add-Member -type NoteProperty -name "name" -value $name
    $body | Add-Member -type NoteProperty -name "value" -value $value 
    $body | Add-Member -type NoteProperty -name "description" -value $description

    $uripost = $url + "/api/thresholds"    
    try
    {
        $threshold = (Invoke-RestMethod -Method POST -Uri $uripost -Body ($body | ConvertTo-Json) -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $threshold
}
New-Alias "opct" OpCon_CreateThreshold

#Set threshold value
function OpCon_SetThreshold($url,$token,$id,$name,$value,$description)
{
    $hdr = @{"authorization" = $token}

    If($name)
    {
        $threshold = OpCon_GetThreshold -url $url -token $token -name $name
    }
    ElseIf($id)
    {
        $threshold = OpCon_GetThreshold -url $url -token $token -id $id
    }
    Else
    {
        Write-Host "No name or id specified!"
    }

    $counter = 0
    $threshold | ForEach-Object { $counter ++ }

    if($counter -ne 1)
    {
        Write-Host "0 or more than 1 threshold found matching name/id, cannot set value"
    }

    if($value.StartsWith("+"))
    {
        $value = $threshold[0].value + [convert]::ToInt32($value.SubString(1))
    }
    elseif($value.StartsWith("-"))
    {
      if($threshold[0].value -lt $value.SubString(1))
      {
        $value = 0
      }
      else
      {
        $value = $threshold[0].value - [convert]::ToInt32($value.SubString(1))        
      }
    }

    $body = New-Object System.Object
    $body | Add-Member -type NoteProperty -name "id" -value $threshold[0].id
    $body | Add-Member -type NoteProperty -name "name" -value $name
    $body | Add-Member -type NoteProperty -name "value" -value $value
    
    if($description)
    {
        $body | Add-Member -type NoteProperty -name "description" -value $description
    }

    $uriput = $url + "/api/thresholds/" + $threshold[0].id
    
    try
    {
        $result = (Invoke-RestMethod -Method PUT -Uri $uriput -Body ($body | ConvertTo-Json) -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $result
}
New-Alias "opst" OpCon_SetThreshold

#Get resource
function OpCon_GetResource($url,$token,$name,$id)
{
    $hdr = @{"authorization" = $token}

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
        $resource = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $resource
}
New-Alias "opgres" OpCon_GetResource

#Create resource
function OpCon_CreateResource($url,$token,$name,$value,$description)
{
    $hdr = @{"authorization" = $token}

    $resource = OpCon_GetResource -url $url -token $token -name $name
    $counter = 0
    $resource | ForEach-Object { $counter ++ }

    if($counter -eq 1)
    {
        Write-Host "Resource $name already exists"
    }

    $body = New-Object System.Object
    $body | Add-Member -type NoteProperty -name "name" -value $name
    $body | Add-Member -type NoteProperty -name "value" -value $value 
    $body | Add-Member -type NoteProperty -name "description" -value $description

    $uripost = $url + "/api/resources"
    
    try
    {
        $resource = (Invoke-RestMethod -Method POST -Uri $uripost -Body ($body | ConvertTo-Json) -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $resource
}
New-Alias "opcres" OpCon_CreateResource

#Set resource value
function OpCon_SetResource($url,$token,$id,$name,$value,$description,$used)
{
    $hdr = @{"authorization" = $token}

    $resource = OpCon_GetResource -url $url -token $token -name $name -id $id

    $counter = 0
    $resource | ForEach-Object { $counter ++ }

    if($counter -ne 1)
    {
        Write-Host "More than 1 or no result, cannot set resource"
    }

    if($value)
    {
        if($value.StartsWith("+"))
        {
            $value = $resource[0].value + [convert]::ToInt32($value.SubString(1))
        }
        elseif($value.StartsWith("-"))
        {
          if($resource[0].value -lt $value.SubString(1))
          {
            $value = 0
          }
          else
          {
            $value = $resource[0].value - [convert]::ToInt32($value.SubString(1))        
          }
        }
    }
    else
    {
        $value = $resource[0].value
    }

    if($used)
    {
        if($used.StartsWith("+"))
        {
            if(($resource[0].used + [convert]::ToInt32($used.SubString(1))) -gt $value)
            {
                $used = $value
            }
            else
            {
                $used = $resource[0].used + [convert]::ToInt32($used.SubString(1))
            }
        }
        elseif($used.StartsWith("-"))
        {
          if($resource[0].used -lt $used.SubString(1))
          {
            $used = 0
          }
          else
          {
            $value = $resource[0].inuse - [convert]::ToInt32($used.SubString(1))        
          }
        }
    }
    else
    {
        $used = $resource[0].used
    }

    $uriput = $url + "/api/resources/" + $resource[0].id

    $body = New-Object System.Object
    $body | Add-Member -type NoteProperty -name "id" -value $resource[0].id
    $body | Add-Member -type NoteProperty -name "name" -value $name
    $body | Add-Member -type NoteProperty -name "value" -value $value
    $body | Add-Member -type NoteProperty -name "used" -value $used

    If($description)
    {
        $body | Add-Member -type NoteProperty -name "description" -value $description
    }
    
    try
    {
        $result = (Invoke-RestMethod -Method PUT -Uri $uriput -Body ($body | ConvertTo-Json) -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $result
}
New-Alias "opsres" OpCon_SetResource

#Gets information about an OpCon Agent
function OpCon_GetAgent($url,$token,$agentname,$id)
{
    $hdr = @{"authorization" = $token}

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
        $machine = (Invoke-Restmethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }
    
    return $machine
}
New-Alias "opga" OpCon_GetAgent

#Starts or stops an OpCon agent based on parameters
function OpCon_ChangeAgentStatus($agentname,$action,$url,$token)
{
    $hdr = @{"authorization" = $token}

    $machine = OpCon_GetAgent -agentname $agentname -url $url -token $token
    if($machine.Count -eq 0)
    {
        Write-Host "No agent by that name!"
    }
    else
    {
        $machine = $machine[0]
    }

    #Enable/Disable the machine
    $uripost = $url + "/api/machineactions"
    $body = '{"machines":[{"id":' + $machine.id + '}],"action":"' + $action + '"}'

    try
    {
        $machineaction = (Invoke-Restmethod -Method POST -Uri $uripost -Headers $hdr -Body "$body" -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_.Exception.Message
    }

    Write-Host "Agent is $action!`r`n"
    return $machineaction
}
New-Alias "opas" OpCon_ChangeAgentStatus


#Creates a new agent in OpCon
function OpCon_CreateAgent($agentname,$agenttype,$agentdescription,$agentsocket,$agentjors,$token,$url)
{
    $hdr = @{"authorization" = $token}

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

        $uripost = $url + "/api/machines"
        $body = '{"name":"' + $agentname + '","type":{"id":' + $agenttypeid + ',"description":"' + $agentdescription + '"},"socket":' + $agentsocket + ',"jorsPortNumber":' + $agentjors + '}'

        try
        {
            $machine = (Invoke-RestMethod -Method POST -Uri $uripost -Headers $hdr -Body "$body" -ContentType "application/json")   
            Write-Host "Machine added!`r`n"
        }
        catch [Exception]
        {
            write-host $_.Exception.Message
        }
    }
    else
    {
        Write-Host "Agent with the same name already exists!`r`n"
    }

    return $machine
}
New-Alias "opca" OpCon_CreateAgent

#Updates a particular field on an existing agent
function OpCon_UpdateAgent($agentname,$token,$url,$field,$value)
{
    $hdr = @{"authorization" = $token}
    
    $agent = OpCon_GetAgent -agentname $agentname -url $url -token $token
    If($agent.PSobject.Properties.name -match $field)
    {
        $agent.$field = $value
    }
    else
    {
        Write-Host "invalid Machine property specified!"
    }

    #Take the machine down
    $down = OpCon_ChangeAgentStatus -agentname $agentname -action "down" -url $url -token $token

    $body = $agent | ConvertTo-Json -Depth 4
    $uriput = $url + "/api/machines/" + $agent.id

    try
    {
        $update = Invoke-Restmethod -Method PUT -Uri $uriput -Headers $hdr -Body "$body" -ContentType "application/json"
    }
    catch [Exception]
    {
        write-host $_.Exception.Message
    }
    Write-Host $agentname "updated!`r`n"

    Sleep 3

    #Bring the updated machine back up
    $up = OpCon_ChangeAgentStatus -agentname $agentname -action "up" -url $url -token $token
    return $up[0]
}
New-Alias "opua" OpCon_UpdateAgent

#Get schedule information
function OpCon_GetSchedule($url,$token,$sname,$date)
{
    $hdr = @{"authorization" = $token}

    if(!$date)
    {
        if(!$sname)
        {
            $uriget = $url + "/api/dailyschedules/dates"
        }
        Else
        {
            $uriget = $url + "/api/dailyschedules/?name=" + "$sname"
        }


        try
        {
            $getdates = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
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
            $getschedule = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
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
New-Alias "opgds" OpCon_GetSchedule


function OpCon_ScheduleAction($url,$token,$sname,$jname,$frequency,$reason,$action,$states,$date,$sid,$instanceProperties,[switch]$applyExceptions,[switch]$rebuildOnRestart)
{
    $hdr = @{"authorization" = $token}

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
                
                if(($z+2) -lt $propertyArray.Count)
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

    $uripost = $url + "/api/ScheduleActions"
    try
    {
        $submit = Invoke-RestMethod -Method POST -Uri $uripost -Body ($body | ConvertTo-Json -Depth 10) -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }
    
    # Get action statuses
    if(($submit.result -ne "success") -and ($submit.result -ne "failed"))
    {
        $timeout = 5
        While((($getAction.result -ne "success") -and ($getAction.result -ne "failed")) -and ($timeout -ne 0))
        {
            $getAction = OpCon_GetScheduleAction -url $url -token $token -id $submit.id
            Start-Sleep -Seconds 1
            $timeout--
        }
        Write-Host $action $getAction.result
    }
    else 
    { Write-Host $action $submit.result.result }
}

#Gets information about a daily job
function OpCon_GetDailyJob($url,$token,$sname,$jname,$date,$id)
{
    $hdr = @{"authorization" = $token}
    
    if($id)
    {
        $uriget = $url + "/api/dailyjobs/" + $id
    }
    else
    {
        if($date)
        {
            $uriget = $url + "/api/dailyjobs?scheduleName=" + $sname + "&dates=" + $date
        }
        else
        {
            $uriget = $url + "/api/dailyjobs?scheduleName=" + $sname
        }
    }

    try
    {
        $jobs = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    if($jname)
    {
        $jobs = $jobs | Where-Object{ $_.name -like "*$jname*" }
    }

    return $jobs
}
New-Alias "opgdj" OpCon_GetDailyJob

#Sends a job action to a job
function OpCon_JobAction($url,$token,$sname,$jname,$date,$action,$reason)
{
    $hdr = @{"authorization" = $token}

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
    }
    Else
    {
        Write-Host "No action specified!"
    }

    if($jname -and $sname)
    {
        if(!$date)
        {
            $date = Get-Date -Format "yyyy/MM/dd"
        }
        $job = OpCon_GetDailyJob -url $url -token $token -sname "$sname" -jname "$jname" -date $date

        $counter = 0    
        $job | ForEach-Object{ $counter++ }
        If($counter -ne 1)
        {
            Write-Host "Too many results for job!`r`n"
        }

        $jobsArray = @()
        $jobsArray += @{ id=$job[0].id; }
    }
    Else
    {
        Write-Host "Missing schedule or job name!"
    }

    $body = New-Object System.Object
    $body | Add-Member -type NoteProperty -name "action" -value $action
    $body | Add-Member -type NoteProperty -name "jobs" -value $jobsArray
    $body | Add-Member -type NoteProperty -name "reason" -value $reason

    $uripost = $url + "/api/jobactions"
    try
    {
        $jobaction = (Invoke-RestMethod -Method POST -Uri $uripost -Body ($body | ConvertTo-JSON) -Headers $hdr -ContentType "application/json")
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

#Get calendar
function OpCon_GetCalendar($url,$token,$name,$id)
{
    $hdr = @{"authorization" = $token}

    if($name -or $id)
    {
        if($name)
        { $uriget = $url + "/api/calendars?name=" + $name }
        
        if($id)
        { $uriget = $url + "/api/calendars/" + $id }

        try
        {
            $counter = 0
            $calendar = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
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
    {
        Write-Host "No name or id specified!"
    }
}
New-Alias "opgc" OpCon_GetCalendar

#Updates a calendar
function OpCon_UpdateCalendar($url,$token,$name,$id,$date)
{
    $hdr = @{"authorization" = $token}

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
    }
    else
    {
        Write-Host "No name or id specified!"
    }
    
    if($date)
    {
        if($date -in $calendar[0].dates)
        {
            Write-Host "Date already in calendar, not adding"
        }
		else
		{
			$uriput = $url + "/api/calendars/" + $calendar[0].id
			$calendar[0].dates += "$date"
			$body = $calendar[0] | ConvertTo-JSON -Depth 7

			try
			{
				$calendaradd = (Invoke-RestMethod -Method PUT -Uri $uriput -Body $body -Headers $hdr -ContentType "application/json")
			}
			catch [Exception]
			{
				Write-Host $_
				Write-Host $_.Exception.Message
			}

			return $calendaradd
		}
    }
    else
    {
        Write-Host "No date specified!"
    }
}
New-Alias "opuc" OpCon_UpdateCalendar

#Creates a user calendar (api allows for holiday calendar based on a schedule too)
function OpCon_CreateCalendar($url,$token,$type,$name,$dates,$description)
{
    $hdr = @{"authorization" = $token}

    #Eventually could add in "holiday" calendars
    $type = 1

    $uripost = $url + "/api/calendars/"
    $body = '{"type":' + $type + ',"name":"' + $name + '","dates":[' + $dates + '],"description":"' + $description + '"}'

    try
    {
        $calendar = (Invoke-RestMethod -Method POST -Uri $uripost -Body $body -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $calendar
}
New-Alias "opcc" OpCon_CreateCalendar

#Checks the status of the SAM service
function OpCon_SAMStatus($url,$token)
{
    $hdr = @{"authorization" = $token}

    $uriget = $url + "/api/servicestatus"

    try
    {
        $status = (Invoke-Restmethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_.Exception.Message
    }
    
    return $status
}

#Checks the OpCon API Version
function OpCon_OpConAPIVersion($url)
{
    $uriget = $url + "/api/version"

    try
    {
        $version = (Invoke-Restmethod -Method GET -Uri $uriget -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_.Exception.Message
    }
    
    return $version
}

#Function to remove an item from a Service Request choice dropdown
function OpCon_DeleteSSChoice($getdropdown,$url,$token,$buttonname,$removeitem)
{
    $hdr = @{"authorization" = $token}

    $get = OpCon_GetSSButton -button $buttonname -url $url -token $token
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

    $delete = ($details.request.variables.variable.choice.items.ChildNodes | Where-Object { $_.caption -like $removeitem }) | ForEach-Object { $_.ParentNode.RemoveChild($_) }

    #Shows list of entries
    $details.request.variables.variable.choice.items.ChildNodes

    #Set XML back
    $get.details = $details.InnerXml
    $body = $get | ConvertTo-Json -Depth 3

    $uriput = $url + "/api/ServiceRequests/" + $get.id

    try
    {
        $update = (Invoke-RestMethod -Method PUT -Uri $uriput -Headers $hdr -Body $body -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $update
}
New-Alias "opdssc" OpCon_DeleteSSChoice

#Function to add entries to a Service Request choice selection
function OpCon_AddSSChoice($addname,$addvalue,$getdropdown,$url,$token,$buttonname)
{
    $hdr = @{"authorization" = $token}

    $get = OpCon_GetSSButton -button $buttonname -url $url -token $token
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
    
        $uriput = $url + "/api/ServiceRequests/" + $get.id
        $body = $get | ConvertTo-Json -Depth 3
        
        try
        {
            $update = (Invoke-RestMethod -Method PUT -Uri $uriput -Headers $hdr -Body $body -ContentType "application/json")
        }
        catch [Exception]
        {
            Write-Host $_.Exception.Message
        }

        return $update
    }
    else
    {
        Write-Host "Entry already exists!"
    }
}
New-Alias "opassc" OpCon_AddSSChoice

#Gets information about a Self Service button
function OpCon_GetSSButton($url,$token,$id,$button)
{
    $hdr = @{"authorization" = $token}

    if($id)
    {
        $uriget = $url + "/api/ServiceRequests/" + $id
    }
    elseif($button)
    {
        $uriget = $url + "/api/ServiceRequests?name=" + $button
    }
    else
    {
        Write-Host "No button name or id specified!"
    }

    try
    {
        $getbutton = Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
        
        if($button)
        {
            $getbutton = Invoke-RestMethod -Method GET -Uri ($url + "/api/ServiceRequests/" + $getbutton.id) -Headers $hdr -ContentType "application/json"
        }
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $getbutton
}
#New-Alias "opgssb" OpCon_GetSSButton

#Gets a user from the OpCon database
function OpCon_GetUser($username,$url,$token)
{
    $hdr = @{"authorization" = $token}

    $uriget = $url + "/api/users?loginName=" + $username + "&includeDetails=true"

    try
    {
        $user = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
		Write-Host $_.Exception.Message
    }

    return $user
}
New-Alias "opgu" OpCon_GetUser

#Get a specific role
function OpCon_GetRole($url,$token,$id,$rolename)
{
    $hdr = @{"authorization" = $token}

    If($id)
    {
        $uriget = $url + "/api/roles/" + $id
    }
    ElseIf($rolename)
    {
        $uriget = $url + "/api/roles?name=" + $rolename
    }
    Else
    {
        Write-Host "No Id or Rolename specified"
    }

    try
    {
        $role = Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
		Write-Host $_.Exception.Message
    }

    return $role
}
New-Alias "opgrol" OpCon_GetRole

#Adds a specific role to a user in OpCon
function OpCon_AddUserRole($user,$rolename,$url,$token)
{
    $hdr = @{"authorization" = $token}

    $userinfo = OpCon_GetUser -username $user -url $url -token $token
    if($userinfo.Count -eq 0)
    {
        Write-Host "User $user does not exist"
    }
    $role = @(OpCon_GetRole -rolename $rolename -url $url -token $token)
    if($role.Count -eq 1)
    {
        $role = $role[0]
    }
    else
    {
        Write-Host "Role $rolename not found or multiple rolenames found!"
    }

    if($userinfo[0].Roles -notcontains "$rolename") 
    { 
        $userinfo[0].Roles += ,@{id=$role.id;name=$rolename} 
        $body = $userinfo[0] | ConvertTo-Json -Depth 4

        $uriput = $url + "/api/users/" + $userinfo.id
        try
        {
            $user = (Invoke-RestMethod -Method PUT -Uri $uriput -Headers $hdr -Body $body -ContentType "application/json")
        }
        catch [Exception]
        {
		    Write-Host $_.Exception.Message
        }
    }
    else
    {
        Write-Host "Role $rolename already on user account, not adding"
    }

    return $user
}
New-Alias "opaurol" OpCon_AddUserRole


#Adds all the roles related to the Demo SS Environment
function OpCon_AddDemoUserRoles($user,$url,$token)
{
    $hdr = @{"authorization" = $token}
    $userinfo = OpCon_GetUser -username $user -url $url -token $token
    $role = OpCon_GetRole -rolename "*_SS" -url $url -token $token

    #Get Role ids for default OpCon/Self Service demo
    $dba = $role | where-object {$_ -like "*DBA_SS*"}
    $opconadmin = $role | where-object {$_ -like "*OpCon_Admin_SS*"}
    $ops = $role | where-object {$_ -like "*Operations_SS*"}
    $usercontrol = $role | where-object {$_ -like "*User_Control_SS*"}
    $oncall = $role | where-object {$_ -like "*OnCall_SS*"}

    #Add roles to user
    if(($userinfo[0].Roles -match "DBA_SS").Count -eq 0) { $userinfo[0].Roles += ,@{id=$dba.id;name="DBA_SS"} }
    if(($userinfo[0].Roles -match "*OpConAdmin_SS*").Count -eq 0) { $userinfo[0].Roles += ,@{id=$opconadmin.id;name="OpConAdmin_SS"} }
    if(($userinfo[0].Roles -match "*User_Control_SS*").Count -eq 0) { $userinfo[0].Roles += ,@{id=$usercontrol.id;name="User_Control_SS"} }
    if(($userinfo[0].Roles -match "*Operations_SS*").Count -eq 0) { $userinfo[0].Roles += ,@{id=$ops.id;name="Operations_SS"} }
    if(($userinfo[0].Roles -match "*OnCall_SS*").Count -eq 0) { $userinfo[0].Roles += ,@{id=$oncall.id;name="OnCall_SS"} }

    #Convert user back to JSON
    $body = $userinfo[0] | ConvertTo-Json -Depth 4

    $uriput = $url + "/api/users/" + $userinfo[0].id
    try
    {
        $user = (Invoke-RestMethod -Method PUT -Uri $uriput -Headers $hdr -Body $body -ContentType "application/json")
    }
    catch [Exception]
    {
		Write-Host $_.Exception.Message
    }
}

#Creates an OpCon user
function OpCon_CreateUser($url,$token,$username,$password,$roleid,$rolename,$email,$notes,$comment)
{
    $hdr = @{"authorization" = $token}

    $get = OpCon_Getuser -url $url -token $token -username $username
    if(@($get).Count -eq 1)
    {
        Write-host "User " $username " already exists"
    }

    if(!$roleid -and $rolename)
    {
        $role = OpCon_GetRole -url $url -token $token -rolename $rolename
        if(@($role).Count -eq 1)
        {
            $roleid = $role[0].id
        }
    }

    #Create OpCon user account
    $uripost = $url + "/api/users"
    $post = '{"loginName":"' + $username + '","name":"' + $username + '","password":"' + $password + '","externalPassword":"' + $password + '","details":"' + $notes + '","moreDetails":"' + $comment + '","roles":[{"Id":' + $roleid + '}],"email":"' + $email + '"}'
    
    try
    {
        $create = (Invoke-RestMethod -Method POST -Uri $uripost -Headers $hdr -Body "$post" -ContentType "application/json")
    }
    catch [Exception]
    {
		Write-Host $_.Exception.Message
    }

    return $create
}
New-Alias "opcu" OpCon_CreateUser
   
#Sets up a job to disable a created user
function OpCon_DisableDemoUser($url,$token,$username,$userid)
{   
    $hdr = @{"authorization" = $token}

    #Get "ADHOC" schedule information
    $scheduleinfo = OpCon_GetSchedule -url $url -token $token -sname "ADHOC" -date (Get-Date -Format "MM/dd/yyyy")

    #Make sure only 1 Adhoc schedule was returned
    If(@($scheduleinfo).Count -ne 1)
    {
        Write-Host "Too many results for schedule"
    }

    #Submit JobAdd to disable user in the future
    $uripost = $url + "/api/ScheduleActions"
    $body = '{"scheduleActionItems":[{"id":"' + $scheduleinfo[0].id + '","jobs":[{"id":"DISABLE OPCON USER","frequency":"OnRequest","instanceProperties":[{"name":"USERNAME","value":"' + $username + '"},{"name":"id","value":"' + $userid + '"}]}]}],"action":"addjobs"}'

    try
    {
        $addjob = (Invoke-RestMethod -Method POST -Uri $uripost -Body $body -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $addjob
}

#Updates a field in an OpCon user
function OpCon_UpdateUser($url,$token,$username,$field,$value)
{
    $hdr = @{"authorization" = $token}

    if($username)
    {
        $getuser = OpCon_GetUser -username $username -url $url -token $token
        if($getuser.length -eq 0) # length of 0 indicates no user record exists
        { 
            Write-Host "User $username does not exist"
        }

        $user = $getuser[0]

        $uriput = $url + "/api/users/" + $user.id
        $user.$field = $value
        $body = $user | ConvertTo-Json

        try
        {
            $updateduser = (Invoke-RestMethod -Method PUT -Uri $uriput -Headers $hdr -Body $body -ContentType "application/json")
        }
        catch [Exception]
        {
            Write-Host $_.Exception.Message
        }

        return $updateduser
    }
    else
    {
        Write-Host "No username provided!"
    }
}
New-Alias "opuu" OpCon_UpdateUser

#Get schedule information
function OpCon_GetDailyJobsCountByStatus($url,$token,$date,$status)
{
    $hdr = @{"authorization" = $token}

    if(!$date)
    {
        $date = Get-Date -format "yyyy-MM-dd"
    }

    $uriget = $url + "/api/dailyjobs/count_by_status" #?terminationDescription=" + $status

    try
    {
        $count = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $count
}
New-Alias "opgdjcs" OpCon_GetDailyJobsCountByStatus

#Gets daily jobs by status and date (default todays date)
function OpCon_GetDailyJobsByStatus($url,$token,$date,$status)
{
    $hdr = @{"authorization" = $token}

    if(!$date)
    {
        $date = Get-Date -format "yyyy-MM-dd"
    }

    $uriget = $url + "/api/dailyjobs?status=" + $status + "&dates=" + $date

    try
    {
        $count = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $count
}
New-Alias "opgdjstat" OpCon_GetDailyJobsByStatus

function OpCon_GetDailyJobsBySchedule($url,$token,$date,$schedule)
{
    $hdr = @{"authorization" = $token}

    if(!$date)
    {
        $date = Get-Date -format "yyyy-MM-dd"
    }

    $uriget = $url + "/api/dailyjobs?scheduleName=" + $schedule

    try
    {
        $count = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $count
}

#Gets a specific daily job based on the jobs id
function OpCon_GetSpecificDailyJob($url,$token,$jid)
{
    $hdr = @{"authorization" = $token}

    $uriget = $url + "/api/dailyjobs/" + $jid

    try
    {
        $jobs = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $jobs
}

#Attempts to get an output file from a job run
function OpCon_SubmitJobInstanceFileAction($url,$token,$sname,$jname,$date,$jobnumber,$path)
{
    $hdr = @{"authorization" = $token}

    if(!$jobnumber)
    {
        $jobnumber = (OpCon_GetDailyJob -url $url -token $token -sname $sname -jname $jname -date $date).jobNumber
    }

    $uripost = $url + "/api/jobinstanceactions"
    $body = '{"action":"FILE","jobInstanceActionItems":[{"id":' + $jobnumber + ',"jorsRequestParameters":' + $path + '}]}'

    try
    {
        $file = (Invoke-RestMethod -Method POST -Uri $uripost -Headers $hdr -Body $body -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $file
}

#Attempts to get a list of output files from a job run
function OpCon_SubmitJobInstanceListAction($url,$token,$sname,$jname,$date)
{
    $hdr = @{"authorization" = $token}

    $jobnumber = (OpCon_GetDailyJob -url $url -token $token -sname $sname -jname $jname -date $date).jobNumber

    $uripost = $url + "/api/jobinstanceactions"
    $body = '{"action":"LIST","jobInstanceActionItems":[{"id":' + $jobnumber + '}]}'

    try
    {
        $list = (Invoke-RestMethod -Method POST -Uri $uripost -Headers $hdr -Body $body -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $list
}

#Gets information about a previously submitted job action
function OpCon_GetJobInstanceAction($url,$token,$id)
{
    $hdr = @{"authorization" = $token}

    $uriget = $url + "/api/jobinstanceactions/" + $id

    try
    {
        $status = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $status
}

#Standard function for returning job output, a custom function may be required if there are multiple output files
function OpCon_GetJobOutput($url,$token,$sname,$jname,$date)
{
    $list = OpCon_SubmitJobInstanceListAction -url $url -token $token -sname $sname -jname $jname -date $date
    $liststatus = OpCon_GetJobInstanceAction -url $url -token $token -id $list.id
    while((($liststatus.result -ne "success") -and ($liststatus.result -ne "failed")))
    {
        $liststatus = OpCon_GetJobInstanceAction -url $url -token $token -id $list.id
    }

    if($liststatus.result -eq "success")
    {
        $path = $liststatus.jobInstanceActionItems.files | ConvertTo-Json
    }
    else
    {
        Write-Host "Problem getting job output file list"
    }

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
New-Alias "opgdjo" OpCon_GetJobOutput

#Gets a user from the OpCon database
function OpCon_GetUserByComment($comment,$url,$token)
{
    $hdr = @{"authorization" = $token}

    $uriget = $url + "/api/users?includeDetails=true"

    try
    {
        $user = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
		Write-Host $_.Exception.Message
    }

    return $user | Where-Object{ $_.moreDetails -like "*$comment*" }
}

#Get vision tags
function OpCon_GetTags($url,$token,$date)
{
    $hdr = @{"authorization" = $token}

    if(!$date)
    {
        $date = Get-Date -format "yyyy-MM-dd"
    }

    $uriget = $url + "/api/vision/cards?dates=" + $date

    try
    {
        $schedule = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    if($schedule.Count -eq 0)
    {
        Write-Host "No schedules found!"
    }

    return $schedule
}
New-Alias "opgtag" OpCon_GetTags

#Gets daily jobs by tag for a date
function OpCon_GetDailyJobsByTag($url,$token,$date,$tag)
{
    $hdr = @{"authorization" = $token}

    if(!$date)
    {
        $date = Get-Date -format "yyyy-MM-dd"
    }

    $uriget = $url + "/api/dailyjobs?tags=" + $tag + "&dates=" + $date

    try
    {
        $count = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $count
}
New-Alias "opgdjtag" OpCon_GetDailyJobsByTag

#Get Agent count by status
function OpCon_GetAgentCountByStatus($url,$token)
{
    $hdr = @{"authorization" = $token}

    if(!$date)
    {
        $date = Get-Date -format "yyyy-MM-dd"
    }

    $uriget = $url + "/api/machines/count_by_status" #?terminationDescription=" + $status

    try
    {
        $count = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $count
}

#Get dependencies for a job
function OpCon_GetDependencyByJob($url,$token,$sname,$jname,$date,$jid)
{
    $hdr = @{"authorization" = $token}

    if(!$jid)
    {
        if(!$sname -or !$jname)
        {
            Write-Host "Error, if no job id supplied then schedule/job name required!"
        }
        elseif(!$date)
        {
            $date = Get-Date -format "yyyy-MM-dd"
        }

        $jid = (OpCon_GetDailyJob -url $url -token $token -sname $sname -jname $jname -date $date).id
    }

    $uriget = $url + "/api/dailygraphedges/" + $jid

    try
    {
        $result = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $result
}

#Gets all daily jobs in a schedule
function OpCon_GetDailyJobsBySchedule($url,$token,$sname,$date)
{
    $hdr = @{"authorization" = $token}

    if(!$date)
    {
        $date = Get-Date -format "yyyy-MM-dd"
    }

    $uriget = $url + "/api/dailyjobs?scheduleName=" + $sname + "&dates=" + $date

    try
    {
        $jobs = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $jobs
}

#DEPRECATED (use OpCon_GetServiceRequestChoice) Function to get a Service Request choice dropdown
function OpCon_GetSSChoice($dropdown,$url,$token,$button)
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

    return $details.request.variables.variable.choice.items.ChildNodes
}
New-Alias "opgssc" OpCon_GetSSChoice

#DEPRECATED (renamed as GetServiceRequestInput) Function to get a Service Request input field
function OpCon_GetSSInput($url,$token,$button)
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

#Creates an OpCon Role
function OpCon_CreateRole($url,$token,$rolename,$inheritSchedule,$inheritMach,$inheritMachGroup,$permissions)
{
    $hdr = @{"authorization" = $token}
    
    #Check if role already exists
    if(OpCon_GetRole -url $url -token $token -rolename "$rolename")
    {
        Write-Host "Role already exists"
    }
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

        #$body | ConvertTo-JSON

        $uripost = $url + "/api/roles"
        try
        {
            $role = (Invoke-Restmethod -Method POST -Uri $uripost -Headers $hdr -Body ($body | ConvertTo-Json) -ContentType "application/json")
        }
        catch [Exception]
        {
            Write-Host $_
            write-host $_.Exception.Message
        }

        return $role
    }
}
New-Alias "opcrol" OpCon_CreateRole

#Creates a Service Request
function OpCon_CreateServiceRequest($url,$token,$name,$doc,$html,$details,$disable,$hide,$category,$categoryName,$roles)
{
    $hdr = @{"authorization" = $token}
    
    #Check if button already exists
    $buttons = @(OpCon_GetSSButton -url $url -token $token -button "$name") 
    if($buttons.Count -eq 1)
    {
        Write-Host "Service Request already exists"
    }
    else
    {
        #Build Service Request object
        $body = New-Object System.Object
        $body | Add-Member -type NoteProperty -name "name" -value "$name"
        $body | Add-Member -type NoteProperty -name "documentation" -value "$doc" 
        $body | Add-Member -type NoteProperty -name "html" -value "$html"
        $body | Add-Member -type NoteProperty -name "details" -value "$details"
        $body | Add-Member -type NoteProperty -name "disableRule" -value "$disable"
        $body | Add-Member -type NoteProperty -name "hideRule" -value "$hide"
        $body | Add-Member -type NoteProperty -name "roles" -value $roles

        if($categoryName)
        {
            $categoryObject = OpCon_GetServiceRequestCategory -url $url -token $token -category "$categoryName"
            $body | Add-Member -type NoteProperty -name "serviceRequestCategory" -value @{id=$categoryObject.id}
        }
        elseif($category)
        {
            $body | Add-Member -type NoteProperty -name "serviceRequestCategory" -value $category
        }

        $uripost = $url + "/api/ServiceRequests"
        try
        {
            $servicerequest = (Invoke-Restmethod -Method POST -Uri $uripost -Headers $hdr -Body ($body | ConvertTo-Json) -ContentType "application/json")
        }
        catch [Exception]
        {
            write-host $_
            write-host $_.Exception.Message
        }

        return $servicerequest
    }
}

#Deletes a Service Request
function OpCon_DeleteServiceRequest($url,$token,$name)
{
    $hdr = @{"authorization" = $token}
    
    $button = OpCon_GetSSButton -url $url -token $token -button "$name"
    
    #Check if button exists
    if($button)
    {
        $uridelete = $url + "/api/ServiceRequests/" + $button.id

        try
        {
            $servicerequest = (Invoke-Restmethod -Method DELETE -Uri $uridelete -Headers $hdr -Body "{}" -ContentType "application/json")
        }
        catch [Exception]
        {
            write-host $_
            write-host $_.Exception.Message
        }

        return $servicerequest        
    }
    else
    {
        Write-Host "Service Request does not exist"
    }
}
New-Alias "opdss" OpCon_DeleteServiceRequest

#Adds a role to a SS button
function OpCon_AddSSButtonRole($url,$token,$button,$rolename)
{
    $hdr = @{"authorization" = $token}
    
    $getbutton = OpCon_GetSSButton -url $url -token $token -button $button
    $rolecheck = "true"
    $getbutton.roles | ForEach-Object{ If($_.name -eq $rolename)
                                       { $rolecheck = "false" }
                                     }
    If($rolecheck -eq "true")
    {
        $getrole = OpCon_GetRole -url $url -token $token -rolename $rolename
        $getbutton.roles += $getrole

        $uripost = $url + "/api/ServiceRequests/" + $getbutton.id
        try
        {
            $update = Invoke-RestMethod -Method PUT -Uri $uripost -Body ($getbutton | ConvertTo-JSON) -Headers $hdr -ContentType "application/json"
        }
        catch [Exception]
        {
            Write-Host $_
            Write-Host $_.Exception.Message
        }

        return $update
    }
    Else
    {
        Write-Host "Button already has role $rolename !"
    }
}
New-Alias "opassrol" OpCon_AddSSButtonRole

#Updates a particular field on a SS button
function OpCon_UpdateSSButton($url,$token,$button,$field,$value)
{
    $hdr = @{"authorization" = $token}
    
    $getbutton = OpCon_GetSSButton -url $url -token $token -button $button
    $getbutton.$field = $value

    $uripost = $url + "/api/ServiceRequests/" + $getbutton.id
    try
    {
        $update = Invoke-RestMethod -Method PUT -Uri $uripost -Body ($getbutton | ConvertTo-Json -Depth 7) -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $update
}

#Function to get a Service Request category/categories
function OpCon_GetServiceRequestCategory($url,$token,$category,$id)
{
    $hdr = @{"authorization" = $token}
    
    if($category)
    {
        $uriget = $url + "/api/ServiceRequestCategories?name=" + $category
    }
    elseif($id)
	{
        $uriget = $url + "/api/ServiceRequestCategories/" + $id
    }
	else
	{
		Write-Host "No name or id specified!"
	}

    try
    {
        $categories = Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"

		if($categories.Count -eq 0)
        {
            Write-Host "Category $category not found!"
        }
		elseif($category)
		{
			$categories = Invoke-RestMethod -Method GET -Uri ($url + "/api/ServiceRequestCategories/" + $categories.id) -Headers $hdr -ContentType "application/json"
		}
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $categories
}
New-Alias "opgsscat" OpCon_GetServiceRequestCategory

#Removes a specific role from a user in OpCon
function OpCon_RemoveUserRole($user,$rolename,$url,$token)
{
    $hdr = @{"authorization" = $token}

    $userinfo = OpCon_GetUser -username $user -url $url -token $token
    $role = @(OpCon_GetRole -rolename $rolename -url $url -token $token)
    if($role.Count -eq 1)
    {
        $role = $role[0]
    }
    else
    {
        Write-Host "Role $rolename not found or multiple rolenames found!"
    }

    if($userinfo[0].Roles.name -contains "$rolename") 
    { 
        $userinfo[0].Roles = @($userinfo[0].Roles | Where-Object { $_.name -ne "$rolename" })
        $body = $userinfo[0] | ConvertTo-Json -Depth 4

        $uriput = $url + "/api/users/" + $userinfo.id
        try
        {
            $result = (Invoke-RestMethod -Method PUT -Uri $uriput -Headers $hdr -Body $body -ContentType "application/json")
        }
        catch [Exception]
        {
		    Write-Host $_.Exception.Message
        }
    }
    else
    {
        Write-Host "Role $rolename is not on user account, not removing"
    }

    return $result
}
New-Alias "opdurol" OpCon_RemoveUserRole

#Handles schedule builds
function OpCon_ScheduleBuild($url,$token,$schedules,$dates,$logfile,$overwrite,$properties,$hold,$namedInstance,$machineName)
{
    $hdr = @{"authorization" = $token}

    $body = New-Object System.Object

    #Checks that a schedule name was provided
    if($schedules)
    {
        $scheduleArray = @()
        if($schedules -like "*;*")
        { $schedules.Split(";") | ForEach-Object{ $scheduleArray += [PSCustomObject]@{ "name" = $_ } } }
        else
        { $scheduleArray += [PSCustomObject]@{"name" = $schedules } }
    }
    else
    {
        Write-Host "No schedule name/s provided!"
    }
    
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
            $properties.Split(";") | ForEach-Object{ $splitter = $_.Split(",") 
                                                     $propertyArray += @{ key=$splitter[0];value=$splitter[1] } }
        }
        else
        {
            $splitter = $properties.Split(",")
            $propertyArray += @{ key=$splitter[0];value=$splitter[1] }
        }
    }

    if(!$overwrite)
    { $overwrite = $false }

    $body | Add-Member -type NoteProperty -name "schedules" -value $scheduleArray
    $body | Add-Member -type NoteProperty -name "dates" -value $dateArray
    $body | Add-Member -type NoteProperty -name "properties" -value $propertyArray
    $body | Add-Member -type NoteProperty -name "logFile" -value $logfile
    $body | Add-Member -type NoteProperty -name "overwrite" -value $overwrite
    $body | Add-Member -type NoteProperty -name "hold" -value $hold
    $body | Add-Member -type NoteProperty -name "namedInstance" -value $namedInstance
    $body | Add-Member -type NoteProperty -name "machineName" -value $machineName 

    $uripost = $url + "/api/schedulebuilds"
    try
    {
        $build = (Invoke-RestMethod -Method POST -Uri $uripost -Body ($body | ConvertTo-JSON -Depth 7) -Headers $hdr -ContentType "application/json")
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
    {
        Write-host $status.message
    }

    return $status
}

#Checks the status of a Schedule Build
function OpCon_ScheduleBuildStatus($url,$token,$id)
{
    $hdr = @{"authorization" = $token}
    
    $uriget = $url + "/api/schedulebuilds/" + $id
    try
    {
        $status = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $status
}

#Gets a count of schedules by status
function OpCon_ScheduleCountByStatus($url,$token,$dates,$name,$failedJobs,$categories)
{
    $hdr = @{"authorization" = $token}
    
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
        $countByStatus = (Invoke-Restmethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }
    
    return $countByStatus
}

#Gets schedule properties
function OpCon_GetScheduleProperty($url,$token,$id,$name,$schedule,$date)
{
    $hdr = @{"authorization" = $token}
    
    $uriget = $url + "/api/dailyschedules/"

    If($id)
    {
        $uriget = $uriget + $id + "/properties"
    }
    ElseIf($schedule)
    {
        if(!$date)
        { $date = Get-Date -Format "yyyy/MM/dd" }

        
        $getsid = OpCon_GetSchedule -url $url -token $token -date $date -sname $schedule
        $uriget = $uriget + $getsid.id + "/properties"
    }
    Else
    {
        Write-Host "Not enough schedule information!"
    }

    If($name)
    {
        $uriget = $uriget + "/" + $name
    }

    try
    {
        $properties = (Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $properties
}
New-Alias "opgsp" OpCon_GetScheduleProperty

#Gets access codes
function OpCon_GetAccessCode($url,$token,$id,$name)
{
    $hdr = @{"authorization" = $token}
    
    #Get property information
    If($id)
    {
        $uriget = $url + "/api/AccessCodes/" + $id
    }
    ElseIf($name)
    {
        $uriget = $url + "/api/AccessCodes?name=" + $name
    }
    Else
    {
        $uriget = $url + "/api/AccessCodes"
    }

    try
    {
        $accessCodes = (Invoke-Restmethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }
    
    return $accessCodes
}

#Creates a new access code
function OpCon_CreateAccessCode($url,$token,$name)
{
    $hdr = @{"authorization" = $token}
    
    #Get property information
    $body = New-Object System.Object
    $body | Add-Member -type NoteProperty -name "name" -value $name

    $uripost = $url + "/api/AccessCodes"
    try
    {
        $accessCode = (Invoke-Restmethod -Method POST -Uri $uripost -Headers $hdr -Body ($body | ConvertTo-Json) -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }

    return $accessCode
}

#Sets a new name for an access code
function OpCon_SetAccessCode($url,$token,$id,$oldName,$name)
{
    If($oldname -or $id)
    {
        $accessCode = OpCon_GetAccessCode -url $url -token $token -name $oldname -id $id

        $counter = 0
        $accessCode | ForEach-Object{ $counter++ }

        if($counter -ne 1)
        {
            Write-Host "Too many or no access codes found!"
        }
    }
    Else
    {
        Write-Host "Id or Name not specified!"
    }

    $hdr = @{"authorization" = $token}
    
    #Set new name
    If($name)
    {
        $accessCode[0].name = $name
    }
    Else
    {
        Write-Host "Name not specified!"
    }

    #Update access code
    $uriput = $url + "/api/AccessCodes/" + $accessCode[0].id
    try
    {
        $update = (Invoke-Restmethod -Method PUT -Uri $uriput -Headers $hdr -Body ($accessCode[0] | ConvertTo-Json) -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }

    return $update
}

#Gets a batch user or list of users
function OpCon_GetBatchUser($url,$token,$id,$ids,$loginName,$roleName,$includeRoles)
{
    $hdr = @{"authorization" = $token}
    
    #Get batchusers
    If($ids -or $loginName -or $roleName -or $includeRoles)
    {
        $uriget = $url + "/api/batchusers?"

        If($ids)
        {
            $uriget = $uriget + "ids=" + $ids
        }
        ElseIf($loginName)
        {
            $uriget = $uriget + "loginName=" + $loginName
        }
        ElseIf($roleName)
        {
            $uriget = $uriget + "roleName=" + $roleName
        }
        ElseIf($includeRoles)
        {
            $uriget = $uriget + "includeRoles=" + $includeRoles
        }
    }
    ElseIf($id)
    {
        $uriget = $url + "/api/batchusers/" + $id
    }
    Else
    {
        $uriget = $url + "/api/batchusers"
    }

    try
    {
        $batchUsers = (Invoke-Restmethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }
    
    return $batchUsers
}
New-Alias "opgbu" OpCon_GetBatchUser

#Creates a new batch user
function OpCon_CreateBatchUser($url,$token,$platformName,$loginName,$password,$roleNames)
{
    $hdr = @{"authorization" = $token}
    
    #Assign Agent type # based off OS name
    If($platformName)
    {
        $platformArray = @("NA","FILE TRANSFER","HP NONSTOP","WINDOWS","OPENVMW","IBMI","UNIX","OS2200","VSE","MCP","NA","NA","ZOS","SAP R3","SAP BW","NA","JEE","JAVA","TUXEDOART","EASE","ASYSCO AMT","SQL")
        for($x=0;$x -lt $platformArray.Count;$x++)
        {
            If($platformArray[$x] -eq $platformName)
            {
                $platformId = $x
            }
        }
    
        if((!$platformId) -or ($platformId -eq "NA"))
        {
            Write-Host "Invalid platform"
        }

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
            {
                Write-Host "Role" $roleNameArray[$x] "not found!"
            }
        }
    }

    #Verify login name
    If(!$loginName)
    {
        Write-Host "No login name specified"
    }
    ElseIf(!$password)
    {
        Write-Host "Password not specified!"
    }

    #Builds Batch User object
    $body = New-Object System.Object
    $body | Add-Member -type NoteProperty -name "loginName" -value $loginName
    $body | Add-Member -type NoteProperty -name "roles" -value $roleIdArray
    $body | Add-Member -type NoteProperty -name "password" -value $password 
    $body | Add-Member -type NoteProperty -name "platform" -value $platformObject

    $uripost = $url + "/api/batchusers"
    try
    {
        $batchUser = (Invoke-Restmethod -Method POST -Uri $uripost -Headers $hdr -Body ($body | ConvertTo-Json -Depth 7) -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_
        write-host $_.Exception.Message
    }

    return $batchUser
}
New-Alias "opcbu" OpCon_CreateBatchUser

#Allows for updating a batch use with new roles
function OpCon_SetBatchUser($url,$token,$loginName,$roleNames)
{
    If($loginName)
    {
        $user = OpCon_GetBatchUser -url $url -token $token -loginName $loginName

        $counter = 0
        $user | ForEach-Object{ $counter++ }

        if($counter -ne 1)
        {
            Write-Host "Too many or no properties found!"
        }
    }
    Else
    {
        Write-Host "loginName not specified!"
    }

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
            {
                Write-Host "Role" $roleNameArray[$x] "not found!"
            }
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
New-Alias "opubu" OpCon_SetBatchUser

#Starts or stops an OpCon agent based on parameters *New version of ChangeAgentStatus*
function OpCon_MachineAction($url,$token,$agentName,$action)
{
    $hdr = @{"authorization" = $token}

    $machine = OpCon_GetAgent -agentname $agentName -url $url -token $token

    $count = 0
    $machine | ForEach-Object{ $count++ }
    if($count -eq 0)
    {
        Write-Host "No agent by that name!"
    }
    else
    {
        $machine = $machine[0]
    }

    #Enable/Disable the machine
    $machinesArray = @()
    $machinesArray += @{ id=$machine.id }
    $body = New-Object System.Object
    $body | Add-Member -type NoteProperty -name "machines" -value $machinesArray
    $body | Add-Member -type NoteProperty -name "action" -value $action

    $uripost = $url + "/api/machineactions"
    try
    {
        $machineaction = (Invoke-Restmethod -Method POST -Uri $uripost -Headers $hdr -Body ($body | ConvertTo-Json) -ContentType "application/json")
    }
    catch [Exception]
    {
        write-host $_.Exception.Message
    }

    if($machineaction.result -eq "success")
    {
        return $machineaction
    }
    elseif($machineaction.result -eq "error")
    {
        Write-Host "Machine action attempt had an error"
    }
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

#Gets information about an OpCon Agent
function OpCon_GetMachineAction($url,$token,$id)
{
    $hdr = @{"authorization" = $token}

    #Validates id is passed
    If($id)
    {
        $uriget = $url + "/api/machineactions/" + $id
    }
    Else
    {
        Write-Host "No id supplied"
    }

    try
    {
        $action = (Invoke-Restmethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }
    
    return $action
}

#Gets information about a submitted Job Action
function OpCon_GetJobAction($url,$token,$id)
{
    $hdr = @{"authorization" = $token}

    #Validates id is passed
    If($id)
    {
        $uriget = $url + "/api/jobactions/" + $id
    }
    Else
    {
        Write-Host "No id supplied"
    }

    try
    {
        $action = (Invoke-Restmethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json")
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }
    
    return $action
}

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
        {
            Write-Host "No dropdowns called $dropdown"
        }
    }
    else
    {
        Write-Host "No dropdown specified!"
    }
}

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

#Gets information about all Self Service button
function OpCon_GetAllSSButtons($url,$token)
{
    $hdr = @{"authorization" = $token}
    $uriget = $url + "/api/ServiceRequests?name="

    try
    {
        $getbutton = Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
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
    $hdr = @{"authorization" = $token}

    if($id)
    {
        $uriget = $url + "/api/ServiceRequests/" + $id
    }
    elseif($button)
    {
        $uriget = $url + "/api/ServiceRequests?name=" + $button
    }
    else
    {
        Write-Host "No button name or id specified!"
    }

    try
    {
        $getbutton = Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"

        if($button)
        {
            $getbutton = Invoke-RestMethod -Method GET -Uri ($url + "/api/ServiceRequests/" + $getbutton.id) -Headers $hdr -ContentType "application/json"
        }
    }
    catch [Exception]
    {
		Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $getbutton
}
New-Alias "opgssb" OpCon_GetServiceRequest

#Function to get all Service Request categories
function OpCon_GetAllServiceRequestCategories($url,$token)
{
    $hdr = @{"authorization" = $token}
    $uriget = $url + "/api/ServiceRequestCategories?name="

    try
    {
        $categories = Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $categories
}

#Updates a Self Service category
function OpCon_OverwriteServiceRequestCategory($url,$token,$category,$destCategory,$destCategoryId)
{
    $hdr = @{"authorization" = $token}

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
    $uriput = $url + "/api/ServiceRequestCategories/" + $oldCategory
    try
    {
        $update = Invoke-RestMethod -Method PUT -Uri $uriput -Body ($category | ConvertTo-Json -Depth 7) -Headers $hdr -ContentType "application/json"
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

#Updates a particular field on a SS button
function OpCon_OverwriteServiceRequest($url,$token,$button,$destButton,$destButtonId)
{
    $hdr = @{"authorization" = $token}

	if($destButton)
	{
		$oldButton = (OpCon_GetServiceRequest -url $url -token $token -button $destButton).id
	}
	elseif($destButtonId)
	{
		$oldButton = (OpCon_GetServiceRequest -url $url -token $token -id $destButtonId).id
	}
	else
	{
		$oldButton = $button.id
	}

	$button.id = $oldButton
    $uripost = $url + "/api/ServiceRequests/" + $oldButton
    try
    {
        $update = Invoke-RestMethod -Method PUT -Uri $uripost -Body ($button | ConvertTo-Json -Depth 7) -Headers $hdr -ContentType "application/json"
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

#Gets information about all Self Service button
function OpCon_GetAllServiceRequests($url,$token)
{
    $hdr = @{"authorization" = $token}
    $uriget = $url + "/api/ServiceRequests?name="

    try
    {
        $getbutton = Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
		Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $getbutton
}

# Gets Daily Vision Workspaces
function OpCon_GetDailyVisionWorkspaces($url,$token)
{
    $hdr = @{"authorization" = $token}
    $uriget = $url + "/api/dailyvisionworkspaces"

    try
    {
        $vision = Invoke-Restmethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }
    
    return $vision
}
New-Alias "opgdv" OpCon_GetDailyVisionWorkspaces

# Gets Master Vision Workspaces
function OpCon_GetMasterVisionWorkspaces($url,$token)
{
    $hdr = @{"authorization" = $token}
    $uriget = $url + "/api/mastervisionworkspaces"

    try
    {
        $vision = Invoke-Restmethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }
    
    return $vision
}

# Updates Master Vision workspaces based on passed in object
function OpCon_UpdateMasterVisionWorkspaces($url,$token,$id,$workspaceObj)
{
    $hdr = @{"authorization" = $token}
    $uriput = $url + "/api/mastervisionworkspaces/$id"

    $body = $workspaceObj

    try
    {
        $vision = Invoke-Restmethod -Method PUT -Uri $uriput -Body ($body | ConvertTo-Json -Depth 15) -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }
    
    return $vision
}

# Gets OpCon server options
function OpCon_GetServerOptions($url,$token)
{
    $hdr = @{"authorization" = $token}

    $uriget = $url + "/api/serverOptions"

    try
    {
        $servOptions = Invoke-Restmethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }
    
    return $servOptions
}
New-Alias "opgservo" OpCon_GetServerOptions

# Updates Server Options
function OpCon_UpdateServerOptions($url,$token,$optionsObj)
{
    $hdr = @{"authorization" = $token}

    $uriput = $url + "/api/serverOptions"
    $body = $optionsObj

    try
    {
        $servOptions = Invoke-Restmethod -Method PUT -Uri $uriput -Body ($body | ConvertTo-Json -Depth 5) -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }
    
    return $servOptions
}
New-Alias "opuservo" OpCon_UpdateServerOptions

#Gets information about a submitted Schedule Action
function OpCon_GetScheduleAction($url,$token,$id)
{
    $hdr = @{"authorization" = $token}

    $uriget = $url + "/api/ScheduleActions/" + $id

    try
    {
        $action = Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $action
}

#Function to add entries to a Service Request choice selection
function OpCon_AddSSChoiceMassImport($addname,$addvalue,$getdropdown,$url,$token,$buttonname)
{
    $hdr = @{"authorization" = $token}

    $get = OpCon_GetSSButton -button $buttonname -url $url -token $token
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
    $xmlFrag = $details.CreateDocumentFragment()

    # Creates one big list of all the items for the dropdown
    For($x=0;$x -lt $addname.Count;$x++)
    {
        $newEntries = $newEntries + "<item><caption>" + $addname[$x] + "</caption><value>" + $addvalue[$x] + "</value></item>"
    }
        
    $xmlFrag.InnerXml = $newEntries
    $add = ($details.request.variables.variable | Where-Object{$_.name -eq $getdropdown}) | ForEach-Object{$_.choice.items.AppendChild($xmlFrag)}     
        
    #Adds modified items back to original object
    $get.details = $details.InnerXml
    
    $uriput = $url + "/api/ServiceRequests/" + $get.id
    $body = $get | ConvertTo-Json -Depth 3
        
    try
    {
        $update = Invoke-RestMethod -Method PUT -Uri $uriput -Headers $hdr -Body $body -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_.Exception.Message
    }

    return $update
}

#Updates all the calendar dates
function OpCon_UpdateAllCalendarDates($url,$token,$name,$id,$dates)
{
    $hdr = @{"authorization" = $token}

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
    }
    else
    {
        Write-Host "No name or id specified!"
    }
    
    if($dates)
    {
        $dates = $dates | select -Unique
		$uriput = $url + "/api/calendars/" + $calendar[0].id
		$calendar[0].dates = $dates
		$body = $calendar[0] | ConvertTo-JSON -Depth 7

		try
		{
			$calendaradd = Invoke-RestMethod -Method PUT -Uri $uriput -Body $body -Headers $hdr -ContentType "application/json"
		}
		catch [Exception]
		{
			Write-Host $_
			Write-Host $_.Exception.Message
		}

		return $calendaradd
    }
    else
    {
        Write-Host "No date/s specified!"
    }
}

#Gets daily jobs
function OpCon_GetDailyJobs($url,$token,$filter)
{
    $hdr = @{"authorization" = $token}

    if($filter)
    {
        $uriget =  $url + "/api/dailyjobs?" + $filter
    }
    else
    {
        $uriget = $url + "/api/dailyjobs"
    }

    try
    {
        $jobs = Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_
        Write-Host $_.Exception.Message
    }

    return $jobs
}
New-Alias "opgdjs" OpCon_GetDailyJobs

<#
.SYNOPSIS

Connects to an OpCon environment

.OUTPUTS

Object with the id,url,token,expiration,release.

.EXAMPLE

C:\PS> opconnect"
#>
Function opconnect($count,$login)
{ 
    if(!$login)
    {
        $url = Read-Host "OpCon API url"
        $user = Read-Host "Enter Username" #-AsSecureString 
        $password = Read-Host "Enter Password" -AsSecurestring
        
        Clear-Host # Clears console
        
        $auth = OpCon_Login -url $url -user $user -password ((New-Object PSCredential "user",$password).GetNetworkCredential().Password)
        $password = "" # Clear out password variable
        $newLogin = [pscustomobject]@{"id"=$count;"name"=$url.Substring($url.IndexOf("//")+2,$url.LastIndexOf(":")-($url.IndexOf("//")+2));"url"=$url;"user"=$user;"token"=("Token " + $auth.id);"expiration"=($auth.validUntil);"release"=((OpCon_OpConAPIVersion -url $url).opConRestApiProductVersion)}
    }
    else
    {
        $login.user = Read-Host "Enter Username" #-AsSecureString 
        $password = Read-Host "Enter Password" -AsSecurestring
        
        Clear-Host # Clears console
        
        $auth = OpCon_Login -url $login.url -user $login.user -password ((New-Object PSCredential "user",$password).GetNetworkCredential().Password)
        $password = "" # Clear out password variable
        $login.token = ("Token " + $auth.id)
        $login.expiration = ($auth.validUntil)
        $login.release = ((OpCon_OpConAPIVersion -url $login.url).opConRestApiProductVersion)
        $newLogin = $login
    }
    
    return $newLogin
}

Function OpCon_ReadLogErrors($path)
{
    If(test-path $path)
    {
        $fileObj = @()
        $contents = Get-Content -Path $path
        For($x=0;$x -lt $contents.Count;$x++)
        {
            if(($contents[$x] -like "*failed*" -or $contents[$x] -like "*unable*") -and $contents[$x] -notlike "*processing event*")
            {
                $fileObj += [pscustomobject]@{"Date/Time"=$contents[$x].Substring(0,23);"Reason"=$contents[$x].Substring(27).Trim()} 
            }
        }
        return $fileObj 
    }
    Else
    {
        Write-Host "Could not access $path"
    }
}
New-Alias "oprle" OpCon_ReadLogErrors

Function OpCon_ReadSAMLogEvents($path)
{
    If(test-path $path)
    {
        $fileObj = @()
        $contents = Get-Content -Path $path
        For($x=0;$x -lt $contents.Count;$x++)
        {
            if($contents[$x] -like "*processing event*" -and $contents[$x] -notlike "*processing events*")
            {
                $fileObj += [pscustomobject]@{"Date/Time"=$contents[$x].Substring(0,23);"Event"=$contents[$x].Substring(43,$contents[$x].IndexOf("Received") - 44).Trim();"Location"=$contents[$x].Substring($contents[$x].IndexOf("Received")).Trim()} 
            }
        }
        return $fileObj 
    }
    Else
    {
        Write-Host "Could not access $path"
    }
}
New-Alias "oprslev" OpCon_ReadSAMLogEvents

# Loads frequently used paths/connections
Function OpCon_LoadConfig($path)
{
    if(test-path $path)
    {
        $object = @()
        $getConfig = Get-Content $path | ForEach-Object{ 
                                                            if($_ -like "LOG*")
                                                            {
                                                                $object += [pscustomobject]@{"Type"="LOG";"Location"=($_.Split("="))[1]}
                                                            }
                                                            elseif($_ -like  "CONNECT*")
                                                            {
                                                                $object += [pscustomobject]@{"Type"="CONNECT";"Location"=($_.Split("="))[1];"Name"=$_.Substring($_.IndexOf("_")+1,$_.IndexOf("=")-($_.IndexOf("_")+1))}
                                                            }
                                                       }

        return $object
    }
    else
    {
        return Write-Host "Could not load OpConsole config:"$path
    }
}

# Gets scripts by name
function OpCon_GetScripts($url,$token,$scriptname,$scripttypename,$scriptids,$limit,$offset)
{
    $hdr = @{"authorization" = $token}

    $uriget = $url + "/api/scripts?scriptname=" + $scriptname

    try
    {
        $scripts = Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_.Exception
        Write-Host $_.Exception.Message
    }

    return $scripts
}
New-Alias "opgscripts" OpCon_GetScripts

# Gets all the versions of a script
function OpCon_GetScriptVersions($url,$token,$id)
{
    $hdr = @{"authorization" = $token}

    $uriget = $url + "/api/scripts/" + $id

    try
    {
        $scripts = Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_.Exception
        Write-Host $_.Exception.Message
    }

    return $scripts
}
New-Alias "opgscriptv" OpCon_GetScriptVersions

# Gets the details of a specific script version
function OpCon_GetScript($url,$token,$scriptId,$versionId)
{
    $hdr = @{"authorization" = $token}

    $uriget = $url + "/api/scripts/" + $scriptId + "/versions/" + $versionId

    try
    {
        $script = Invoke-RestMethod -Method GET -Uri $uriget -Headers $hdr -ContentType "application/json"
    }
    catch [Exception]
    {
        Write-Host $_.Exception
        Write-Host $_.Exception.Message
    }

    return $script
}
New-Alias "opgscript" OpCon_GetScript