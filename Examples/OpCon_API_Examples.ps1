param(
    $opconmodule = "C:\OpConModule.psm1",
    $token = "Token 12345-1234-1234-1234-12345", # API token (or you can use a temporary token)
    $url = "https://<opcon server>"   # OpCon API Url ie: https://<opconserver>:9010
)

if(Test-Path $opconmodule)
{
    #Verify PS version is at least 3.0
    if($PSVersionTable.PSVersion.Major -ge 3)
    { Import-Module -Name $opconmodule -Force }  
    else
    {
        Write-Host "Powershell version needs to be 3.0 or higher!"
        Exit 100
    }
}
else
{
    Write-Host "Unable to import SMA API module!"
    Exit 100
}


## Skip self signed certs 
OpCon_SkipCerts

#API Version check, also verifies connectivity
#OpCon_APIVersion -url $url

#Login for Token
#$id = "Token " + (OpCon_Login -url $url -user test_DEMO -password 0pC0nxp$).id #-appname $appname

#Checks SAM service status
#OpCon_SAMStatus -url $url -token $token

#User Example
$days = 30
OpCon_GetUser -url $url -token $token -username "" | ForEach-Object{
    if($_.psobject.properties.name -match "lastLoggedIn") 
    { 
        if((Get-Date -Date ($_.lastLoggedIn.Substring(6,$_.lastLoggedIn.IndexOf(",")-6)) -format "YYYY-MM-dd") -le (Get-Date -date ((Get-Date).AddDays(-$days)) -format "YYYY-MM-dd"))
        { OpCon_UpdateUser -url $url -token $token -username $_.loginName -field "isDisabled" -value $true }
    }
}

#OpCon_UpdateUser -url $url -token $token -username "test_DEMO" -field "name" -value "Roundtable Demo"
#OpCon_GetUserByComment -url $url -token $token -comment "TEST"

#Global Property Example
#OpCon_GetGlobalProperty -url $url -token $token -name '$date'
#OpCon_CreateGlobalProperty2 -url $url -token ************ -name "test5" -value "test" #-encrypt $encrypt 

#Calendar Example
#[System.Collections.ArrayList]$dates = (OpCon_GetCalendar -url $url -token $token -name "Master Holiday").dates
#$dates.Remove("1/19/2009")
#OpCon_UpdateAllCalendarDates -url $url -token $token -name "Master Holiday" -dates $dates
#OpCon_CreateCalendar -url $url -token $token -name "Test API" -dates '"5/11/2017","12/25/2017"'

#Threshold Examples
#OpCon_CreateThreshold -url $url -token $token -name "Test" -value "1"
#OpCon_GetThreshold -url $url -token $token -name "Test"
#OpCon_SetThreshold -url $url -token $token -name "Test" -value "+1"

#Resource Examples
#OpCon_CreateResource -url $url -token $token -name "Test" -value "1"
#OpCon_GetResource -url $url -token $token -name "DemoAuditFiles"
#OpCon_SetResource -url $url -token $token -name "DemoAuditFiles" -value "+1" 

#Job Action examples
#OpCon_JobAction -url $url -token $token -sname "ROUNDTABLE_BRUCE JERNELL" -jname "OPCON API EXAMPLE" -action "JOB:GOOD" -date (Get-Date -Format "MM/dd/yyyy")

#Gets information about a daily job
#OpCon_GetDailyJob -url $url -token $token | FOrmat-Table Schedule,JobName #-sname "SMAUtility" -jname "AUDIT HISTORY PURGE" -date (Get-Date -Format "MM/dd/yyyy")
#OpCon_GetDailyJob -url $url -token $token -sname "Adhoc" -jname "Set Failure SLA"
#OpCon_GetDailyJob -url $url -token $token -sname "ENVIRONMENT_MACHINES[MACHINES SUBSCHEDULE]" -jname "*" #-date "12-15-2018"
#OpCon_GetJobOutput -url $url -token $token -sname "SMAUtility" -jname "Audit History Purge" #default is todays date

#Job Info examples
#OpCon_GetDailyJobsBySchedule -url $url -token $token -date (Get-Date -Format MM-dd-yyyy) -schedule SMAUtility
#OpCon_GetDailyJobsByStatus -url $url -token $token -status "FAILED" -date (Get-Date -Format MM-dd-yyyy)
#OpCon_GetDailyJobsCountByStatus -url $url -token $token
#$id = (OpCon_GetDailyJobs -url $url -token $token -filter "name=SMA DATABASE BACKUP*").id

#Schedule Action examples
#OpCon_GetSchedule -url $url -token $token -sname "SMAUtility" -date (Get-Date -Format MM-dd-yyyy)
#OpCon_GetSchedule -url $url -token $token -sname $temp -date (Get-Date -Format MM-dd-yyyy)
#OpCon_ScheduleAction -url $url -token $token -sname $temp -jname "TEST JOB" -jfreq "OnRequest" -action "JOB:ADD" -reason "Testing api"
#OpCon_ScheduleAction -url $url -token $token -sid "20171117|227|1" -action "JOB:ADD" -date (Get-Date -Format MM-dd-yyyy) -jname "GENERATE LIST OF EVENT ATTENDEES" -jfreq "Sun-Sat-O"
#OpCon_ScheduleAction -url $url -token $token -sname "TEST" -jname "TEST JOB" -jfreq "OnRequest" -action "JOB:ADD" -reason "Testing api"
#OpCon_ScheduleAction -url $url -token $token -sname "TEST" -action "SCHEDULE:HOLD" -reason "Testing api" -date (Get-Date -Format MM-dd-yyyy)
#OpCon_ScheduleAction -url $url -token $token -sname "ADHOC" -action "SCHEDULE:BUILD" -date "8/10/2017" #-jname "PLACEHOLDER" -jfreq "SMASun-SatO7" -reason "Testing api" -date "8/10/2017" -sid "20170810|32000|1"

#Machine examples
#OpCon_CreateAgent -agentname "Test" -agenttype "Windows" -agentsocket "3100" -agentjors "3110" -token $token -url $url
#OpCon_UpdateAgent -agentname "Test" -field "allowKillJob" -value true -token $token -url $url
#OpCon_SubmitMachineAction -agentname "Test" -action "down" -url $url -token $token
#OpCon_GetAgent -url $url -token $token -agentname "LOCALHOST"
#OpCon_GetAgent -url $url -token $token | Out-GridView -Title "OpCon Agents"

#Standard function for returning job output, a custom function may be required if there are multiple output files
#OpCon_GetJobOutput -url $url -token $token -sname "SMAUtility" -jname "SMA DATABASE BACKUP" -date (Get-Date -Format MM-dd-yyyy) #).jobInstanceActionItems[0]
#OpCon_GetJobOutput -url $url -token $token -sname "ENVIRONMENT" -jname "LOAD ENVIRONMENT PROPERTIES" -date (Get-Date -Format MM-dd-yyyy)
#OpCon_GetJobOutput -url $url -token $token -sname "ADHOC" -jname "VPN CONNECT" -date (Get-Date -Format MM-dd-yyyy)

#Schedule Builds
#OpCon_ScheduleBuild -url $url -token $token -schedules "TEST" -dates "9/6/2019;9/7/2019"

#Schedule count by status
#OpCon_ScheduleCountByStatus -url $url -token $token #-dates $dates -name $name #-failedJobs $failedJobs -categories $categories

#Gets input field information from a Self Service button
#OpCon_GetSSInput -url $url -token $token -button "Send document"

#Scripts
<#
$id = OpCon_GetScripts -url $url -token $token -scriptname "API_Demo"
$latest = OpCon_GetScriptVersions -url $url -token $token -id $id[0].id
(OpCon_GetScript -url $url -token $token -versionId $latest.versions[-1].id).content | Invoke-Expression
#>
