param(
    $opconmodule = "C:\OpCon_Module.psm1",
    $restapi,
    $token, 
    $url
)

if(Test-Path $opconmodule)
{
    #Verify PS version is at least 3.0
    if($PSVersionTable.PSVersion.Major -ge 3)
    { Import-Module -Name $opconmodule -Force #-Verbose  #uncomment this option to see a list of functions  }
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

##Needed when accessing a non-local OpCon API (Powershell v5.1 only)
#SMA_IgnoreSelfSignedCerts

#API Version check, also verifies connectivity
SMA_OpConAPIVersion -url $url


#Login for Token
#SMA_Login -url $url -user $user -password $password -appname $appname

#Checks SAM service status
#SMA_SAMStatus -url $url -token $token

#User Example
#SMA_GetUser -url $url -token $token -username "ocadm"
#SMA_UpdateUser -url $url -token $token -username "test_DEMO" -field "loginName" -value "zzztest_DEMO"
#SMA_GetUserByComment -url $url -token $token -comment "TEST"

#Global Property Example
#SMA_GetGlobalProperty -url $url -token $token -name "7ZIP*"
#SMA_CreateGlobalProperty2 -url $url -token ************ -name "test5" -value "test" #-encrypt $encrypt 

#Calendar Example
#[System.Collections.ArrayList]$dates = (SMA_GetCalendar -url $url -token $token -name "Master Holiday").dates
#$dates.Remove("1/19/2009")
#SMA_UpdateAllCalendarDates -url $url -token $token -name "Master Holiday" -dates $dates
#SMA_CreateCalendar -url $url -token $token -name "Test API" -dates '"5/11/2017","12/25/2017"'

#Threshold Examples
#SMA_CreateThreshold -url $url -token $token -name "Test" -value "1"
#SMA_GetThreshold -url $url -token $token -name "Test"
#SMA_SetThreshold -url $url -token $token -name "Test" -value "+1"

#Resource Examples
#SMA_CreateResource -url $url -token $token -name "Test" -value "1"
#SMA_GetResource -url $url -token $token -name "DemoAuditFiles"
#SMA_SetResource -url $url -token $token -name "DemoAuditFiles" -value "+1" 

#Job Action examples
#SMA_JobAction -url $url -token $token -sname "TEST" -jname "OPCON API SETUP" -action "JOB:GOOD" -date (Get-Date -Format MM-dd-yyyy)

#Gets information about a daily job
#SMA_GetDailyJob -url $url -token $token -sname "AMAZON ALEXA" -jname "PLACEHOLDER"
#SMA_GetDailyJOb -url $url -token $token -sname "Adhoc" -jname "Set Failure SLA"
#SMA_GetDailyJob -url $url -token $token -sname "ENVIRONMENT_MACHINES[MACHINES SUBSCHEDULE]" -jname "*" #-date "12-15-2018"
#SMA_GetJobOutput -url $url -token $token -sname "SMAUtility" -jname "Audit History Purge" #default is todays date

#Job Info examples
#SMA_GetDailyJobsBySchedule -url $url -token $token -date (Get-Date -Format MM-dd-yyyy) -schedule SMAUtility
#SMA_GetDailyJobsByStatus -url $url -token $token  #-status "FINISHED&20OK" -date (Get-Date -Format MM-dd-yyyy)
#SMA_GetDailyJobsCountByStatus -url $url -token $token
#$id = (SMA_GetDailyJobs -url $url -token $token -filter "name=SMA DATABASE BACKUP*").id
#SMA_GetDailyJob -url $url -token $token -sname "SMAUtility" -jname "SMA DATABASE BACKUP"

#Schedule Action examples
#SMA_GetSchedule -url $url -token $token -sname "SMAUtility" -date (Get-Date -Format MM-dd-yyyy)
#SMA_GetSchedule -url $url -token $token -sname $temp -date (Get-Date -Format MM-dd-yyyy)
#SMA_ScheduleAction -url $url -token $token -sname $temp -jname "TEST JOB" -jfreq "OnRequest" -action "JOB:ADD" -reason "Testing api"
#SMA_ScheduleAction -url $url -token $token -sid "20171117|227|1" -action "JOB:ADD" -date (Get-Date -Format MM-dd-yyyy) -jname "GENERATE LIST OF EVENT ATTENDEES" -jfreq "Sun-Sat-O"
#SMA_ScheduleAction -url $url -token $token -sname "TEST" -jname "TEST JOB" -jfreq "OnRequest" -action "JOB:ADD" -reason "Testing api"
#SMA_ScheduleAction -url $url -token $token -sname "TEST" -action "SCHEDULE:HOLD" -reason "Testing api" -date (Get-Date -Format MM-dd-yyyy)
#SMA_ScheduleAction -url $url -token $token -sname "ADHOC" -action "SCHEDULE:BUILD" -date "8/10/2017" #-jname "PLACEHOLDER" -jfreq "SMASun-SatO7" -reason "Testing api" -date "8/10/2017" -sid "20170810|32000|1"

#Machine examples
#SMA_CreateAgent -agentname "Test" -agenttype "Windows" -agentsocket "3100" -agentjors "3110" -token $token -url $url
#SMA_UpdateAgent -agentname "Test" -field "allowKillJob" -value true -token $token -url $url
#SMA_SubmitMachineAction -agentname "Test" -action "down" -url $url -token $token
#(SMA_GetAgent -url $url -token $token | Where-Object{ $_.agentName }).type.description | Sort-Object -Unique #-agentname "Localhost"

#Standard function for returning job output, a custom function may be required if there are multiple output files
#(SMA_GetJobOutput -url $url -token $token -sname "SMAUtility" -jname "SMA DATABASE BACKUP" -date (Get-Date -Format MM-dd-yyyy)).jobInstanceActionItems[0]
#SMA_GetJobOutput -url $url -token $token -sname "ENVIRONMENT" -jname "LOAD ENVIRONMENT PROPERTIES" -date (Get-Date -Format MM-dd-yyyy)
#SMA_GetJobOutput -url $url -token $token -sname "ADHOC" -jname "VPN CONNECT" -date (Get-Date -Format MM-dd-yyyy)

#Schedule Builds
#SMA_ScheduleBuild -url $url -token $token -schedules "TEST" -dates "9/6/2019;9/7/2019"

#Schedule count by status
#SMA_ScheduleCountByStatus -url $url -token $token #-dates $dates -name $name #-failedJobs $failedJobs -categories $categories

#Gets input field information from a Self Service button
#SMA_GetSSInput -url $url -token $token -button "Send document"