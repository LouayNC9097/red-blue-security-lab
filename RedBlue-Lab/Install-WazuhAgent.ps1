<#
    Install-WazuhAgent.ps1
    One-file Wazuh agent installer for the red/blue lab.

    Run this on the TARGET machine (WinServer 2022 or WindowsClient Win11)
    from an Administrator PowerShell.

    Examples:
      .\Install-WazuhAgent.ps1 -AgentName winsrv-01 -AgentGroup windows,servers
      .\Install-WazuhAgent.ps1 -AgentName wincli-01 -AgentGroup windows,endpoints

    It does the whole job and then tells you whether it worked.
#>

[CmdletBinding()]
param(
    # Wazuh manager (your SIEM-Ubuntu VM) on the isolated lab network.
    [string]$ManagerIP = '10.0.0.40',

    # Agent name. Must be unique. Defaults to the machine hostname.
    [string]$AgentName,

    # Groups. These are ENFORCED on the manager - they decide what config
    # your agent gets. Do not use them for descriptive tags.
    [string]$AgentGroup = 'windows',

    [string]$MsiUrl = 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.8-1.msi',

    # Registration port (authd) on the manager. The agent also needs 1514 for events.
    [int]$ManagerPort = 1514,
    [int]$RegistrationPort = 55000,

    # Optional: pre-shared key, if you have enabled API key auth on the manager.
    # Leave empty for the simple, recommended lab setup.
    [string]$RegistrationPassword,

    # Set -SkipDownload if you already copied the MSI onto the machine.
    [switch]$SkipDownload
)

$ErrorActionPreference = 'Stop'

function Write-Step  { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Ok    { param($m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Bad   { param($m) Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Write-Info  { param($m) Write-Host "  [info] $m" -ForegroundColor Gray }

# ---------------------------------------------------------------- 0. admin
Write-Step 'Checking administrator rights'
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Bad 'This script must run as Administrator.'
    Write-Info 'Right-click PowerShell -> Run as administrator, then run it again.'
    exit 1
}
Write-Ok 'Running elevated'

# ------------------------------------------------- 1. name and local identity
if (-not $AgentName) { $AgentName = $env:COMPUTERNAME.ToLower() }
Write-Step 'Agent identity'
Write-Info "Agent name : $AgentName"
Write-Info "Manager     : $ManagerIP"
Write-Info "Group(s)    : $AgentGroup"

$ip = Get-NetIPAddress -AddressFamily IPv4 |
      Where-Object { $_.IPAddress -notlike '127.*' -and
                     $_.IPAddress -notlike '169.254.*' } |
      Select-Object -First 1
if ($ip) { Write-Info "This host   : $($ip.IPAddress) on $($ip.InterfaceAlias)" }

# ------------------------------------------------- 2. can we reach the manager?
Write-Step 'Testing the path to the manager'
foreach ($port in @($ManagerPort, $RegistrationPort)) {
    $t = Test-NetConnection -ComputerName $ManagerIP -Port $port -WarningAction SilentlyContinue
    if ($t.TcpTestSucceeded) { Write-Ok "Port $port reachable at $ManagerIP" }
    else {
        Write-Bad "Cannot reach $ManagerIP`:$port"
        Write-Info "The agent needs $ManagerPort (events) and $RegistrationPort (enrolment)."
        Write-Info 'On the manager, both are opened by the Wazuh service itself.'
    }
}

# --------------------------------------------------------- 3. download the MSI
$msi = Join-Path $env:TEMP 'wazuh-agent.msi'

if ($SkipDownload) {
    Write-Step 'Skipping download'
} else {
    Write-Step 'Downloading the Wazuh agent'
    Write-Info $MsiUrl
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $MsiUrl -OutFile $msi -UseBasicParsing
        $kb = [math]::Round((Get-Item $msi).Length / 1KB)
        Write-Ok "Downloaded ($kb KB) -> $msi"
    } catch {
        Write-Bad "Download failed: $($_.Exception.Message)"
        Write-Info 'No internet on this NIC? Copy the MSI across manually and re-run with -SkipDownload'
        exit 1
    }
}

# ------------------------------------------------------------ 4. install it
Write-Step 'Installing silently'
Write-Info 'This takes 30-60 seconds.'

$log = Join-Path $env:TEMP 'wazuh-msi.log'
# NOTE: do not name this $args - that is a PowerShell automatic variable.
$msiArgs = @(
    '/i', $msi, '/quiet', '/norestart', '/l*v', $log,
    "WAZUH_MANAGER=$ManagerIP",
    "WAZUH_MANAGER_PORT=$ManagerPort",
    "WAZUH_REGISTRATION_SERVER=$ManagerIP",
    "WAZUH_REGISTRATION_PORT=$RegistrationPort",
    "WAZUH_AGENT_NAME=$AgentName",
    "WAZUH_AGENT_GROUP=$AgentGroup"
)
if ($RegistrationPassword) {
    $msiArgs += "WAZUH_REGISTRATION_PASSWORD=$RegistrationPassword"
}
$p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru

switch ($p.ExitCode) {
    0       { Write-Ok 'MSI returned 0 (success)' }
    3010    { Write-Ok 'Installed, reboot required' }
    1618    { Write-Bad 'Another install is in progress. Reboot and retry.'; exit 1 }
    1638    { Write-Bad 'A newer version is already installed.'; exit 1 }
    default { Write-Bad "MSI failed, exit code $($p.ExitCode). Log: $log"; exit 1 }
}

# --------------------------------------------- 5. service auto-start + running
# NOTE: the service is called WazuhSvc, NOT "Wazuh". Getting this name wrong
# is the single most common failure when scripting the Wazuh agent on Windows.
Write-Step 'Setting the service to start automatically'
$svc = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Bad 'Service "WazuhSvc" not found after install. Check the MSI log.'
    exit 1
}
Set-Service -Name 'WazuhSvc' -StartupType Automatic
Start-Service -Name 'WazuhSvc'
Start-Sleep -Seconds 5
$svc = Get-Service -Name 'WazuhSvc'
if ($svc.Status -eq 'Running') { Write-Ok "WazuhSvc is $($svc.Status), start type $($svc.StartType)" }
else { Write-Bad "WazuhSvc is $($svc.Status)" }

# ---------------------------------------------------------- 6. firewall rule
Write-Step 'Opening the firewall for the agent'
$existing = Get-NetFirewallRule -DisplayName 'Wazuh Agent 1514' -ErrorAction SilentlyContinue
if ($existing) {
    Write-Ok 'Rule already present'
} else {
    New-NetFirewallRule -DisplayName 'Wazuh Agent 1514' `
        -Direction Inbound -Action Allow -Protocol TCP `
        -LocalPort 1514 -Profile Any | Out-Null
    Write-Ok 'Created inbound rule on TCP 1514'
}

# ------------------------------------------------------ 7. verify registration
# The agent writes to ossec.log, NOT wazuh-agent.log. The latter only appears
# on Linux. Looking for the wrong file is why "I can't see the log" is common.
Write-Step 'Reading the agent log for registration'
$agentLog = 'C:\Program Files (x86)\ossec-agent\ossec.log'

Start-Sleep -Seconds 12
if (Test-Path $agentLog) {
    $tail = Get-Content $agentLog -Tail 40

    $registered = $tail | Select-String 'Enrolled new agent|Registered successfully|Valid registration'
    if ($registered) {
        $registered | Select-Object -Last 3 | ForEach-Object { Write-Ok $_.Line.Trim() }
    } else {
        Write-Info 'No successful registration line yet.'
    }

    if ($tail | Select-String 'ERROR') {
        Write-Bad 'Errors in the log:'
        ($tail | Select-String 'ERROR') | Select-Object -Last 5 |
            ForEach-Object { Write-Info $_.Line.Trim() }
        Write-Info 'Error 1208 = cannot reach the enrolment service on 55000.'
        Write-Info 'That is almost always the manager being down, or a firewall in the way.'
    }
} else {
    Write-Info "Log not found yet at $agentLog"
}

# --------------------------------------------------------- 8. configuration
# The real settings live in ossec.conf (wazuh-agent.conf is for
# osquery.conf-style local overrides and is usually not what you want to read).
Write-Step 'What the agent is actually configured with'
$conf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
if (Test-Path $conf) {
    Get-Content $conf | Select-String '<server>|<address>|<port>|<agent_name>|<labels>' |
        Select-Object -First 10 | ForEach-Object { Write-Info $_.Line.Trim() }
} else {
    Write-Info "Config not found at $conf"
}

# ------------------------------------------------------------------ summary
Write-Step 'Summary'
$final = Test-NetConnection -ComputerName $ManagerIP -Port $ManagerPort -WarningAction SilentlyContinue
$svc = Get-Service -Name 'WazuhSvc'

Write-Host ""
Write-Host "  Agent name : $AgentName" -ForegroundColor White
Write-Host "  Service    : $($svc.Status) / $($svc.StartType)" -ForegroundColor White
Write-Host "  Manager    : $ManagerIP (port $ManagerPort reachable: $($final.TcpTestSucceeded))" -ForegroundColor White
Write-Host "  Installed  : $((Get-Item $msi -ErrorAction SilentlyContinue).LastWriteTime)" -ForegroundColor Gray
Write-Host ""

if ($svc.Status -eq 'Running' -and $final.TcpTestSucceeded) {
    Write-Host '  RESULT: agent is running and the manager is reachable.' -ForegroundColor Green
    Write-Host '  Next: open the Wazuh dashboard -> Agents. This machine should turn Active' -ForegroundColor Green
    Write-Host "  within about 30 seconds. Look for '$AgentName'." -ForegroundColor Green
} else {
    Write-Host '  RESULT: something is not right yet. See the [FAIL] lines above.' -ForegroundColor Red
    Write-Host '  Most common cause: wrong ManagerIP, or the manager is not running.' -ForegroundColor Red
}

Write-Host ""
Write-Host '  Local log to watch: ' -NoNewline
Write-Host 'C:\Program Files (x86)\ossec-agent\ossec.log' -ForegroundColor Cyan
Write-Host '  (ossec.log, not wazuh-agent.log - that filename is Linux-only)' -ForegroundColor DarkGray
Write-Host ''
