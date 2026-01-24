https://app.hackthebox.com/machines/Archetype?tab=play_machine

┌──(cchopin◉ Mac-Studio)-[~/projets-git/ctf-toolkit/challenges/HTB/Sherlocks/PhishNet][main]
└─$ nmap 10.129.36.251 -T4
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-23 21:18 +0100
Nmap scan report for 10.129.36.251
Host is up (0.024s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 6.76 seconds


──(cchopin◉ Mac-Studio)-[~/projets-git/ctf-toolkit/challenges/HTB/Sherlocks/PhishNet][main]
└─$ nmap 10.129.36.251 -A -p 135,139,445,1433,5985
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-23 23:19 +0100
Nmap scan report for 10.129.36.251
Host is up (0.024s latency).

PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-01-23T20:17:27
|_Not valid after:  2056-01-23T20:17:27
|_ssl-date: 2026-01-23T23:19:53+00:00; +1h00m00s from scanner time.
| ms-sql-ntlm-info:
|   10.129.36.251:1433:
|     Target_Name: ARCHETYPE
|     NetBIOS_Domain_Name: ARCHETYPE
|     NetBIOS_Computer_Name: ARCHETYPE
|     DNS_Domain_Name: Archetype
|     DNS_Computer_Name: Archetype
|_    Product_Version: 10.0.17763
| ms-sql-info:
|   10.129.36.251:1433:
|     Version:
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h36m00s, deviation: 3h34m40s, median: 59m59s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2026-01-23T23:19:48
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb-os-discovery:
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-01-23T15:19:46-08:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.39 seconds
┌──(cchopin◉ Mac-Studio)-[~/projets-git/ctf-toolkit/challenges/HTB/Sherlocks/PhishNet][main]
└─$

┌──(cchopin◉ Mac-Studio)-[~/projets-git/ctf-toolkit/challenges/HTB/Sherlocks/PhishNet][main]
└─$ # Scan SMB complet pour un pentest
nmap -p 139,445 -sV --script="smb-* and not smb-brute and not smb-flood" --script-args="unsafe=1" 10.129.36.251 -oA smb_scan
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-23 23:24 +0100
Nmap scan report for 10.129.36.251
Host is up (0.025s latency).

PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-enum-sessions:
|   Users logged in
|_    ARCHETYPE\sql_svc since <unknown>
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
| smb-mbenum:
|_  ERROR: Call to Browser Service failed with status = 2184
| smb-vuln-cve2009-3103:
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|
|     Disclosure date: 2009-09-08
|     References:
|       http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_smb-print-text: false
| smb-os-discovery:
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-01-23T15:24:14-08:00
|_smb-vuln-ms10-054: ERROR: Script execution failed (use -d to debug)
| smb-psexec: Can't find the service file: nmap_service.exe (or nmap_service).
| Due to false positives in antivirus software, this module is no
| longer included by default. Please download it from
| https://nmap.org/psexec/nmap_service.exe
|_and place it in nselib/data/psexec/ under the Nmap DATADIR.
|_smb-system-info: ERROR: Script execution failed (use -d to debug)
| smb-protocols:
|   dialects:
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2.0.2
|     2.1
|     3.0
|     3.0.2
|_    3.1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.18 seconds


venv) ┌──(cchopin◉ Mac-Studio)-[~/projets-git/ctf-toolkit/tools/enum4linux-ng][master]
└─$ python3 enum4linux-ng.py -A 10.129.36.251
ENUM4LINUX - next generation (v1.3.7)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.129.36.251
[*] Username ......... ''
[*] Random Username .. 'hqceeozc'
[*] Password ......... ''
[*] Timeout .......... 10 second(s)

 ======================================
|    Listener Scan on 10.129.36.251    |
 ======================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ============================================================
|    NetBIOS Names and Workgroup/Domain for 10.129.36.251    |
 ============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ==========================================
|    SMB Dialect Check on 10.129.36.251    |
 ==========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:
  SMB 1.0: true
  SMB 2.0.2: true
  SMB 2.1: true
  SMB 3.0: true
  SMB 3.1.1: true
Preferred dialect: SMB 3.0
SMB1 only: false
SMB signing required: false

 ============================================================
|    Domain Information via SMB session for 10.129.36.251    |
 ============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: ARCHETYPE
NetBIOS domain name: ''
DNS domain: Archetype
FQDN: Archetype
Derived membership: workgroup member
Derived domain: unknown

 ==========================================
|    RPC Session Check on 10.129.36.251    |
 ==========================================
[*] Check for anonymous access (null session)
[+] Server allows authentication via username '' and password ''
[*] Check for guest access
[+] Server allows authentication via username 'hqceeozc' and password ''
[H] Rerunning enumeration with user 'hqceeozc' might give more results

 ====================================================
|    Domain Information via RPC for 10.129.36.251    |
 ====================================================
[-] Could not get domain information via 'lsaquery': STATUS_IO_TIMEOUT

 ================================================
|    OS Information via RPC for 10.129.36.251    |
 ================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows Server 2019 Standard 17763
OS version: '10.0'
OS release: '1809'
OS build: '17763'
Native OS: Windows Server 2019 Standard 17763
Native LAN manager: Windows Server 2019 Standard 6.3
Platform id: null
Server type: null
Server type string: null

 ======================================
|    Users via RPC on 10.129.36.251    |
 ======================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED

 =======================================
|    Groups via RPC on 10.129.36.251    |
 =======================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED

 =======================================
|    Shares via RPC on 10.129.36.251    |
 =======================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user

 ==========================================
|    Policies via RPC for 10.129.36.251    |
 ==========================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 ==========================================
|    Printers via RPC for 10.129.36.251    |
 ==========================================
[-] Could not get printer info via 'enumprinters': timed out

Completed after 33.02 seconds


(venv) ┌──(cchopin◉ Mac-Studio)-[~/projets-git/ctf-toolkit/tools/smbmap/smbmap][master]
└─$ smbclient -N -L \\\\10.129.37.16
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	backups         Disk
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
(venv) ┌──(cchopin◉ Mac-Studio)-[~/projets-git/ctf-toolkit/tools/smbmap/smbmap][master]
└─$ smbclient -N -L \\\\10.129.37.16\\backups
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	backups         Disk
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
(venv) ┌──(cchopin◉ Mac-Studio)-[~/projets-git/ctf-toolkit/tools/smbmap/smbmap][master]
└─$
