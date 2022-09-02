---
layout: single
title: HTB - Timelapse
excerpt: "Timelapse is a windows machine with easy level of difficulty in the exploitation phase and mediumn the escalation of privileges. first we need to crack a protected zip file using john and then crack an pfx file that contain inside of that zip file in order to extracting the certificate and key from the pfx file..." 
date: 2022-08-27
classes: wide
header:
  teaser: /assets/images/img-timelapse/portada.png
  teaser_home_page: true
  icon: /assets/images/
categories:
  - CTF  
tags:
  - Hack the box
  - Samba 
  - Openssl
  - WinRM
  - Laps
---

Timelapse is a windows machine with easy level of difficulty in the exploitation phase and mediumn the escalation of privileges. first we need to crack a protected zip file using john and then crack an pfx file that contain inside of that zip file in order to extracting the certificate and key from the pfx file, and with the certificate we are able to access to the target machine using evil-winrm. For the privilege escalation we are going to switch with another user that have assign in the LAPS group in order to dump all the users passwords including of the admins.

<p align = "center">
<img src = "/assets/images/img-timelapse/portada.png">
</p>

Machine matrix:

<p align = "center">
<img src = "/assets/images/img-timelapse/matrix.png">
</p>

First we will create a directory with the name of the machine, and with ***mkt*** i will create the following directories to be able to move better the content of each one of those directories.

<p align = "center">
<img src = "/assets/images/img-timelapse/captura1.png">
</p>

mkt is a function that i have defined in the ***~/.zshrc*** so that I can create these directories without creating them one by one.

```
mkt () {
        mkdir {nmap,content,exploits,scripts}
}
```

We send one icmp trace to the victim machine, and we can see that we have sent a packet and received that packet back. and through the TTL we can know that the target machine is windows. since linux machines have ttl 64 and windows machines have ttl 128. The ttl can decrement by one unit because there are intermediate nodes from our machine to the target machine and this is known as traceroute, that's why in the output we can see 127 instead of 128. with the ***-R*** parameter we can see those nodes in the case of linux machines in windows will not work.

<p align = "center">
<img src = "/assets/images/img-timelapse/captura2.png">
</p>


## Scanning

Here is our first nmap scan using the following parameters:

|Flags|Description |  
|-----|----------- |
|-p-  |Means that we want to scan all the ports that exists in tcp and udp which is in total 65,535 ports.|
|-sS  |Means that we want tcp syn scan.           |
|--min-rate 5000 | Means we just want to send packets no slower then 5000 packets per second to discover ports, and with that parameter our scan will be most faster. |
|--open | Means that we want only output the ports with the status open not filtred.
|-vvv | Means that we want to output more information.
|-n | Means we don't want DNS resolution, because sometimes the DNS resolution can take our scan much slower.
|-Pn | Means that we don't to ping to discover ports.
|-oG | Means that we want to save the scan in grapable format to not rescan again, you have more formats to save like nmap, xml, etc.

And this is all the open ports that we discoverd.

<p align = "center">
<img src = "/assets/images/img-timelapse/captura3.png">
</p>

Now once we discoverd those ports we are going to perform another scan to know whats services and versions are running in those ports using the following parameters:

|Flags|Description |  
|-----|------------|
|-sCV |Means that we want to use some nmap scripts, in this case to discover the version and services that are running each of those ports. 
|-p   |To specify the ports.           |
|-oN  |Save the scan in nmap format. 

The scan result:

```ruby
# Nmap 7.92 scan initiated Wed Aug 24 18:16:31 2022 as: nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49696,54208 -oN targeted 10.10.11.152
Nmap scan report for 10.10.11.152
Host is up (0.11s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2022-08-25 06:16:53Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2022-08-25T06:18:23+00:00; +8h00m02s from scanner time.
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49696/tcp open  msrpc             Microsoft Windows RPC
54208/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 8h00m01s, deviation: 0s, median: 8h00m01s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-08-25T06:17:44
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 24 18:18:24 2022 -- 1 IP address (1 host up) scanned in 112.67 seconds
```

## Enumeration

In this case if is a windows machine first thing i will do is identify the version of windows is running on the target system using ***crackmapexec***, here we can see the version that is running and a domain name ***timelapse.htb***.

<p align = "center">
<img src = "/assets/images/img-timelapse/captura5.png">
</p>

To resolve that domain we are going to add on the hosts file, because in some cases if we are going to perform some attack o enumeration it will requiere to put the domain name of the AD.

<p align = "center">
<img src = "/assets/images/img-timelapse/captura6.png">
</p>

Using ***smbclient*** using a null session we can see the list of shares that are available on the target machine, and we can see a particular share called ***shares*** that has no comments. 

<p align = "center">
<img src = "/assets/images/img-timelapse/captura7.png">
</p>

We can perform the same enumaration using ***smbmap*** and it will show us the permissions that are assign in each share. 

<p align = "center">
<img src = "/assets/images/img-timelapse/captura8.png">
</p>

Now let's access on the shares resource that we have read access using smbclient with a null session (-N). There is a two directories called ***Dev*** and ***Helpdesk***, if we access on the dev directorie there is a zip file and on the helpdesk directories there is an msi file and documents file named LAPS, so here we can think the... 

<p align = "center">
<img src = "/assets/images/img-timelapse/captura9.png">
</p>

