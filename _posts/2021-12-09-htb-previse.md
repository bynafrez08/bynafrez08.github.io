---
layout: single
title: HTB - Previse
excerpt: "Previse is a linux machine with difficulty esay pulling a little to medium both the level of intrusion and privilege escalation pulls a little to medium level of difficulty. this machine has vulnerabilities such as log poisoning and in the part of escalation we take advantage of nopasswd."
date: 2021-12-09
classes: wide
header:
  teaser: /assets/images/img-previse/portada.png
  teaser_home_page: true
  icon: /assets/images/
categories:
  - CTF
  - Pentest
tags:
  - Hack the box
  - Linux
  - reverse shell
---

Previse is a linux machine with difficulty esay pulling a little to medium both the level of intrusion and privilege escalation pulls a little to medium level of difficulty. this machine has vulnerabilities such as log poisoning and in the part of escalation we take advantage of nopasswd.

<p align = "center">
<img src = "/assets/images/img-previse/portada.png">
</p>

Machine rating according to the people.

<p align = "center">
<img src = "/assets/images/img-previse/cali.png">
</p>

Machine matrix:

<p align = "center">
<img src = "/assets/images/img-previse/matrix.png">
</p>

The first thing we are going to do is to create a file with the machine name, and inside of that file with ***mkt*** we are going to create to following directories. 

<p align = "center">
<img src = "/assets/images/img-previse/captura1.png">
</p>

## recognition

Now i am going to send a one icmp packet to know if i have connection to the victim machine, and to know what is the OS in the victim machine through the ***ttl***. If you that the windows systems have 128 ttl and the linux systems have 64 ttl.

<p align = "center">
<img src = "/assets/images/img-previse/captura2.png">
</p>

And in my case i have a function that is ***wichsystem*** that through the ttl reports me if it is a windows or linux machine.

<p align = "center">
<img src = "/assets/images/img-previse/captura3.png">
</p>

wichsystem script:

```python
#!/usr/bin/python3
#coding: utf-8
 
import re, sys, subprocess
 
# python3 wichSystem.py YOURIP 
 
if len(sys.argv) != 2:
    print("\n[!] Uso: python3 " + sys.argv[0] + " <direccion-ip>\n")
    sys.exit(1)
 
def get_ttl(ip_address):
 
    proc = subprocess.Popen(["/usr/bin/ping -c 1 %s" % ip_address, ""], stdout=subprocess.PIPE, shell=True)
    (out,err) = proc.communicate()
 
    out = out.split()
    out = out[12].decode('utf-8')
 
    ttl_value = re.findall(r"\d{1,3}", out)[0]
 
    return ttl_value
 
def get_os(ttl):
 
    ttl = int(ttl)
 
    if ttl >= 0 and ttl <= 64:
        return "Linux"
    elif ttl >= 65 and ttl <= 128:
        return "Windows"
    else:
        return "Not Found"
 
if __name__ == '__main__':
 
    ip_address = sys.argv[1]
 
    ttl = get_ttl(ip_address)
 
    os_name = get_os(ttl)
    print("\n%s (ttl -> %s): %s\n" % (ip_address, ttl, os_name))
```


When we ping the ttl it reports 63 but this is because there are intermediate nodes as we can see.

<p align = "center">
<img src = "/assets/images/img-previse/captura4.png">
</p>

## Scanning - Ports recognition

With nmap we will scan wich ports are open on the victim machine so that we can attack.

<p align = "center">
<img src = "/assets/images/img-previse/captura5.png">
</p>

Basically i report the scan in a grepable format because I have a function defined in the ***~/.zshrc*** called ***extractports*** that shows me the available ports in a much more elegant way and it copies the ports that we can paste it in the clipboard.

<p align = "center">
<img src = "/assets/images/img-previse/captura6.png">
</p>

Extractports script:

```bash
#!/bin/bash

function extractPorts(){
        ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
        ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
        echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
        echo -e "\t[*] IP Address: $ip_address"  >> extractPorts.tmp
        echo -e "\t[*] Open ports: $ports\n"  >> extractPorts.tmp
        echo $ports | tr -d '\n' | xclip -sel clip
        echo -e "[*] Ports copied to clipboard\n"  >> extractPorts.tmp
        cat extractPorts.tmp; rm extractPorts.tmp
}
```
Now with the ports we have discovered we will do another scan to find out what version and services are running on each of those ports.

```
# Nmap 7.91 scan initiated Mon Dec  6 17:36:15 2021 as: nmap -sCV -p22,80 -oN targeted 10.10.11.104
Nmap scan report for 10.10.11.104
Host is up (0.047s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec  6 17:36:26 2021 -- 1 IP address (1 host up) scanned in 10.48 seconds
```

With ***whatweb*** we can make a small recognition of the web service to know if the victim machine is using any cms and the web server that is using.

<p align = "center">
<img src = "/assets/images/img-previse/captura7.png">
</p>

I am access to the website and it is a login page that i dont have credentials to access and i can't create an account.

<p align = "center">
<img src = "/assets/images/img-previse/captura8.png">
</p>

Looking at the page code i don't see anything interesting.

<p align = "center">
<img src = "/assets/images/img-previse/captura9.png">
</p>

Now with nmap i am going to do a simple fuzzing to see potential routes, but i didn't find any shit and its because nmap its not to powerful to fuzzing.

```
# Nmap 7.91 scan initiated Mon Dec  6 17:42:20 2021 as: nmap --script http-enum -p80 -oN Webscan 10.10.11.104
Nmap scan report for 10.10.11.104
Host is up (0.044s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /login.php: Possible admin folder
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|_  /js/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'

# Nmap done at Mon Dec  6 17:42:29 2021 -- 1 IP address (1 host up) scanned in 9.51 seconds
```
Now with ***wfuzz*** we are going to perform fuzzing using a dictionary to see more potential routes and it is also more powerful than nmap.

<p align = "center">
<img src = "/assets/images/img-previse/captura11.png">
</p>

In the word ***FUZZ*** I am going to indicate the php extension so that it looks for paths containing the php extension, and i found some interesting paths

<p align = "center">
<img src = "/assets/images/img-previse/captura12.png">
</p>

And basically when accessing each of those routes it does not let me show the content.

<p align = "center">
<img src = "/assets/images/img-previse/captura13.png">
</p>

As the ftp service was open i try to access if the user ***anonymous*** was enabled, but in this case it is not enabled.

<p align = "center">
<img src = "/assets/images/img-previse/captura14.png">
</p>

Ok so in the login page i tried to test if the web was vulnerable to sql injections, and we can see it's not.

<p align = "center">
<img src = "/assets/images/img-previse/captura15.png">
</p>

I try to apply virtual hosting to see if there is any change in the web if it is with the domain name, and if i can access in the php paths i found above.

<p align = "center">
<img src = "/assets/images/img-previse/captura16.png">
</p>

But as we can see i can't view tha content each of the php paths. 

<p align = "center">
<img src = "/assets/images/img-previse/captura17.png">
</p>

So then i use burpsuite if i can see anything, and as we can see in the route ***accounts.php*** there is a form to sing up on the website. 

<p align = "center">
<img src = "/assets/images/img-previse/captura18.png">
</p>

If you look at the response part of the code of the page, we see that the http server returns a status code ***302*** which means that the resource we have solved was found, but not in the expected place, basically it is used for the temporary redirection of the url. So thinking a little bit what would happen if we change tha http status code with 200 (which is successful)? let's try.

<p align = "center">
<img src = "/assets/images/img-previse/captura19.png">
</p>

Then what we will do is intercept that request before sending it to the server, so in burpsuite in the ***intercept*** section we right click and select ***"Do intercept -> Response to this request"***.

<p align = "center">
<img src = "/assets/images/img-previse/captura20.png">
</p>

We are going to put ***200*** and then click in ***forward***

<p align = "center">
<img src = "/assets/images/img-previse/captura21.png">
</p>

And magic!!!, now we can access in "accounts.php" and now we go to create an account anN click on ***submit***, and in burpsuite we click on ***forward*** or send the request that we have modified to the server.

<p align = "center">
<img src = "/assets/images/img-previse/captura22.png">
</p>

Now close tha proxy, and we are going to try login with the account that we have created.

<p align = "center">
<img src = "/assets/images/img-previse/captura23.png">
</p>

And boom!! we can access on the website.

<p align = "center">
<img src = "/assets/images/img-previse/captura24.png">
</p>

If we go to the ***files*** section we see that there are interesting files as you can see we can download the files and we can also upload files, We are going to download the 3 files.

<p align = "center">
<img src = "/assets/images/img-previse/captura25.png">
</p>

Let's unzip the the backup file.

<p align = "center">
<img src = "/assets/images/img-previse/captura26.png">
</p>

So in the ***config.php*** we have mysql database credentials, that we are going to save this credentials for letter.

<p align = "center">
<img src = "/assets/images/img-previse/captura27.png">
</p>

Ok so in the ***revshell.php*** file we see that a reverse shell is being applied using netcat and php code for command execution.

<p align = "center">
<img src = "/assets/images/img-previse/captura28.png">
</p>

And in the file ***combinazione.txt*** we can see the admin credentials idk, i don't find this useful this file.

<p align = "center">
<img src = "/assets/images/img-previse/captura29.png">
</p>

On the web it reports that the mysql server is active and that there are 11 admin users logged in, and 3 files uploaded.

<p align = "center">
<img src = "/assets/images/img-previse/captura30.png">
</p>

And in the ***log data*** part i download a .log file, let's see what it is.

<p align = "center">
<img src = "/assets/images/img-previse/captura31.png">
</p>

And we see that the file contains logs of the users who have uploaded the files or who have registered, well we see that there is a user called ***m4lwhere***.

<p align = "center">
<img src = "/assets/images/img-previse/captura32.png">
</p>

## Explotation

I came up with an idea is to make a reverse shell inside a php file and upload it on the web to see if I can connect to the machine on port "4444".

<p align = "center">
<img src = "/assets/images/img-previse/captura33.png">
</p>

It lets me upload the file but unfortunately i can't connect to the machine.

<p align = "center">
<img src = "/assets/images/img-previse/captura34.png">
</p>

I trying to make a reverse shell with python.

<p align = "center">
<img src = "/assets/images/img-previse/captura35.png">
</p>

But it doesn't work anyway.

<p align = "center">
<img src = "/assets/images/img-previse/captura36.png">
</p>

Well thinking about it a bit, as before we could download the logs i thought of intercepting the request in burpsuite when downloading the log to see if we can see something.

<p align = "center">
<img src = "/assets/images/img-previse/captura36.png">
</p>

In the burpsuite in the request part there is a parameter called ***delim=comma***.

<p align = "center">
<img src = "/assets/images/img-previse/captura37.png">
</p>

Well so we are going to establish reverse shell with bash on the port 4444 in the ***delim=comma** parameter. And click on ***forward or send*** to send the request we have just modified.

<p align = "center">
<img src = "/assets/images/img-previse/captura38.png">
</p>

We can do tha same process with python.

<p align = "center">
<img src = "/assets/images/img-previse/captura39.png">
</p>

And on our attacker machine we see that we have a connection on the victim machine. 

<p align = "center">
<img src = "/assets/images/img-previse/captura40.png">
</p>

Now we are as the user "www-data" and do ***cat /etc/passwd*** we see all the users of the victim machine. Ok so let's access to the home directory of the user ***m4lwhere***.

<p align = "center">
<img src = "/assets/images/img-previse/captura41.png">
</p>

I access the home directory of the user m4lwhere and we see that the first flag is there, but i can't see the content because i don't have permissions.

<p align = "center">
<img src = "/assets/images/img-previse/captura42.png">
</p>

Well let's access to the mysql database, since we have the credentials from the ***config.php*** file we downloaded earlier.

<p align = "center">
<img src = "/assets/images/img-previse/captura43.png">
</p>

We can see that there are an database called ***previse***, let's access on that database and we can see there two tables called ***account***, huhuhu let's see what is there on that table.

<p align = "center">
<img src = "/assets/images/img-previse/captura44.png">
</p>

And gentlemens as we can see we have usernames and passwords. and well i also see my credentials when i created the account which is the user ***test101***.

<p align = "center">
<img src = "/assets/images/img-previse/captura45.png">
</p>

As the password is hashed we are going to crack it with ***john***. The first thing I'm going to do is to unzip the file where the ***rockyou.txt***, because we are going to use it this dictionary.

<p align = "center">
<img src = "/assets/images/img-previse/captura46.png">
</p>

What we do is with john specify the dictionary ***rockyou.txt*** and then what i have done is to put the hashed password of the user m4lwhere in the file called ***hash.txt***. As it is an md5-crypt hash it reports in terminal that we must specify the format.

<p align = "center">
<img src = "/assets/images/img-previse/captura47.png">
</p>

Here are some of the most commonly used hashes, but there are other types of hashes.

<p align = "center">
<img src = "/assets/images/img-previse/hashes.png">
</p>

Now specify the hash type and wait for it to finish cracking the password using the ***rockyou.txt*** dictionary. And we can see the hash is cracked and we found the password.

<p align = "center">
<img src = "/assets/images/img-previse/captura48.png">
</p>

With john let's visualize the password better way.

<p align = "center">
<img src = "/assets/images/img-previse/captura49.png">
</p>

And with the password obtained we can see that I can access via ssh in the user ***m4lwhere***.

<p align = "center">
<img src = "/assets/images/img-previse/captura50.png">
</p>

And as we are with the user ***m4lwhere*** we can visualize the first flag.

<p align = "center">
<img src = "/assets/images/img-previse/captura51.png">
</p>

## Privilege Escalation

With the command ***sudo -l*** we are going to check which commands we can execute with the privileges in this case of root we can execute without using the password. And we can see that we can execute a script as the user ***root***, let's check that script.

reference = https://book.hacktricks.xyz/linux-unix/privilege-escalation#nopasswd

<p align = "center">
<img src = "/assets/images/img-previse/captura52.png">
</p>

Basically the script must store the logs using gzip and that there are backups that is a task that should have been configured with cron, as commented in the comments of the script.

<p align = "center">
<img src = "/assets/images/img-previse/captura53.png">
</p>

After analyzing the script and investigating a little, there is a possible vulnerability that we can exploit that is the ***path injection***. this attack is based on changing the value of variable ***$PATH***, this variable contains the paths where certain programs or commands run on our systems, so if we want our malicious script to run in ***/tmp*** or ***/dev/shm*** we must change the path so that it can run. normally by default are in / "usr/bin".

what we will do it's go inside a directory that we have permissions of sudo in this case can be the ***/tmp*** or ***/dev/shm***, then we will create our small script execute so that it returns us a revershell through netcat, we assign permissions to our script and finally we will change the variable ***$path***.

<p align = "center">
<img src = "/assets/images/img-previse/captura54.png">
</p>

We going to listen on port 4444 with netcat, now with sudo we are going to execute the script ***access_backup*** in the same path where we were. And SIUUUUUUUU we have connection with root user. 

<p align = "center">
<img src = "/assets/images/img-previse/captura55.png">
</p>	

So we are going to the root path, and as you can see we can view the second flag.

<p align = "center">
<img src = "/assets/images/img-previse/captura56.png">
</p>

