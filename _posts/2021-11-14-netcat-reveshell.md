---
layout: single
title: Reverse shell using netcat
excerpt: "We are going to learn how we can reverse shell in every OS, and some netcat commands that can help us when we are pentesting or scanning our environment."
date: 2021-11-14
classes: wide
header:
  teaser: /assets/images/img-netcat/netcat.jpg
  teaser_home_page: true
  icon: /assets/images/img-netcat/logo.png
categories:
  - Networking
  - Pentest
tags:
  - netcat
  - Linux
  - reverse shell
---

<p align = "center">
<img src = "/assets/images/img-netcat/netcat.jpg">
</p>

We are going to learn how we can reverse shell in every OS, and some netcat commands that can help us when we are pentesting or scanning our environment.

We are going to learn:

+ What is netcat
+ Basics netcat commands
+ Web server in netcat
+ What is reverse shell
+ Create a reverse shell in netcat
+ Reverse shell using scripts and payloads

## What is netcat?

Netcat ***(The Network Swiss Army knife)*** it is a command line tool that reads and writes data over network connections using TCP, allows us to open TCP and UDP ports for listening and allows us to scan ports similar to nmap but with some limitations. The main use of this tool is in reverse shell.

## Basics netcat commands

On linux systems netcat is installed by default and if it is not installed we use the following command:

```
sudo apt install netcat
```
In some Windows versions it is not installed by default, so we have to install the file called nc.exe.

With the ***-help*** parameter we can see the possibilities that netcat offers us and if we want to know more information about each parameter is to use the command ***man*** to see the netcat documentation. 

<p align = "center">
<img src = "/assets/images/img-netcat/captura1.png">
</p>

Scan ports. we can specify port ranges to report if any of those port ranges are open. it doesn't do a full scan like nmap, but it reports back to the console if the port we specified is open or not.

With the parameter ***-z*** we indicate that we only search for open ports, without sending any data.

The parameter ***-n*** we indicate only ip adress, no dns names.

The parameter ***-v*** it's for verbose, that we tell it to report back to us everything that is happening on the console.

<p align = "center">
<img src = "/assets/images/img-netcat/captura2.png">
</p>

With the ***-u*** parameter we specify that we want to scan udp ports.

<p align = "center">
<img src = "/assets/images/img-netcat/udp.png">
</p>

We can specify that only ports that are open or successful will be reported by the console with the command ***grep***.

<p align = "center">
<img src = "/assets/images/img-netcat/captura3.png">
</p>

Netcat allows us to communicate with client machines via tcp, as if it were a kind of chat to communicate.

On the attacker's machine I am going to listen on port 5000 with the parameter ***-l (listen)***. If the client machine is connected to our server it will report us by console and we can send messages.

<p align = "center">
<img src = "/assets/images/img-netcat/captura4.png">
</p>

On the client machine from the terminal with the command ***nc*** we indicate the ip address of the server machine and the port that is listening, which in my case is 5000.

And we can see that I can see the messages that the server machine is sending me on the client machine.

<p align = "center">
<img src = "/assets/images/img-netcat/captura5.png">
</p>

Netcat allows us to do banner grabbing to get relevant information about a specific port or a specific page which service is running, the version, etc. In my case it will be port 80.

In this case as it is a port that runs http, I indicate with the command ***HEAD / HTTP/1.0*** that I want information about this service. If it returns ***200 ok*** it means that the scan has been done correctly and we can see that it reports the version of this service, the day it was created, etc. And this as attackers allows us to find possible exploits that may have a port.

<p align = "center">
<img src = "/assets/images/img-netcat/captura6.png">
</p>

If it does not work with "HTTP/1.0" or is not reporting concrete information on port 80, we can use the command ***/HEAD /HTTP/1.1***. This is because the http port may be running http 1.1.

<p align = "center">
<img src = "/assets/images/img-netcat/captura7.png">
</p>

Another famous use of netcat is to be able to transfer files over the network via tcp. although this is insecure as we can do the same thing via ssh. but it is another alternative to be able to transfer files over the network fast wey.

So in this case i am gon a create a file with the following massege, and I am going to listen on port 4444 specifying with ***"<"*** that i want to transfer this file when a machine wants to connect to me on port 4444.

<p align = "center">
<img src = "/assets/images/img-netcat/captura8.png">
</p>

On the client machine who will receive the file, we will specify with parameter ***-w*** is to wait 2 seconds before canceling the transfer if there is a loss of connection, we specify the ip address and the port of the server machine, and with ">" we specify that we are going to receive the file indicating the name of that file. As we can see that on the client machine the file has been received correctly and we can view the contents of the file.

<p align = "center">
<img src = "/assets/images/img-netcat/captura9.png">
</p>

## What is a reverse shell?

A reverse shell consists of creating a remote connection from the shell of the victim machine to the attacker's machine, reverse shell is the concept of access to the victim's shell with the ip address.

For example, in our local network there is a router that inside has the firewall configured and we as attackers it is difficult to try to access the network because it is protected by the firewall. Then our objective is to access remotely on the victim machine, for example, I want to access through the terminal or shell to do things through commands, but the firewall protects us by denying those types of access. Then we can make the victim connect to us to remotely access his terminal, this concept is known as reverse shell. 

<p align = "center">
<img src = "/assets/images/img-netcat/reverse.png">
</p>

## Create a reverse shell in netcat

So what we would do with netcat is that the victim connects on the attacker's machine on port 4444 via tcp. and on the victim machine we will connect via netcat with the ip address specifying the port that we have chosen on the attacker's machine and with the parameter "-e " we make it return a shell in this case bash on the attacker's machine.

<p align = "center">
<img src = "/assets/images/img-netcat/captura10.png">
</p>

In the attacker we are going to listen in on the port 4444.

<p align = "center">
<img src = "/assets/images/img-netcat/captura11.png">
</p> 

And in the victim machine in my case can't not run the parameter "-e" and this happens because this parameter is insecure and there are some OS that you can not run this parameter, so I had to use some bash parameters to connect to the attacker's machine.
 
<p align = "center">
<img src = "/assets/images/img-netcat/captura12.png">
</p>

As we can see in the attacker's machine we are already connected to the shell of the victim machine.

<p align = "center">
<img src = "/assets/images/img-netcat/captura13.png">
</p>

We can indicate using script in bash to spawn a pseudo console to be able to use ctrl-c, ctrl v, to be able to handle us more comfortably in the remote shell. 

<p align = "center">
<img src = "/assets/images/img-netcat/captura14.png">
</p>

We do ctrl-z, type the following command and type "reset" to reset the terminal configuration.

<p align = "center">
<img src = "/assets/images/img-netcat/captura15.png">
</p>

we export two environment variables, so that we can use the terminal comfortably, like in ssh.

<p align = "center">
<img src = "/assets/images/img-netcat/captura16.png">
</p>

The other option is that we can execute this command on the victim machine to connect from the attacking machine. 

<p align = "center">
<img src = "/assets/images/img-netcat/captura17.png">
</p>

And the above command allows us to connect to the shell of the victim machine and automatically the pseudo console is applied to us. 

<p align = "center">
<img src = "/assets/images/img-netcat/captura18.png">
</p>

## Reverse shell in windows

On the attacking machine we listen in on port 8888 via TCP.

<p align = "center">
<img src = "/assets/images/img-netcat/captura19.png">
</p>

We perform the following command on the victim machine, with the parameter -e we are indicating the type of shell that we are going to report on the attacker's machine, in this case being windows we will put ***cmd.exe***, we see that it reports me in the terminal that the port 8888 is open. It is important to mention that windows by default does not have netcat installed so we have to look for the netcat executable which is "nc.exe".

<p align = "center">
<img src = "/assets/images/img-netcat/captura20.png">
</p>

And on the attacker's machine we already have shell access to the windows machine.

<p align = "center">
<img src = "/assets/images/img-netcat/captura21.png">
</p>

## Reverse shell using scripts and payloads

***If we are attackers, how can we make the victim be able to execute these types of commands on his computer? or it could also be that he does not have netcat installed on his computer.*** 

To do this there are a lot of scripts that we can run on the victim's machine. An example we can send the victim a malicious email that he press a button and the script runs automatically and we can gain access as attackers. This term is known as RAT (remote administration tool) is a method that hackers use to remotely access to the victim's machine, but i will cover this in the another article, since here we are talking about reverse shell.

For example in my case I am going to run a script on the victim machine so that I can access the powershell of the victim machine on my attacker machine. So on the attacker's machine I am going to listen on port 3001.

<p align = "center">
<img src = "/assets/images/img-netcat/captura22.png">
</p>

To provide the size of the terminal on the attacking machine we are going to execute the following command to know the size of our terminal. and this command varies if we put the terminal minimized or in full window. 

<p align = "center">
<img src = "/assets/images/img-netcat/captura25.png">
</p>


In the victim machine in the powershell I am executing the script. Basically what I'm doing is to say that I want to run the following script that is in github, with the parameter ***remoteip*** I indicate the ip of the attacking machine and with the parameter ***remoteport*** I indicate the port that is listening, which is my case is the port 3001. And with the parameter ***rows and cols*** I indicate how I want to display the size of the shell in my attacker terminal.

<p align = "center">
<img src = "/assets/images/img-netcat/captura23.png">
</p>

We do ctrl+z and as before I recommend to use this command so that we can move better in the remote terminal.

<p align = "center">
<img src = "/assets/images/img-netcat/captura26.png">
</p>

And as we can see thanks to the previous command that we have executed we can use ctrl + c, to move better in the remote shell from our attacker's machine. 

<p align = "center">
<img src = "/assets/images/img-netcat/captura27.png">
</p>

In conclusion we have been able to learn how attackers can access our systems in an easier way. and it is also important to know how to use netcat if we are system administrators or are auditing a company and also these techniques are needed to know if we are doing ctf's in hack the box, tryhackme.
