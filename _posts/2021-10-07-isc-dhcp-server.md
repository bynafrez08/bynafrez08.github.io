---
layout: single
title: Configure dhcp server in linux with isc-dhcp-server
excerpt: "we are going to learn how to configure a dhcp server in linux using the isc-dhcp-server service, we are going to learn how to create subnets and make reserved ips."
date: 2021-10-20
classes: wide
header:
  teaser: /assets/images/img-dhcp/servidor-DHCP-e1511228735448.png
  teaser_home_page: true
  icon: /assets/images/img-dhcp/ics_logo.png
categories:
  - Networking
  - Subnetting
tags:
  - dhcp
  - isc-dhcp-server
  - Linux
---

<p align = "center">
<img src = "/assets/images/img-dhcp/servidor-DHCP-e1511228735448.png">
</p>

we are going to learn how to configure a dhcp server in linux using the isc-dhcp-server service, we are going to learn: create a fixed ip for our server machine, create subnets, exclude ips ranges, create an ips address concession and finally make a reserved ip for a specific host with its mac address.
 
## What is a dhcp server?

Dynamic Host Configuration Protocol (DHCP), is a network management protocol that allows us to automatically assign IP addresses to client computers, default gateways, and other network parameters. allowing them to use network services such as DNS, NTP and any communication protocol based on UDP or TCP.

To understand more clearly how the dhcp protocol works, the following diagram shows us how it works:

<p align = "center">
<img src = "/assets/images/img-dhcp/dhcp.png">
</p>

## Installing dhcp-server and adding fix ip address in our server machine.
Before configuring the dhcp server, we are going to install it with the command: 

```
sudo apt-get install isc-dhcp-server
```

In my case I am going to assign a fixed IP address on the server machine. For this we will go to the path "/ etc / netplan" and then we will enter with the «nano» editor in the configuration file that haswithin that route. Inside the file we will put the following parameters:

<p align = "center">
<img src = "/assets/images/img-dhcp/captura2.png">
</p>

After we are going to save the changes to the file, we use the command "netplan apply" so that the ip is added to our server. And we use the command "ifconfig" to see if the ip address has been apply.

<p align = "center">
<img src = "/assets/images/img-dhcp/captura3.png">
</p>

## Configuring our dhcp sever  

Once we have configured an ip for our server, we will go to the file "/etc/default/isc-dhcp.server", where it says "interfacesv4 (ipv4 version)" we put the name of the network card where it will listen to the requests that we are going to configure. In my case I want it to assign the ips addresses in the "enp0s8" adapter on the client machines.

<p align = "center">
<img src = "/assets/images/img-dhcp/captura4.png">
</p>

We are going to create a subnet declaration specifying the ip range, open dhcp configure file ("/etc/dhcp/dhcpd.conf"). what we have to do inside a subnet declaration and then with the command «range» we will first put the lowest ip (in my case it is 10) the second the highest ip ( which in my case is 200).

<p align = "center">
<img src = "/assets/images/img-dhcp/captura6.png">
</p>

To add any changes it is important to ***restart*** the dhcp service with the command:

```
sudo service isc-dhcp-server restart
```

In the same configuration file we can establish the default time that an IP address is going to be lend (defualt-lease-time) and the second would be the maximum rental time of an IP address (max-lease-time). In my case, in both, the time is 1 and 3 hours, which I have indicated in seconds.

<p align = "center">
<img src = "/assets/images/img-dhcp/captura8.png">
</p>

If in the case that we want to exclude ip ranges, within the same subnet declaration, we are going to specify which range of ip we want to exclude, for example in my case what I did is within the subnet declaration is to add a new range ip that is from 10 to 49 and change the ip range that I put previously, in this case it is from 61 to 200, and with this we exclude the ip range from 50 to 60. 

<p align = "center">
<img src = "/assets/images/img-dhcp/captura7.png">
</p>

## Reserve ip for a host 

To reserve an IP with the mac address of a specific host, inside the dhcp configuration file we add a new host declaration (in my case I put the name of the client machine which is name "nafsuclient") and with the command «hardware ethernet "we put the client's mac address and with the command" fixed-address "we add the ip that we want to assign for that machine. once we done, save the file and restart de dhcp service.

<p align = "center">
<img src = "/assets/images/img-dhcp/captura9.png">
</p>

And this is my client machine, we can see that the mac address is the same as I have put in the configuration file.

<p align = "center">
<img src = "/assets/images/img-dhcp/captura10.png">
</p>

Before we have to make sure that the "isc-dhcp-client" service is installed on the client's machine. If in the case that it is not installed we execute the following command: 

```
sudo apt-get install isc-dhcp-client
```

In the client machine that we are going to reserve the IP, we are going to use the following command so that it can carry out the process of obtaining the IP, indicating the network adapter that will obtain the IP that we put on the server. 

<p align = "center">
<img src = "/assets/images/img-dhcp/captura12.png">
</p>

Then in the client machine, we turn off and on the adapter that will get the ip (in my case it is 8). 

<p align = "center">
<img src = "/assets/images/img-dhcp/captura13.png">
</p>

We use the "ifconfig" command on the client machine to verify that we have added the ip that we declared on the server. 

<p align = "center">
<img src = "/assets/images/img-dhcp/captura14.png">
</p>

In conclusion we have been able to learn some concepts of the dhcp protocol, and also how to administer the dhcp service in linux in a very easy and fasty way. 
