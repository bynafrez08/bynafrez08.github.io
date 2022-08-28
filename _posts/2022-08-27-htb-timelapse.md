---
layout: single
title: HTB - Timelapse
excerpt: ""
date: 2022-08-27
classes: wide
header:
  teaser: /assets/images/
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

<p align = "center">
<img src = "/assets/images/img-timelapse/">
</p>

Machine matrix:

<p align = "center">
<img src = "/assets/images/img-pandora/matrix.png">
</p>

First we will create a directory with the name of the machine, and with ***mkt*** i will create the following directories to be able to move better the content of each one of those directories.

<p align = "center">
<img src = "/assets/images/img-pandora/captura1.png">
</p>

mkt is a function that i have defined in the ***~/.zshrc*** so that I can create these directories without creating them one by one.

```
mkt () {
        mkdir {nmap,content,exploits,scripts}
}
```

## Recognition

We send one icmp trace to the victim machine, and we can see that we have sent a packet and received that packet back. and through the TTL we can know that the target machine is linux. since linux machines have ttl 64 and windows machines have ttl 128. 

<p align = "center">
<img src = "/assets/images/img-pandora/captura2.png">
</p>

If you asking why when we receive the packet the ttl shows 63 instead of 64? this is because when we send icmp packet to the machine it goes through a series of intermediary nodes and this causes the ttl to decrease by one digit, and this process is known a traceroute. We can see this if we use the ***-R*** parameter.

<p align = "center">
<img src = "/assets/images/img-pandora/captura3.png">
</p>

Anyway i have a tool on my system called ***wichsystem*** that tells if the machine is linux or windows through the ttl.

<p align = "center">
<img src = "/assets/images/img-pandora/captura4.png">
</p>

Wichsystem script.

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

## Scanning

Now with nmap we are going to do the scanning process to know what's ports and services are running on the target machine, with the following parameters.

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

Basically i export the scan in grepable format because I have a function that i define in the ~/.zshrc which is the ***extractports*** function, basically it allows me to visualize the ports in a more elegant way and it copies the ports in the clipboard, so this is useful when we are scanning a target machine and it has to much ports and we don't need to write one by one to scan those ports.

<p align = "center">
<img src = "/assets/images/img-pandora/captura5.png">
</p>

The ***extractPorts*** script:

```bash
extractPorts () {
        ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
        ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
        echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
        echo -e "\t[*] IP Address: $ip_address" >> extractPorts.tmp
        echo -e "\t[*] Open ports: $ports\n" >> extractPorts.tmp
        echo $ports | tr -d '\n' | xclip -sel clip
        echo -e "[*] Ports copied to clipboard\n" >> extractPorts.tmp
        cat extractPorts.tmp
        rm extractPorts.tmp
}
```

## Ports Recognition and Enumeration

Once we have discovered possible ports, we will perform another scan to recognize the services and versions that use each of these ports. To order to do that we going to use the following parameters or flags:

|Flags|Description |  
|-----|------------|
|-sCV |Means that we want to use some nmap scripts, in this case to discover the version and services that are running each of those ports. 
|-p   |To specify the ports.           |
|-oN  |Save the scan in nmap format. 
