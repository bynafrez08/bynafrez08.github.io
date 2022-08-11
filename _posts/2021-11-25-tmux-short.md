---
layout: single
title: Tmux Shortcuts
excerpt: "Tmux is a tool that allows us to divide a terminal in several panes and also to speed up when we are working in the console with different functions and shortcuts."
date: 2021-11-25
classes: wide
header:
  teaser: /assets/images/tmux/tmux22.png
  teaser_home_page: true
  icon: /assets/images/
categories:
  - zsh
tags:
  - tmux
  - linux
---

<p align = "center">
<img src = "/assets/images/tmux/tmux22.png">
</p>

Tmux is a tool that allows us to divide a terminal in several panes and also to speed up when we are working in the console with different functions and shortcuts. tmux sessions are persistent, which means that programs running in tmux will continue to run if we get disconnect our computer.

## How works?

Tmux is a multiplexer terminal, the term multiplexer is a term used in telecommunications where multiple signals converge into one. And this term in tmux means that we can use multiple terminals in a single terminal.

<p align = "center">
<img src = "/assets/images/tmux/multiplexer.png">
</p>

To use tmux we have to understand these concepts: sessions, windows, panes

The sessions are collection of virtual consoles managed by tmux that the session can have one or more windows associate, the window occupy the entire terminal screen and can be devided into a rectangular regions called panes, and in the panes is execute multiple virtual consoles.

The tmux architecture is client/server, when we execute the tmux command in our terminal, there are gonna be two process that are executing, one for the client and one for the server, these processes can communicate with each other by sending commands.

The functions of the client is to send to the server the commands that we want tmux to execute, create sessions, windows and panels that the server is going to manage. While the tmux server is responsable for executing the commands it receives from the client and managing our sessions and virtual consoles. And thanks to this architecture, if the client process is finish, the server will continue executing the tasks in the background and this allows us to recover the sessions in the case that we have closed the terminal or shutdown our computer.

<p align = "center">
<img src = "/assets/images/tmux/arctmux.png">
</p>

So if you list the processes on your machine, your are gonna see processes like "tmux: client" which is the client of the tmux (we are the clients) and tmux which is the tmux server.

For example if we need to connect via ssh into a particular server or machine and we are opening several terminals and make sevaral ssh connections to that server, we can use tmux and it will make our life easier and we don't need to open another terminal and connect to the server via ssh.

## Tmux shortcuts

Prefix

```
ctrl + b 
```
Create session

```
tmux new -s "nameofthesession"  
```

List session

```
tmux ls 
```
Change session name

```
prefix + $  
```

Kill session

```
tmux kill-session -t [name]  
```
Enter a session

```
tmux attach -t [name] 
```

Save the session

```
prefix + d
```

Another wey to save a session if we are in on that particular session.

```
prefix + shift + : = "detach" 
```
Rename window

```  
ctrl + b + , 
```
Create a window

```
ctrl + b + c  
```
Move from windows

```
ctrl + b + 1,2,3,4  
```
Vertical panel

```
ctrl + b + shift + 2 
```
Panel in horizontal position

```
ctrl + b + shift + 5   
```
Move the second panel in horizontal or in vertical.

```
ctrl + b + space
```
See the hour in the panel.

```
prefix + t 
```
If we want to write in the panel 1,2,3,4 use this shortcut. 

```
prefix + arrows - ↑ - ↓ - ← - →  
```

Delete bash o zsh window

```
prefix + & 
```

Resize the panel, (hold the ctrl key and use the arrows) 

```
prefix + arrows ↑ and ↓, if we have horizontal panel to resize use ← and →
```

View the sessions, panes and windows that we have created and their contents, we can use this shortcut if we are in a prevoius tmux session and we do not want to leave that session to list the available sessions.

```
prefix + s 
```
Another way to view sessions with hierarchy. We can use both shortcuts to move betweeen sessions, we simply select the sessions that we want with the arrows key and press enter. I presonally recommend using this shortcut since it shows us the sessions and their window in a hierarchical wey.

```
prefix + w 
```

Delete a session if we are inside a previous session of tmux and we don't want to leave that session.

```
prefix + s + [Select the session that u want to delete with the arrows] + x + y (yes option)
```

To see the number of panes, This is useful if we dont what is the order of the panel.

```
prefix + q  
```
Move the content of a panel in another.

```
prefix + {} ("{" means right and "}" left)
```
Allows you to move the contents of the panes in a clockwise direction.

```
prefix + o 
```

Use the mouse on the tmux session, so you can move through panes and split panels with the mouse like in terminator. To disable this option, use the same shurcut. Personally i don't recommend use this shortcut because the main function of tmux is using shortcuts with the keyboard so that we are much faster and more versatility using the terminal.

```
prefix + m
```
Unify or compact windows.

```
prefix + shift + : write this command "join-pane -s (window we are currently in) 1 -t (and in the window we want to move) 2" -> join-pane -s 1 -t 2
```

Copy the content of a file or some command output. 

```
prefix + [ (copy mode), ctrl + space (selection mode), alt + w (copy content), prefix + ] (paste content in the clipboard or in a file)   
```
Search for info using filters.

```
prefix + [ (copy mode) + ctrl + s + Write what u are searching for + enter
```

If we want to scroll up some output of a command we can use the copy mode to do that.

```
prefix + alt + [ (copy mode) - ctrl + u (if we want to sroll up slowly) - Repag (if u want to scroll up fast) - Avpag (if u want to scroll down fast, this is useful when we need to copy some output on the terminal) 
```

Window swap, for example if u want window 2 to be in window 1.

```
prefix + shift + : = "swap-window -s 2(current window) -t 1 (window you want to move)  
```

Move a pane in a new window.

```
prefix + shift + 1 
```

Zoom a particular pane to view better the content of that pane. Use the same shortcut if u want to disable the zoom mode.

```
prefix + z
```

## Bonus

Concatenate files with micro

```
cat /etc/passwd | micro
```
Create a script using micro and it will detect the syntax in bash or zsh. 

```
micro script.sh 
```

See the modification of a file in another window in real time, like a live serve.

```
tail -f namefile 
```

## Tmux autopwn script

```bash
#!/bin/bash

time=1

read -p 'Put the session name: ' sessions
read -p 'First window name: ' firstwin
read -p 'Seconde window name: ' secondwin

tmux new-session -d -s "$sessions" && sleep $time # u can use the "-t" flag to put the num of the session on the name of the session.
tmux rename-window "$firstwin" && tmux split-window -v && tmux select-pane -t 1
#tmux new-window -t $sessions:2 -n "$secondwin"
tmux select-window -t 1
#---------------------------------------------------------------------------
tmux send-keys "ifconfig" C-m && sleep $time # -> "C-m" means that write the command and hide enter
#tmux send-keys "id" C-m && sleep $time # -> "send-keys" this command option is to send keystroke in the terminal
#tmux send-keys "ps -a" C-m && sleep $time
#tmux send-keys "ifconfig" C-m && sleep $time
tmux select-pane -t 2 && tmux send-keys "cat /etc/passwd" C-m && sleep $time # this line on the pane of the window 1 it gonna be execute "cat /etc/passwd"
#---------------------------------------------------------------------------
#tmux select-window -t 2 && sleep $time && tmux send-keys "cat /etc/group" C-m && sleep $time && tmux select-window -t 1 # -> this line it will execute the command "cat /etc/group" on the window 2
tmux new-window -t $sessions:2 -n "$secondwin" && sleep $time && tmux send-keys "cat /etc/group" C-m && sleep $time && tmux select-window -t 1 #if we want to create a new window and execute some command.
#---------------------------------------------------------------------------
tmux attach -t "$sessions"
```
