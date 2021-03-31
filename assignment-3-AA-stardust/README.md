# Lab 3: Respond to ARP

## Due Oct 30, 2020, 11:59PM (GMT+8)

## Overview

This is the first in a series of exercises that have the ultimate goal of creating an IPv4 router. The basic functions of an Internet router are to:

1. Respond to ARP (Address Resolution Protocol) requests for addresses that are assigned to interfaces on the router.
2. Make ARP requests for IP addresses that have no known Ethernet MAC address. A router will often have to send packets to other hosts, and needs Ethernet MAC addresses to do so.
3. Receive and forward packets that arrive on links and are destined to other hosts. Part of the forwarding process is to perform address lookups ("longest prefix match" lookups) in the forwarding information base. You will eventually just use "static" routing in your router, rather than implement a dynamic routing protocol like RIP or OSPF.
4. Respond to Internet Control Message Protocol (ICMP) messages like echo requests ("pings").
5. Generate ICMP error messages when necessary, such as when an IP packet's TTL (time to live) value has been decremented to zero.

The goal of this first stage of building the router is to accomplish item **#1** above: respond to ARP requests.

## Your Tasks

In the source directory for this exercise, there is a Python file to use as a starter template: `myrouter.py`. This file contains the outline of a Router class, and currently contains a constructor (`__init__`) method and a `router_main` method. This is just a starter template: you can refactor and redesign the code in any way you like.

The main task for this exercise is to modify the Router class to do the following:

> **[NOTE]**
> The sentences marked with ✅ are related to the content of your report. Please pay attention.

### Task 1: Preparation

Initiate your project with our template.

[Start the task here](preparation.md)

### Task 2: Handle ARP Requests

Ready to make ARP work.

[Start the task here](handle-arp-request.md)

### Task 3: Cached ARP Table

Maintain a correlation between each MAC address and its corresponding IP address.

[Start the task here](arp-table.md)

## Handing it in

### Report

We will provide a template of your lab assignment report [here](https://github.com/NJUCS-Networklabs-20fall/NetworkReport). You need to submit the report in your repository named `<学号><姓名>_lab_3`. The format of your report can be Microsoft Doc or PDF. An example is `123456789拾佰仟_lab_3.pdf`.

### Submit to GitHub Classroom

To submit your work, you need to do the following things.

1. Modify your code and complete your report.

2. When you have done your work, put your report and code in the folder `lab_3` then commit them. An example is `123456789/lab_3`. Finally your project will look like

   ```
   Your repo
     ├─.../
   + ├─lab_3/
   + │ ├─123456789拾佰仟_lab_3.pdf
   + │ ├─myrouter.py
     │ ├─...
   + │ └─start_mininet.py
     ├─.gitignore
     └─...
   ```

  > **[WARNING]**
  > The file names in your submission have to **exactly** match the file names above. Otherwise, you will lose points!

3. Submit your work by pushing your local repository to your remote repository by running the command `git push`.

  > **[WARNING]**
  > **Only** commit your source code and other necessary files to your local repository. If some generated files are not source code, ignore them by adding them in the file `.gitignore`.
