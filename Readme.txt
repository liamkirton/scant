================================================================================
Scant 0.4.10
Copyright ©2007-2008 Liam Kirton <liam@int3.ws>

7th April 2008
http://int3.ws/
================================================================================

=========
Overview:
=========

Scant is a small ARP, TCP and UDP scanner for Windows, built using Winpcap
(http://www.winpcap.org/), and designed for efficient parallel scanning of
network ranges.

===========
Parameters:
===========

/Device:
--------

The /Device parameter specifies the Winpcap device to use for scanning. Execute
Scant.exe without parameters to view a list of available devices.

/Target:
--------

The /Target parameter may contain several disjoint target strings separated by
semi-colons, e.g. "host.domain.tld;a.b.c.d;x.y.z.w".

Each target string may contain a host name, or an IP address taking the form
"a.b.c.d".

Each octet of each target string may contain one or more comma separated digits
or ranges, e.g. "a-b,c.d-e,f.g,h.i-j".

Each target string parameter may also specify a subnet in VLSM/CIDR notation,
e.g. "a-b,c.d-e,f.g,h.i/x".

Additionally, a host name may be specified together with a subnet
(e.g. "host.domain.tld/24"). This will resolve via DNS to a.b.c.d/24 and hence
the relevant network segment will be scanned.

/Resolve:
---------

The /Resolve parameter specifies that target IP addresses should be resolved.
This is done in parallel to the scan.

/Port:
------

The /Port parameter may contain one or more comma separated digits
or ranges, e.g. "a,b-c,d".

/Sport:
-------

The /Sport parameter specifies the source port from which to send outgoing
TCP & UDP packets.

/Arp, /Tcp, /Udp:
-----------------

These parameters specify the type of scan required. Either /Arp or a selection
of /Tcp or /Udp may be provided.

/Rst:
-----

The /Rst specifies that TCP RST packets should be sent in response to TCP SYN+ACK
responses.

/Queue:
-------

The /Queue parameter specifies the maximum number of packets to send out in each
packet round.

Default: 1024.

/Block:
-------

The /Block parameter specifies the number of packets to send out in a block for
each target. Only one block per target is sent per packet round.

Default: 1.

/Interval:
----------

The /Interval parameter specifies the millisecond interval between each packet
round.

Default: 15.

/Retry:
-------

The /Retry parameter specifies the number of attempts to rescan each
unresponsive port.

Default: 0.

/Ip, /Netmask, /Route:
----------------------

The /Ip parameter specifies the source address from which outgoing packets are
sent, /Netmask specifies the subnet mask for this address, and /Route
specifies the default route to use.

Default: Adapter default.

/Dummy:
-------

The /Dummy parameter specifies that no actual scanning should occur, potential
scanning actions are reported.

/Verbose:
---------

The /Verbose parameter specifies that TCP RST+ACK and ICMP packets should be
reported upon receipt (These are summarised at the end).

=========
Examples:
=========

Basic Scans:
------------

Scant.exe /Device 1 /Target 25.0.1.1 /Arp

Scamp.exe /Device 1 /Target host.domain.tld /Tcp /Port 1-1024 

Scant.exe /Device 1 /Target 25.0.1.1 /Tcp /Port 1-1024 

Scant.exe /Device 1 /Target 25.0.1.1 /Tcp /Rst /Port 53 /Sport 53 

Scant.exe /Device 1 /Target 25.0.1.1 /Udp /Port 1-1024

Parallel Scans:
---------------

Scant.exe /Device 1 /Target 25.0.0.0/24 /Arp

Scant.exe /Device 1 /Target 25.0-1.0-255.0/24 /Arp

Scant.exe /Device 1 /Target 25.0-1.0-255.0-255 /Tcp /Port 1-1024

Scant.exe /Device 1 /Target 25.0-1.0-255.0-255 /Tcp /Udp /Port 1-1024 /Verbose 

Advanced Parallel Scans:
------------------------

Scant.exe /Device 1 /Target 25.0-1.0-15,18-25,254.0-5,10,254 /Arp

Scant.exe /Device 1 /Target 25.0-1.0-15,18-25,254.0/24 /Tcp /Udp
          /Port 1-1024 /Interval 0 

Scant.exe /Device 1 /Target 25.0-1.0-15,18-25,254.0-5,10,254 /Tcp /Udp
          /Port 1-1024 /Interval 0 /Queue 2048 /Block 32

Scant.exe /Device 1 /Target 25.0-1.0-15,18-25,254.0-5,10,254;25.254.0.0-251,254
          /Tcp /Udp /Port 1-1024 /IP 25.62.0.1 /Netmask 255.192.0.0 /Route
          
================================================================================
