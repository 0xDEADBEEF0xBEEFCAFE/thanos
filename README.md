# dns-flood
This is a fork of https://github.com/hawell/dns-flood/blob/master/dnsflood.c 

This is a modified version of DNS-Flood tool codename Thanos. The code should not be used in the wild for DOS but for educational, lab testing and verification purposes only.

Use raw sockets to generate DNS flood.

In contrast to fork version it provides:
 - Support additional query Type ANY



## How to run

Usage:
```bash
./dnsflood <query_name> <destination_ip> [options]  
	Options:  
	-t, --type		query type  
	-s, --source-ip		source ip  
	-p, --dest-port		destination port  
	-P, --src-port		source port  
	-i, --interval		interval (in microseconds) between two packets  
	-n, --number		number of DNS requests to send  
	-d, --duration		run for at most this many seconds   
	-r, --random-src	fake random source IP
	-R, --random-sub	prefix with random subdomain names
	-S, --dnssec		make a dnssec query
	-D, --daemon		run as daemon  
	-h, --help		print this message   
```
Example:
```bash

```

## Credits for original version

Original DNS-Flood tool found on code.google.com

Use raw sockets to generate DNS flood.

Original Here: https://code.google.com/p/dns-flood/
