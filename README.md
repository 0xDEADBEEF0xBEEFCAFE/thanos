# dns-flood-ng

This is modified version od DNS-Flood tool. 

In contrast to original tool it provides:
  - subdomain part of query randomization aka DNS Water Torture
  - source port and TTL randomization
  - additional query types like AAAA and MX

The tool is able to bypass Radware DefensePro SW version prior to 8.x.

## How to install

1. Clone Repo
2. Run Make
3. Enjoy Kittens
 
## How to run

```
Usage: ./dnsflood <query_name> <destination_ip> [options]  
	Options:  
	-t, --type		query type  
	-s, --source-ip		source ip  
	-p, --dest-port		destination port  
	-P, --src-port		source port  
	-i, --interval		interval (in millisecond) between two packets  
	-n, --number		number of DNS requests to send  
	-r, --random		fake random source IP  
	-D, --daemon		run as daemon  
	-h, --help  
```

## Credits for original version

Original DNS-Flood tool found on code.google.com

Use raw sockets to generate DNS flood attack.

Original Here: https://code.google.com/p/dns-flood/
