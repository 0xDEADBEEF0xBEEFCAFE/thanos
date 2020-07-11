#define _DEFAULT_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

 #include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/wait.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

#define	  CLASS_INET 1

enum dns_type {
	TYPE_A = 1,
	TYPE_NS,		//2
	TYPE_MD,		//3
	TYPE_MF,		//4
	TYPE_CNAME,		//5
	TYPE_SOA,		//6
	TYPE_MB,		//7
	TYPE_MG,		//8
	TYPE_MR,		//9
	TYPE_NULL,		//10 
	TYPE_WKS,		//11 
	TYPE_PTR,		//12 
	TYPE_HINFO,		//13
	TYPE_MINFO,		//14
	TYPE_MX,		//15 
	TYPE_TXT,		//16
	TYPE_AAAA = 0x1c,
};

typedef struct type_name{
	uint16_t type;
	char typename[8];
} type_name_t;

type_name_t dns_type_names [] = {
	{TYPE_A, "A"},
	{TYPE_NS, "NS"},			
	{TYPE_MD, "MD"},			
	{TYPE_MF, "MF"},			
	{TYPE_CNAME, "CNAME"},		
	{TYPE_SOA, "SOA"},			
	{TYPE_MB, "MB"},			
	{TYPE_MG, "MG"},			
	{TYPE_MR, "MR"},			
	{TYPE_NULL, "NULL"},		
	{TYPE_WKS, "WKS"},			
	{TYPE_PTR, "PTR"},			
	{TYPE_HINFO, "HINFO"},		
	{TYPE_MINFO, "MINFO"},		
	{TYPE_MX, "MX"},			
	{TYPE_TXT, "TXT"},			
	{TYPE_AAAA, "AAAA"},		
};

#define DNS_TYPE_NUM (sizeof(dns_type_names) / sizeof(type_name_t))

struct dnshdr {
	unsigned short int id;

	unsigned char rd:1;			/* recursion desired */
	unsigned char tc:1;			/* truncated message */
	unsigned char aa:1;			/* authoritative answer */
	unsigned char opcode:4;		/* purpose of message */
	unsigned char qr:1;			/* response flag */

	unsigned char rcode:4;		/* response code */
	unsigned char unused:2;		/* unused bits */
	unsigned char pr:1;			/* primary server required (non standard) */
	unsigned char ra:1;			/* recursion available */

	unsigned short int que_num;
	unsigned short int rep_num;
	unsigned short int num_rr;
	unsigned short int num_rrsup;
};

#define OPT_TYPE 41

uint16_t get_type(const char *type)
{
	int i;
	for (i = 0; i < DNS_TYPE_NUM; i++) {
		if (strcasecmp(type, dns_type_names[i].typename) == 0) {
			return dns_type_names[i].type;
		}
	}

	return 0;
}

unsigned short in_cksum(char *packet, int len)
{
	register int nleft = len;
	register u_short *w = (u_short *) packet;
	register int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */

	if (nleft == 1) {
		*(u_char *) (&answer) = *(u_char *) w;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

void usage(char *progname)
{
	printf("Usage: %s <query_name> <destination_ip> [options]\n"
			"\tOptions:\n"
			"\t-t, --type\t\tquery type\n"
			"\t-s, --source-ip\t\tsource ip\n"
			"\t-p, --dest-port\t\tdestination port\n"
			"\t-P, --src-port\t\tsource port\n"
			"\t-i, --interval\t\tinterval (in microsecond) between two packets\n"
			"\t-n, --number\t\tnumber of DNS requests to send\n"
			"\t-d, --duration\t\trun for at most this many seconds\n"
			"\t-r, --random-src\t\tfake random source IP\n"
			"\t-R, --random-sub\t\tprefix with random subdomain names\n"
			"\t-D, --daemon\t\trun as daemon\n"
			"\t-S, --dnssec\t\tenable dnssec\n"
			"\t-h, --help\n"
			"\n"
			, progname);
}

/*
 * RFC 1035 - https://www.ietf.org/rfc/rfc1035.txt
 *
 * 2.3.1. Preferred name syntax
 * 
 * Note that while upper and lower case letters are allowed in domain
 * names, no significance is attached to the case.  That is, two names with
 * the same spelling but different case are to be treated as if identical.
 *
 * The labels must follow the rules for ARPANET host names.  They must
 * start with a letter, end with a letter or digit, and have as interior
 * characters only letters, digits, and hyphen.  There are also some
 * restrictions on the length.  Labels must be 63 characters or less.
 *
 * For example, the following strings identify hosts in the Internet:
 *
 * A.ISI.EDU XX.LCS.MIT.EDU SRI-NIC.ARPA
 *
 * 2.3.4. Size limits
 *
 * Various objects and parameters in the DNS have size limits.  They are
 * listed below.  Some could be easily changed, others are more
 * fundamental.
 *
 * labels          63 octets or less
 *
 * names           255 octets or less
 *
 * TTL             positive values of a signed 32 bit number.
 *
 * UDP messages    512 octets or less
 */

/*
 * Return a valid random label string
 */
char *random_label(size_t len, char *r_label)
{
	const static char valid_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-";
	size_t charset_len = sizeof valid_chars - 1;
	size_t letter_len = sizeof valid_chars - 12;
	size_t letdig_len = sizeof valid_chars - 2;
	size_t n;

#ifdef DEBUG
	if (len > 63 || len < 1) {
		printf("Invalid label length: %d.\nLabels must be 63 characters or less.\n", (int)len);
		exit(1);
	}
#endif

	if (r_label) {
		// They must start with a letter.
		r_label[0] = valid_chars[random() % letter_len];
		// and have as interior characters only letters, digits, and hyphen.
		for (n = 1; n < (len - 1); n++) {
			r_label[n] = valid_chars[random() % charset_len];
		}
		// end with a letter or digit
		if (n < len)
			r_label[n] = valid_chars[random() % letdig_len];

		r_label[len] = '\0';

#ifdef DEBUG
		printf("Label: %02d %s\n", (int)strlen(r_label), r_label);
#endif

	}
	return r_label;
}

#define MAX_LABEL_LEN 10
#define MAX_LABEL_COUNT 2

void random_name(int len, int label_cnt, char *r_name)
{
	int i;

	label_cnt += (random() % (len / 64 + 1)) + 1;
	label_cnt %= MAX_LABEL_COUNT + 1;
#ifdef DEBUG
	printf("LabelCnt: %d\n", label_cnt);
#endif
	for (i = 0; i < label_cnt && len > 1; i++) {
		if (len > MAX_LABEL_LEN)
			random_label((random() % MAX_LABEL_LEN) + 1, r_name);
		else
			random_label((random() % len) + 1, r_name);
		strcat(r_name, ".");
		len -= strlen(r_name);
		r_name += strlen(r_name);
	}
}

void random_addr(char *addr)
{
	uint32_t r_addr = random();

	addr += snprintf(addr, 5, "%d.", (int)((r_addr >> 24 & 0xFD) + 1));
	addr += snprintf(addr, 5, "%d.", (int)(r_addr >> 16 & 0xFF));
	addr += snprintf(addr, 5, "%d.", (int)(r_addr >> 8 & 0xFF));
	snprintf(addr, 4, "%d", (int)((r_addr & 0xFD) + 1));
}

void nameformat(char *name, char *target)
{
	// max label length is 63, plus 1 byte of length, plus 1 byte '\0'
	char fullname[255];
	char *bungle = fullname;
	char *x = NULL;
	int cp_len;

	*target = 0;
	strcpy(bungle, name);
	x = strtok(bungle, ".");
	while (x != NULL) {
		cp_len = snprintf(target, 65, "%c%s", (int)strlen(x), x);
		if (cp_len >= 65) {
			puts("String overflow.");
#ifdef DEBUG
			printf("cpLen: %d, Len: %d, inStr: %s, cpStr: %s\n", cp_len, (int)strlen(x), x, target);
#endif
			exit(1);
		}
		target += cp_len;
		x = strtok(NULL, ".");
	}
}

void nameformat_ip(char *ip, char *target)
{
	char *comps[8];
	char fullptr[32];
	char *pbungle = fullptr;
	char *x = NULL;
	char ina[] = "in-addr";
	char end[] = "arpa";
	int px = 0;
	int cpLen;

	*target = 0;
	strcpy(pbungle, ip);
	x = strtok(pbungle, ".");
	while (x != NULL) {
		if (px >= 4) {
			puts("Force DUMP:: dumbass, wtf you think this is, IPV6?");
			exit(1);
		}
		comps[px++] = x;
		x = strtok(NULL, ".");
	}

	for (px--; px >= 0; px--) {
		cpLen = snprintf(target, 5, "%c%s", (int)strlen(comps[px]), comps[px]);
		if (cpLen >= 5) {
			puts("Invalid IP Address.");
#ifdef DEBUG
			printf("cpLen: %d, Len: %d, inStr: %s, cpStr: %s\n", cpLen, (int)strlen(comps[px]), comps[px], target);
#endif
			exit(1);
	}
		target += cpLen;
	}

	target += snprintf(target, sizeof(ina) + 2, "%c%s", (int)strlen(ina), ina);
	snprintf(target, sizeof(end) + 2, "%c%s", (int)strlen(end), end);
}

int make_question_packet(char *data, char *name, int type)
{
	if(type == TYPE_PTR)
		nameformat_ip(name, data);
	else
		nameformat(name, data);
       
	*((u_short *) (data + strlen(data) + 1)) = htons(type);

	*((u_short *) (data + strlen(data) + 3)) = htons(CLASS_INET);

	return (strlen(data) + 5);
}

int make_dnssec_packet(struct dnshdr *dns_header, char *opt_data)
{
	dns_header->num_rrsup = htons(1);
	*opt_data = 0; /* Name = <Root> */
	*( (u_short *) (opt_data+1) ) = htons(OPT_TYPE); /* RR Type = OPT(41) */
	*( (u_short *) (opt_data+3) ) = htons(4096); /* UDP Payload Size = 4096 */
	*( (u_long *)(opt_data+5) ) = htonl(0x8000); /* Z = 0x8000 (DO = 1) */
	*( (u_short *)(opt_data+9) ) = htons(0); /* Data len = 0 */
	return 11;
}

int read_ip_from_file(char *filename)
{
	return 0;
}

void urandom_init() {
	unsigned long mySeed;
	unsigned long *buf = &mySeed;
	int urandom_fd = open("/dev/urandom", O_RDONLY);

	if (urandom_fd >= 0) {
		ssize_t result = read(urandom_fd, buf, sizeof(long));
		if (result < 0)
			mySeed = 0x4a6f6273;
	} else {
		mySeed = 0x4a6f6273;
    }
	srandom((unsigned long) time(NULL) * getpid() + mySeed);
}


static int stop = 0;

void term(int signum) {
    printf("Stopping.. \n");
    stop = 1;
}

int main(int argc, char **argv)
{
	char qname[256] = {0};	/* question name */
	char r[256] = {0};
	uint16_t qtype = TYPE_A;
	struct in_addr src_ip = {0};	/* source address          */
	struct sockaddr_in sin_dst = {0};	/* destination sock address*/
	u_short src_port = 0;			/* source port             */
	u_short dst_port = 53;			/* destination port        */
	int sock;				/* socket to write on      */
	int number = 0;
	int duration = 0;
	int count = 0;
	double difft = 0;
	time_t start_t, end_t;
	struct sigaction action;
	int sleep_interval = 0;	/* interval (in microseconds) between two packets */
	int dnssec = 0;

	int src_opt = -2;
	int random_ip = 0;
	int random_sub = 0;
	int static_ip = 0;

	int arg_options;

	const char *short_options = "f:t:p:P:DrRSs:i:n:d:h";

	const struct option long_options[] = {
		{"type", required_argument, NULL, 't'},
		{"dest-port", required_argument, NULL, 'p'},
		{"file", required_argument, NULL, 'f'},
		{"src-port", required_argument, NULL, 'P'},
		{"daemon", no_argument, NULL, 'D'},
		{"random-src", no_argument, NULL, 'r'},
		{"random-sub", no_argument, NULL, 'R'},
		{"dnssec", no_argument, NULL, 'S'},
		{"source-ip", required_argument, NULL, 's'},
		{"interval", required_argument, NULL, 'i'},
		{"number", required_argument, NULL, 'n'},
		{"duration", required_argument, NULL, 'd'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	int quit = 0;
	const int on = 1;

	//char *from, *to, filename;
	//int itmp = 0;

	unsigned char packet[1500] = { 0 };
	struct ip *iphdr;
	struct udphdr *udp;
	struct dnshdr *dns_header;
	char *dns_data;

	// Initial random seed
	urandom_init();

	while ((arg_options = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {

		switch (arg_options) {

		case 'p':
			dst_port = atoi(optarg);
			break;

		case 'P':
				src_opt = atoi(optarg);
				if (src_opt >= 0)
					src_port = src_opt;
				else if (src_opt < -1)
					src_opt = -2;
			break;

		case 'i':
			sleep_interval = atoi(optarg);
			break;

		case 'n':
			number = atoi(optarg);
			break;

		case 'd':
			duration = atoi(optarg);
			break;
	
		case 'r':
			random_ip = 1;
			srandom((unsigned long)time(NULL));
				break;

			case 'R':
				random_sub = 1;
			break;

		case 'D':
			//TODO
			break;

		case 'S':
			dnssec = 1;
			break;

		case 'f':
			if (read_ip_from_file(optarg)) {
			}
			break;

		case 's':
				//static_ip = 1;
			inet_pton(AF_INET, optarg, &src_ip);
			break;

		case 't':
			qtype = get_type(optarg);
			if (qtype == 0) {
				printf("bad query type\n");
				quit = 1;
			}
			break;

		case 'h':
			usage(argv[0]);
			return 0;
			break;

		default:
			printf("CMD line Options Error\n\n");
			break;
		}
	}

	/* query name */
	if (optind < argc) {
		snprintf(qname, sizeof(qname), "%s", argv[optind]);
		strcpy(qname, argv[optind]);
	} else {
		quit = 1;
	}

	optind++;

	/* target IP */
	if (optind < argc) {
		inet_pton(AF_INET, argv[optind], &sin_dst.sin_addr);
	} else {
		quit = 1;
	}

	if (quit || !sin_dst.sin_addr.s_addr) {
		usage(argv[0]);
		exit(0);
	}

	/* check root user */
	if (getuid() != 0) {
		printf("This program must run as root privilege.\n");
		exit(1);
	}

	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		printf("\n%s\n", "Create RAW socket failed\n");
		exit(1);
	}

	if ((setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *) &on, sizeof(on)))
		== -1) {
		perror("setsockopt");
		exit(-1);
	}

	sin_dst.sin_family = AF_INET;
	sin_dst.sin_port = htons(dst_port);

	iphdr = (struct ip *)packet;
	udp = (struct udphdr *)((char *)iphdr + sizeof(struct ip));
	dns_header = (struct dnshdr *)((char *)udp + sizeof(struct udphdr));
	dns_data = (char *)((char *)dns_header + sizeof(struct dnshdr));

	/* the fixed fields for DNS header */
	dns_header->rd = 1;
	dns_header->que_num = htons(1);
	dns_header->qr = 0;			/* qr = 0: question packet   */
	dns_header->aa = 0;			/* aa = 0: not auth answer   */
	dns_header->rep_num = htons(0);	/* sending no replies        */

	/* the fixed fields for UDP header */
	udp->uh_dport = htons(dst_port);
	if (src_port) {
		udp->uh_sport = htons(src_port);
	}

	/* the fixed fields for IP header */
	iphdr->ip_dst.s_addr = sin_dst.sin_addr.s_addr;
	iphdr->ip_v = IPVERSION;
	iphdr->ip_hl = sizeof(struct ip) >> 2;
	//iphdr->ip_ttl = 245;
	iphdr->ip_p = IPPROTO_UDP;

	/* Set signal handler */
	memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = term;
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGINT, &action, NULL);

	time(&start_t);
	time(&end_t);

	while (!stop) {
		int dns_datalen;
		int udp_datalen;
		int ip_datalen;

		ssize_t ret;

		if (random_ip) {
			src_ip.s_addr = random();
		}

		dns_header->id = random();
		if (random_sub) {
			if (qtype == TYPE_PTR)
				random_addr(r);
			else
				random_name(255 - strlen(qname), 0, r);
		//printf("b: %s\n", qname);
		strcat(r, ".");
		strcat(r, qname);
		//printf("a: %s\n", r);
		dns_datalen = make_question_packet(dns_data, r, qtype);
		} else {
			dns_datalen = make_question_packet(dns_data, qname, qtype);
		}

		if (dnssec) {
			char* opt_data = (char *)dns_data + dns_datalen;
			dns_datalen += make_dnssec_packet(dns_header, opt_data);
		}

		udp_datalen = sizeof(struct dnshdr) + dns_datalen;
		ip_datalen = sizeof(struct udphdr) + udp_datalen;

		// update UDP header 
		if (src_opt == -2) {
			// By default - Comply with RFC6056 - Ephemeral port should in range: 1024~65535 
			udp->uh_sport = htons((random() % (65536 - 1024)) + 1024);
		} else if (src_opt == -1) {
			// As you want, will set Ephemeral port range to 0~65535 
			udp->uh_sport = htons(random() % 65536);
		}

#ifdef DEBUG
		printf("Src_opt: %d,\tudp_sport: %u\n", src_opt, ntohs(udp->uh_sport));
#endif

		udp->uh_ulen = htons(sizeof(struct udphdr) + udp_datalen);
		udp->uh_sum = 0;

		iphdr->ip_ttl = 10 + random() % 235;
		/* update IP header */
		iphdr->ip_src.s_addr = src_ip.s_addr;
		iphdr->ip_id = random() % 5985;
		//iphdr->ip_len = htons(sizeof(struct ip) + ip_datalen);
		iphdr->ip_len = sizeof(struct ip) + ip_datalen;
		iphdr->ip_sum = 0;
		//iphdr->ip_sum = in_cksum((char *)iphdr, sizeof(struct ip));

		ret = sendto(sock, iphdr, sizeof(struct ip) + ip_datalen, 0,
				(struct sockaddr *) &sin_dst, sizeof(struct sockaddr));
		if (ret == -1) {
			// perror("sendto error");
		}

		count++;
		time(&end_t);
		difft = difftime(end_t, start_t);
		
		// Check if no count reach
		if (number > 0 && count >= number) {
			// done
			break;
		}
		
		// Check if duration count reached
		if (duration > 0 && difft >= duration) {
			// done 
			break;
		}

		if (sleep_interval > 0) {
			usleep(sleep_interval);
		}
	}

	printf("sent %d DNS requests in %f sec.\n", count, difft);

	return 0;
}
