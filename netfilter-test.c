#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include <linux/types.h>
#include <linux/netfilter.h>		

#include <errno.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>


void usage() {
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net\n");
}


char URL[4096] = {'\0'};


int ckMeth(unsigned char* pBuf) {
	if(pBuf[0] == 'G' && pBuf[1] == 'E' && pBuf[2] == 'T')
        	return 1;
    	else
        	return 0;
    
}

int dump(unsigned char* pBuf, int size) {
    	int i;
    	unsigned char pkt_host[4096];
    	int option = 0;
    	option = ckMeth(pBuf);

    	switch (option) {
    		case 1: sscanf(pBuf, "GET / HTTP/1.1\r\nHost: %s", pkt_host);
    	    		break;
    		default:
    			break;
    	}

    	if(option) {
        	printf("Site : %s\n", pkt_host);

        	if(!strncmp(pkt_host, URL, strlen(pkt_host))) {
        	    return 1;
        	}else
            	return 0;
    	}
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	int id = 0;
	
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	
	int ret;
	unsigned char *pkt;
	char *Method;
	int op = 0;
	
	ph = nfq_get_msg_packet_hdr(nfa);
	
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	ret = nfq_get_payload(nfa, &pkt);
	
	if (ret >= 0) {
        	pkt += 0 + 20 + 20;
		op = dump(pkt, ret);	
	}
	
	if(op) {
        	printf("Blocked!\n");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    	}else {
        	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    	}
}

int main(int argc, char **argv)
{

	if(argc != 2) {
        	usage();
        	return 0;
    	}
    
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char pBuf[4096] __attribute__ ((aligned));


	strncpy(URL, argv[1], 4095);
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, pBuf, sizeof(pBuf), 0)) >= 0) {

			nfq_handle_packet(h, pBuf, rv);
			continue;
		}

		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
