#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <libnet.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <unordered_set>
#include <string>

#define ASSERT(cond, msg)\
if(!(cond)) {\
    fprintf(stderr, "ASSERT FAILED [%s:%d]: %s\n", __FILE__, __LINE__, (msg));\
    exit(-1);\
}

#define GOTOIFN(cond, msg, label, exit_code)\
if(!(cond)) {\
    fprintf(stderr, "ASSERT FAILED [%s:%d]: %s\n", __FILE__, __LINE__, (msg));\
    goto label;\
}

#ifdef DEBUG
#define DASSERT(cond, msg)\
if(!(cond)) {\
    fprintf(stderr, "DASSERT FAILED [%s:%d]: %s\n", __FILE__, __LINE__, (msg));\
    exit(-1);\
}

#define DEBUG_PRINT(fmt, ...) printf("DEBUG PRINT [%s:%d]: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define DASSERT(...) {}
#define DEBUG_PRINT(...) {}
#endif

#define MIN_HTTP_REQUEST_SIZE   24
#define MAX_ITER                20

std::unordered_set<std::string> block_table;

char *HTTP_METHODS[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};
size_t LEN_HTTP_METHODS[] = {3, 4, 4, 3, 6, 7};

void exception_handler(int code) {
    system("iptables -F");
    exit(-1);
}

inline bool check_block(char *address) {
    std::string str(address);
    return block_table.find(str) != block_table.end();
}


static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    int id, ret;
    unsigned char *payload;
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
        if(ph->hw_protocol != htons(ETHERTYPE_IP))
            goto PASS;
    }

    hwph = nfq_get_packet_hw(nfa);
    
    ret = nfq_get_payload(nfa, &payload);
    if(ret >= 0) {
        // Parse IPv4 Packet
        struct libnet_ipv4_hdr *view_ip = (struct libnet_ipv4_hdr *)payload;
        if(view_ip->ip_p != IPPROTO_TCP)
            goto PASS;

        if(ret != ntohs(view_ip->ip_len) || ret < ((view_ip->ip_hl) * sizeof(uint32_t))) {
            DEBUG_PRINT("Wrong IPv4 Packet Size\n");
            goto PASS;
        }
        payload += ((view_ip->ip_hl) * sizeof(uint32_t));
        ret -= ((view_ip->ip_hl) * sizeof(uint32_t));
        struct libnet_tcp_hdr *view_tcp = (struct libnet_tcp_hdr *)payload;
        if(view_tcp->th_dport != htons(80))
            goto PASS;
        
        if(ret < (view_tcp->th_off * sizeof(uint32_t))) {
            DEBUG_PRINT("Wrong TCP Packet Size\n");
            goto PASS;
        }
        payload += (view_tcp->th_off * sizeof(uint32_t));
        ret -= (view_tcp->th_off * sizeof(uint32_t));

        bool found = false;
        if(ret < MIN_HTTP_REQUEST_SIZE)
            goto PASS;
        
        for(int i = 0; i < sizeof(HTTP_METHODS); i++) {
            if(memcmp(payload, HTTP_METHODS[i], LEN_HTTP_METHODS[i]) == 0) {
                found = true;
                break;
            }
        }
        if(!found)
            goto PASS;
        
        unsigned char * pos = payload;
        size_t length = ret;
        found = false;
        
        for(int i = 0; i < MAX_ITER; i++) {
            unsigned char *end =  (unsigned char *)memchr(pos, '\n', length);
            if(end == NULL)
                break;
            if(end - pos < 5)
                break;
            if(strncasecmp((const char *)pos, "Host", 4) == 0) {
                unsigned char *cu = pos +4;
                if (*cu == ':') {
                    cu++;
                    while(*cu == ' ' && cu < end)
                        cu++;
                    if(cu < end) {
                        char *address = (char *) malloc(end - cu + 1);
                        ASSERT(address != 0, "malloc failed");
                        memcpy(address, cu, end - cu);
                        address[end - cu] = '\x00';
                        size_t idx = end - cu - 1;
                        while(idx != 0 && (address[idx] == ' ' || address[idx] == '\n' || address[idx] == '\r'))
                            idx--;
                        address[idx + 1] = '\x00';
                        if(check_block(address)) {
                            printf("Block: %s\n", address);
                            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                        }
                    }
                }
            }
            length -= end - pos + 1;
            pos = end + 1;
        }
        DEBUG_PRINT("Pass\n");
    }
PASS:  
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


void parse_csv_file(char *file) {
    FILE *fp = fopen(file, "r");
    char *line = NULL;
    size_t length = 0;
    while (getline(&line, &length, fp) != -1) {
        // printf("line: %s", line);
        char *num = strtok(line, ",");
        if (num == NULL)
            continue;
        char *address = strtok(NULL, ",");
        size_t address_len = strlen(address);
        if (address_len == 0)
            continue;
        if (address[address_len - 1] == '\n') {
            address[address_len - 1] = '\x00';
        }
        std::string str(address);
        block_table.insert(str);
    }
    free(line);
}


int main(int argc, char *argv[]) {
    struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
    char buf[4096] __attribute__ ((aligned));
    int ret;
    int fd;
	int rv;
    int exit_code = 0;

    if(argc < 2) {
        printf("Usage: %s [File]\n", argv[0]);
        printf("File: Host list to ban in csv format\n");
        exit(-1);
    }

    parse_csv_file(argv[1]);
    printf("Parse complete\n");

    signal(SIGINT, exception_handler);

    ret = system("iptables -F");
    ASSERT(ret == 0, "failed flushing chains");
    ret = system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    ASSERT(ret == 0, "append to output chain");
    ret = system("iptables -A INPUT -j NFQUEUE --queue-num 0");
    GOTOIFN(ret == 0, "append to input chain", __EXIT_1, -1);

    h = nfq_open();
    GOTOIFN(h != NULL, "error during nfq_open()", __EXIT_1, -1);

    ret = nfq_unbind_pf(h, AF_INET);
    GOTOIFN(ret == 0, "error during nfq_unbind_pf()", __EXIT_2, -1);

    ret = nfq_bind_pf(h, AF_INET);
    GOTOIFN(ret == 0, "error during nfq_bind_pf()", __EXIT_2, -1);

    qh = nfq_create_queue(h,  0, &callback, NULL);
	GOTOIFN(qh != NULL, "error during nfq_create_queue()", __EXIT_3, -1);

    ret = nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    GOTOIFN(ret == 0, "can't set packet_copy mode", __EXIT_4, -1);

    fd = nfq_fd(h);

    while(1) {
        if((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
			DEBUG_PRINT("losing packets");
			continue;
		}
        GOTOIFN(1, "failed sending packet", __EXIT_4, -1);
    }

__EXIT_4:
    nfq_destroy_queue(qh);
__EXIT_3:
    nfq_unbind_pf(h, AF_INET);
__EXIT_2:
    nfq_close(h);
__EXIT_1:
    ret = system("iptables -F");

    return exit_code;
}