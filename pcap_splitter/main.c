#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>

#include <zmq.h>

#include "pcap_idx_lib.h"
#include "mempool.h"

#define DATA_BUF_LEN MB

char *filelist[] = {"/IS-NI/raw/disk1/sbs_traffic_disk1/00/ni0_1432825760.pcap"};
int filelist_num = sizeof(filelist) / sizeof(char *);

enum MSG_STAT {
	MSG_EMPTY,
	MSG_NOT_SENT
};

enum THD_STAT {
	THD_WAIT,
	THD_RUN
};

typedef struct zmq_ctl {
	pthread_t thread_id;		//thread id
	int thread_num;			//thread number
	char thread_run;		//thread loop run

	void *socket;			//zeromq socket
	void *context;			//zeromq context
	zmq_msg_t msg;			//zeromq msg struct

	mpool_elt *head_elt;		//mempool tailq head
	mpool_elt *reserve_elt;		//reserved mempool elements

	uint64_t buf_wlen;		//data write length to reserved mempool

	enum THD_STAT thd_stat;		//thread status
	enum MSG_STAT msg_stat;		//msg data buffer process status
} zmq_ctl_t;

#define PCAP_SF_PKTHDR_LEN 16

struct pcap_sf_pkthdr {
	bpf_int32 tv_sec;           /* seconds */
	bpf_int32 tv_usec;          /* microseconds */
	bpf_u_int32 caplen;         /* length of portion present */
	bpf_u_int32 len;            /* length this packet (off wire) */
};

zmq_ctl_t *zmq_ctrl = NULL;

int cfg_split_cnt = 2;
int main_loop_run = 1;

void data_buf_free_func (void *data, void *hint) { if(data) free (data); }

int init_zmq_struct(int split_cnt) {
	int i;

	zmq_ctrl = malloc(sizeof(zmq_ctl_t) * split_cnt);
	if (zmq_ctrl == NULL) return 0;

	memset(zmq_ctrl, 0x00, sizeof(zmq_ctl_t) * split_cnt);

	for (i = 0; i < split_cnt; i++) {
		zmq_ctrl[i].thread_num = i;
		zmq_ctrl[i].thread_run = 1;
	}

	return 1;
}

void destroy_zmq_struct(int split_cnt) {
	int i;
	mpool_elt *elt, *tmp;

	for (i = 0; i < split_cnt; i++) {
		if (zmq_ctrl[i].socket) zmq_close(zmq_ctrl[i].socket);
		if (zmq_ctrl[i].context) zmq_ctx_destroy(zmq_ctrl[i].context);
		if (zmq_ctrl[i].head_elt) {
			LL_FOREACH_SAFE(zmq_ctrl[i].head_elt, elt, tmp) {
				printf("delete : %p\n", elt->elt_addr);
				LL_DELETE(zmq_ctrl[i].head_elt, elt);
				free(elt);
			}
		}
		if (zmq_ctrl[i].reserve_elt) {
			printf("reserve_elt : %p\n", zmq_ctrl[i].reserve_elt->elt_addr);
			free(zmq_ctrl[i].reserve_elt);
		}
	}

	if(zmq_ctrl) free(zmq_ctrl);
}

void signal_handler(int signum) {
	int i;
	for(i = 0; i < cfg_split_cnt; i++) {
		while(zmq_ctrl[i].thd_stat != THD_WAIT) usleep(100);
		zmq_ctrl[i].thread_run = 0;

		pthread_join(zmq_ctrl[i].thread_id, NULL);
	}
	
	main_loop_run = 0;
}

int next_file_open(int *fd) {
	static int file_id = 0;

	if (file_id < filelist_num) {
		*fd = open(filelist[file_id], O_NOATIME | O_NONBLOCK | O_LARGEFILE | O_RDONLY);
		printf("file %s open\n", filelist[file_id]);
		if (*fd < 0) {
			printf("file open error!!!\n");
			return 0;
		}
		lseek(*fd, sizeof(struct pcap_file_header), SEEK_SET);

		file_id++;

		return 1;
	}
	return 0;
}

//extracted from mtcp
inline uint32_t get_idx(char *key) {
	unsigned int hash, i;

	for (hash = i = 0; i < 12; ++i) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash;
}

uint8_t get_idx_from_pktdata(char *pkt_data, int split_cnt) {
	struct ethhdr *ethh = (struct ethhdr *)pkt_data;
	u_short ip_proto = ntohs(ethh->h_proto);

	if (ip_proto == ETH_P_IP) {
		struct iphdr *iph = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
		char skey[12]; //ip+ip+port+port
		char s_lt_d = 0;

		if (iph->version != 0x4) return 0;

		if (iph->saddr > iph->daddr) {
			*((uint32_t *)&skey[0]) = iph->saddr;
			*((uint32_t *)&skey[4]) = iph->daddr;
			s_lt_d = 1;
		}
		else {
			*((uint32_t *)&skey[0]) = iph->daddr;
			*((uint32_t *)&skey[4]) = iph->saddr;
		}

		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *tcph = (struct tcphdr *)(pkt_data + sizeof(struct ethhdr) + (iph->ihl<<2));

			if(s_lt_d) {
				*((uint16_t *)&skey[8]) = tcph->source;
				*((uint16_t *)&skey[10]) = tcph->dest;
			}
			else {
				*((uint16_t *)&skey[8]) = tcph->dest;
				*((uint16_t *)&skey[10]) = tcph->source;
			}
		}
		else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *udph = (struct udphdr *)(pkt_data + sizeof(struct ethhdr) + (iph->ihl<<2));
			if(s_lt_d) {
				*((uint16_t *)&skey[8]) = udph->source;
				*((uint16_t *)&skey[10]) = udph->dest;
			}
			else {
				*((uint16_t *)&skey[8]) = udph->dest;
				*((uint16_t *)&skey[10]) = udph->source;
			}
		}
		else {
			*((uint16_t *)&skey[8]) = 0;
			*((uint16_t *)&skey[10]) = 0;
		}

		return get_idx(skey) % split_cnt;
	}

	return 0;
}

#define MEMPOOL_CANNOT_WRITE(elt, wlen) (elt && ((elt->elt_wsize + PCAP_SF_PKTHDR_LEN + wlen) > elt->elt_size))
#define MEMPOOL_WRITE_PKT(elt, hdr, raw) \
	memcpy(elt->elt_addr + elt->elt_wsize, hdr, PCAP_SF_PKTHDR_LEN); \
	elt->elt_wsize += PCAP_SF_PKTHDR_LEN; \
	memcpy(elt->elt_addr + elt->elt_wsize, raw, hdr->caplen); \
	elt->elt_wsize += hdr->caplen;

char write_pkt_to_mempool(int idx, struct pcap_sf_pkthdr *pkthdr, char *raw_pkt) {
	zmq_ctl_t *izmq = &zmq_ctrl[idx];

	if (MEMPOOL_CANNOT_WRITE(izmq->reserve_elt, pkthdr->caplen)) {
		LL_APPEND(izmq->head_elt, izmq->reserve_elt);
		izmq->reserve_elt = NULL;
	}

	if (izmq->reserve_elt == NULL) {
		izmq->reserve_elt = get_mempool();
		if (izmq->reserve_elt == NULL) {
			printf("cannot get mempool\n");
			return 0;
		}
		izmq->reserve_elt->elt_wsize = 0;
	}

	if (izmq->reserve_elt) MEMPOOL_WRITE_PKT(izmq->reserve_elt, pkthdr, raw_pkt);

	return 1;
}

char get_sendable_packet_len(char *org_buf, size_t org_buf_len, uint32_t *remain_pktlen) {
	struct pcap_sf_pkthdr *pkthdr = (struct pcap_sf_pkthdr *)org_buf;
	char *remain_data = org_buf + PCAP_SF_PKTHDR_LEN;
	size_t readable_buf_len = org_buf_len - PCAP_SF_PKTHDR_LEN;

	while(readable_buf_len){
		//raw data is enough
		//printf("caplen : %u : %p, %p\n", pkthdr->caplen, pkthdr, remain_data);
		if (pkthdr->caplen <= readable_buf_len) {
			uint8_t idx;

			//get_idx_from_pktdata
			idx = get_idx_from_pktdata(remain_data, cfg_split_cnt);
			if (write_pkt_to_mempool(idx, pkthdr, remain_data) == 0) {
				memmove(org_buf, pkthdr, readable_buf_len + PCAP_SF_PKTHDR_LEN);
				*remain_pktlen = (readable_buf_len + PCAP_SF_PKTHDR_LEN);
				return 1;
			}

			remain_data += pkthdr->caplen;
			readable_buf_len -= pkthdr->caplen;

			//next data part is not enough pkt header and raw data
			if (readable_buf_len <= PCAP_SF_PKTHDR_LEN) {
				memmove(org_buf, remain_data, readable_buf_len);
				*remain_pktlen =  readable_buf_len;
				return 0;
			}

			readable_buf_len -= PCAP_SF_PKTHDR_LEN;
			pkthdr = (struct pcap_sf_pkthdr *)remain_data;
			remain_data += PCAP_SF_PKTHDR_LEN;
		}
		//raw data is not enough
		else {
			memcpy(org_buf, pkthdr, readable_buf_len + PCAP_SF_PKTHDR_LEN);
			*remain_pktlen = readable_buf_len + PCAP_SF_PKTHDR_LEN;
			return 0;
		}
	}

	return 0;
}

void *msg_thread(void *arg) {
	zmq_ctl_t *zmq = (zmq_ctl_t *)arg;
	char zmq_socket_name[50];
	char zmq_socket_ret;

	uint64_t send_bytes = 0;

	sprintf(zmq_socket_name, "ipc:///tmp/pcap_zmq%d", zmq->thread_num);
	printf("msg_thread %d start, zmq_socket : %s\n", zmq->thread_num, zmq_socket_name);

	zmq->context = zmq_ctx_new();
	zmq->socket = zmq_socket(zmq->context, ZMQ_REQ);
	zmq_connect(zmq->socket, zmq_socket_name);

	while(zmq->thread_run) {
		if (zmq->thd_stat == THD_WAIT) sleep(1);
		else {
			mpool_elt *elt = zmq->head_elt;
			if (elt != NULL) {
				zmq_msg_init_data(&zmq->msg, (void *)elt->elt_addr, elt->elt_wsize, NULL, NULL);

				send_bytes += zmq_msg_send(&zmq->msg, zmq->socket, 0);
				zmq_recv(zmq->socket, &zmq_socket_ret, sizeof(char), 0);

				LL_DELETE(zmq->head_elt, elt);

				put_mempool(elt);
			}
			else {
				zmq->msg_stat = MSG_EMPTY;
				zmq->thd_stat = THD_WAIT;
			}
		}
	}

	printf("msg_thread %d ,%"PRIu64" end\n", zmq->thread_num, send_bytes);

	return NULL;
}

void msg_thread_run(void) {
	int i;

	for(i = 0; i < cfg_split_cnt; i++) {
		zmq_ctrl[i].msg_stat = MSG_NOT_SENT;
		zmq_ctrl[i].thd_stat = THD_RUN;
	}
}

void flush_msg(void) {
	int i;
	for(i = 0; i < cfg_split_cnt; i++) {
		if (zmq_ctrl[i].reserve_elt) {
			LL_APPEND(zmq_ctrl[i].head_elt, zmq_ctrl[i].reserve_elt);
			zmq_ctrl[i].reserve_elt = NULL;
		}
	}
}

char msg_thread_end_check(void) {
	int msg_process_end_cnt = 0;
	int i;

	for (i = 0; i < cfg_split_cnt; i++) {
		if (zmq_ctrl[i].msg_stat == MSG_EMPTY) msg_process_end_cnt++;
	}
	if (msg_process_end_cnt == cfg_split_cnt) return 1;

	return 0;
}


int main(void) {
	int i, ret;
	int f = -1;
	char *read_buf = malloc(sizeof(char) * DATA_BUF_LEN);
	uint32_t remain_pkt_len = 0;
	char pkt_sended = 0;

	if ( init_zmq_struct(cfg_split_cnt) == 0 ) {
		destroy_zmq_struct(cfg_split_cnt);
		exit(EXIT_FAILURE);
	}

	ret = init_mempool(100, MB);
	if (ret == 0) {
		printf("init_mempool_failed\n");
		destroy_zmq_struct(cfg_split_cnt);
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	for(i = 0; i < cfg_split_cnt; i++) {
		pthread_create(&zmq_ctrl[i].thread_id, NULL, msg_thread, (void *)&zmq_ctrl[i]);
	}

	printf("main loop start\n");
	while(main_loop_run) {
		if (pkt_sended) {
			if (msg_thread_end_check()) pkt_sended = 0;
			else usleep(100);
		}
		else {
			size_t read_len;
			if (f < 0) {
				if (next_file_open(&f) == 0) {
					main_loop_run = 0;
				}
			}

			if (f >= 0) {
				if (remain_pkt_len) {
					if (DATA_BUF_LEN - remain_pkt_len) {
						read_len = read(f, read_buf + remain_pkt_len, DATA_BUF_LEN - remain_pkt_len);
						if(read_len > 0) read_len += remain_pkt_len;
					}
					else read_len = remain_pkt_len;
				}
				else read_len = read(f, read_buf, DATA_BUF_LEN);

				if (read_len <= 0) {
					close(f);
					f = -1;

					flush_msg();
					msg_thread_run();
					while(!msg_thread_end_check()) usleep(100);
				}
				else {
					pkt_sended = get_sendable_packet_len(read_buf, read_len, &remain_pkt_len);
					if (pkt_sended) msg_thread_run();
				}
			}
		}
	}

	for(i = 0; i < cfg_split_cnt; i++) {
		while(zmq_ctrl[i].thd_stat != THD_WAIT) usleep(100);
		zmq_ctrl[i].thread_run = 0;

		pthread_join(zmq_ctrl[i].thread_id, NULL);
	}

	destroy_mempool();
	destroy_zmq_struct(cfg_split_cnt);
	free(read_buf);

	return 0;
}
