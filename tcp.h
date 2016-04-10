#ifndef TCP_H
#define TCP_H

#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#include "module.h"

#define mknew(x)	(x *)rte_malloc("mknew",sizeof(x),0)
# define NIDS_JUST_EST 1
# define NIDS_DATA 2
# define NIDS_CLOSE 3
# define NIDS_RESET 4
# define NIDS_TIMED_OUT 5
# define NIDS_EXITING   6	/* nids is exiting; last chance to get data */

# define NIDS_DO_CHKSUM  0
# define NIDS_DONT_CHKSUM 1


struct skbuff {
  struct skbuff *next;
  struct skbuff *prev;

  void *data;
  u_int len;
  u_int truesize;
  u_int urg_ptr;
  
  char fin;
  char urg;
  u_int seq;
  u_int ack;
};

struct tuple4
{
  u_short source;
  u_short dest;
  u_int saddr;
  u_int daddr;
};

struct half_stream
{
  char state;
  char collect;
  char collect_urg;

  char *data;
  int offset;
  int count;
  int count_new;
  int bufsize;
  int rmem_alloc;

  int urg_count;
  u_int acked;
  u_int seq;
  u_int ack_seq;
  u_int first_data_seq;
  u_char urgdata;
  u_char count_new_urg;
  u_char urg_seen;
  u_int urg_ptr;
  u_short window;
  u_char ts_on;
  u_char wscale_on;
  u_int curr_ts; 
  u_int wscale;
  struct skbuff *list;
  struct skbuff *listtail;
};

struct tcp_stream
{
  struct tuple4 addr;
  char nids_state;
  struct lurker_node *listeners;
  struct half_stream client;
  struct half_stream server;
  struct tcp_stream *next_node;
  struct tcp_stream *prev_node;
  int hash_index;
  struct tcp_stream *next_time;
  struct tcp_stream *prev_time;
  int read;
  struct tcp_stream *next_free;
  void *user;
};
struct tcp_timeout
{
  struct tcp_stream *a_tcp;
  struct timeval timeout;
  struct tcp_timeout *next;
  struct tcp_timeout *prev;
};
//the following func should use inside the tcp.c, just for the error no previous for func.

static void del_tcp_closing_timeout(void *handle, struct tcp_stream * a_tcp);
static void add_tcp_closing_timeout(void * handle, struct tcp_stream * a_tcp);
void tcp_check_timeouts(void *handle, struct timeval *now);
struct tcp_stream * nids_find_tcp_stream(void * handle, struct tuple4 *addr);
void nids_free_tcp_stream(void * handle, struct tcp_stream * a_tcp);
void add_to_ringpool(void * handle, struct tcp_stream * a_tcp);
struct tcp_stream * find_stream(void *handle, struct tcphdr * this_tcphdr, struct ip * this_iphdr, int *from_client);


//end


static inline int before(u_int seq1, u_int seq2);


static inline int after(u_int seq1, u_int seq2);



int tcp_init(void *,int);
void tcp_exit(void *);
void process_tcp(void *, u_char *, int);
//void process_icmp(u_char *);

void addPacket(void * handle, struct rte_mbuf *m);
void *getStream(void * handle);//void * getStream maybe better.
void realsePacket(void * handle, void * mem);
void realseStream(void *handle, void *mem);
void init(struct common_stream *pl, const char * name, void ** handle);
void checkTimeOut(void * handle);
void showState(void * handle);

#endif
//end of tcp.h
