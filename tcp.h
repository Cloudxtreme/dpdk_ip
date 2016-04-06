#ifndef TCP_H
#define TCP_H

#include <sys/time.h>

#include "module.h"

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

int tcp_init(int);
void tcp_exit(void);
void process_tcp(u_char *, int);
void process_icmp(u_char *);
void tcp_check_timeouts(struct timeval *);

void addPacket(void * handle, struct rte_mbuf *m);
void getStream(void * handle);//void * getStream maybe better.
void realsePacket(void * handle, void * mem);
void realseStream(void *handle, void *mem);
void init(struct common_stream *pl, const char * name, void ** handle);
void checkTimeOut(void * handle);
void showState(void * handle);

#endif
//end of tcp.h