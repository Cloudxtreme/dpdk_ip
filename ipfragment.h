#ifndef IPFRAGMENT_H
#define IPFRAGMENT_H
#include <rte_mbuf.h>
#include "module.h"
/*ip packet data, may need change.*/
struct sk_buff {
	char *data;
	int truesize;
};
/*need change*/
/*not use now*/
struct Info{
	unsigned char * mac;//mac addr
	struct ip * ipHead;
	int len;//
	short iplen;
	short maclen;
	long timestamp;//timestamp for pcap file
};
/*
hashtable -> srcDestAddr -> ipPacketHead -> ipFragment
*/
struct ipFragment{
	struct ipFragment * next;//this to help judge whether the fragment is complete.
	struct ipFragment * seq;//this to mark the coming sequence of the fragement.
	struct ipFragment * timer_next;//this to help judge whether the fragment is complete.
	struct ipFragment * timer_pre;//this to mark the coming sequence of the fragement.
	struct sk_buff * skb;//the data of the ip packet.
//	struct Info info;//the info of packet head, need change.
	int offset;
	int length;
	unsigned long myJiffies;//each time, insert a packet, update the jiffer.
};

struct ipPacketHead{
	struct ip *head;
	struct Info info;
	struct ipPacketHead * next;
	struct ipPacketHead * pre;
	struct ipFragment * ipFra;
	struct ipFragment * fraSeq;
	int MF;
};

struct srcDstAddr{
	struct in_addr Src;
	struct in_addr Dst;
	struct srcDstAddr * next;
	struct ipPacketHead * packets;
};

struct hashtable{
	struct srcDstAddr * addr;
};
void checkTimeOut(void * handle);
int addrtoHash(struct in_addr Src, struct in_addr Dest);
struct ring_buf * getPacket(void * handle);
void addToHashTable(void *handle, struct hashtable * table, struct ip * iphead, struct sk_buff *skb);
void addToAddr(void *handle, struct srcDstAddr * table, struct ip * iphead, struct sk_buff *skb);
void adddToipFra(void *handle, struct srcDstAddr * fa, struct ipPacketHead * table, struct ip *iphead, struct sk_buff * skb);
struct ring_buf * getPacket(void *handle);
//insert an ip packet into table
void ipDeFragment(void * handle, struct ip * iphead,struct sk_buff *skb);
//init the ip fragment table
void initIpTable(struct hashtable* tables);

//
void dpdk_ipDeFragment(void *handle, struct rte_mbuf *m);
void init(Stream * pl,const char * name, void ** handle);
#endif
//end of ipfragment.h
