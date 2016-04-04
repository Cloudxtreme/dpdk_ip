#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>//will be replaced by rte_malloc.
#include <rte_malloc.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <rte_ring.h>
#include "ipfragment.h"
#include "module.h"

#define OUTOFMEM {printf("Out of Mem!\n");return ;}
#define TABLESIZE 1024
#define IP_CE 0x8000   /* Flag: "Congestion" */
#define IP_DF 0x4000   /* Flag: "Don't Fragment" */
#define IP_MF 0x2000   /* Flag: "More Fragments" */
#define IP_OFFSET 0x1FFF  /* "Fragment Offset" part */
/*
**to do://2016.3.16
**1.add the completed fragements to rings;
**2.notify the users to get packet of rings;
**3.add ttl about the fragement;
**4.delete the completed fragements safely.
*/

/*
*to do:
*1. 在一开始的时候就对ip包进行解析，取出必要的信息写入结构体重
*2. 对内存分配部分进行修改（for 性能）
*3. 在最后的分片链表中不保存ip头，只保存data和必要的信息，最后再重组ip头
*4. 
*/


typedef struct ipstruct{
	struct hashtable tables[TABLESIZE];
	struct rte_ring * r;
	struct ipFragment *tail;
	struct ipFragment *head;
	unsigned long timeout;
} IpImpl;


//hash
int addrtoHash(struct in_addr Src, struct in_addr Dest){
		//printf("In cacu %d %d.\n",Src.s_addr,Dest.s_addr);
		return (Src.s_addr + Dest.s_addr)%1024;//need change 
}

/*globle value*/
//struct hashtable  tables[TABLESIZE];


/*
static void sentPacket(struct ipPacketHead * table){
	//rebuild the packet and sent it to pcap
	//或保存一个数据包池，满足条件了再发出去.
	printf("addr: %s %s.\n",inet_ntoa(table -> head -> ip_src),inet_ntoa(table -> head -> ip_dst));
}*/
//将数据加入到分片链表中，其中，分片一定是唯一的，关于重复能不能重复这一点有待商榷
void adddToipFra(void *handle, struct srcDstAddr * fa, struct ipPacketHead * table, struct ip *iphead, struct sk_buff * skb)
{
	IpImpl * impl = (IpImpl *)handle;
	if (((ntohs(iphead->ip_off)&~IP_OFFSET) & IP_MF) == 0){
		table->MF = 0;
	}
printf("2 ");
fflush(stdout);
	if (table->ipFra == NULL){
		table->ipFra = (struct ipFragment *)rte_malloc("ipFra", sizeof(struct ipFragment),0);
		if (table ->ipFra == NULL ){printf("Out of Mem1!\n");return ;}
		else{
			table->ipFra->next = NULL;
			table->ipFra->seq = NULL;
			table->ipFra->skb = skb;
			table-> ipFra -> myJiffies = getTime();
			table->fraSeq = table->ipFra;
			table->ipFra->length = iphead -> ip_len;
			table->ipFra->offset = ntohs(iphead->ip_off) & IP_OFFSET;
			if(impl -> tail == NULL){
				impl -> tail = table -> ipFra;
				table -> ipFra -> timer_pre = impl -> head;
				impl -> head -> timer_next = table -> ipFra;
				impl -> tail -> timer_next = NULL;
								
			}else{
			table -> ipFra -> timer_pre = impl -> tail;
			impl -> tail -> timer_next = table -> ipFra;
			impl -> tail = table -> ipFra;
			impl -> tail -> timer_next = NULL;
			}
			/*
			table->ipFra->timer_pre -> timer_next = table -> ipFra -> timer_next;
			if(table->ipFra->timer_next)
				table->ipFra->timer_next ->timer_pre = table -> ipFra -> timer_pre;
			impl -> tail -> timer_next = table -> ipFra;
			table -> ipFra -> timer_pre = impl -> tail;
			impl -> tail = table -> ipFra;
			impl -> tail -> timer_next = NULL;
			*/
		}
	}
	else{
		//这里要做的是两件事
		//1.记录下数据包到来的顺序。
		//2.按数据包偏移位排序。
		//3.记录完成后检查是否是一个完整的分片包。
		//4.不完整就结束程序，完整就将包发到数据包池中。
		//timer_link
		table -> ipFra -> myJiffies = getTime();//just change the first's myJiffies.
		table->ipFra->timer_pre -> timer_next = table -> ipFra -> timer_next;
		if(table->ipFra->timer_next)
			table->ipFra->timer_next ->timer_pre = table -> ipFra -> timer_pre;
		impl -> tail -> timer_next = table -> ipFra;
		table -> ipFra -> timer_pre = impl -> tail;
		impl -> tail = table -> ipFra;
		impl -> tail -> timer_next = NULL;
		printf("\naddr:%ld %ld %ld\n",(long)table -> ipFra, (long)table -> ipFra -> timer_pre, (long)table -> ipFra->timer_next);	
		struct ipFragment * current, *pre,*newFrag;
		newFrag = (struct ipFragment *)rte_malloc("Fra", sizeof(struct ipFragment),0);
		if (newFrag == NULL){printf("Out of Mem2!\n");return ;}
		else{
			//here edit the new fragment
			//to do:edit the info.

			newFrag->skb = skb;
			newFrag->seq = NULL;
			newFrag->next = NULL;
			newFrag->offset = ntohs(iphead->ip_off) & IP_OFFSET;
			newFrag->length = iphead -> ip_len;
		}
		//1.record the sequence of packet.
		current = table->fraSeq;
		pre = current;
printf("3 ");
		while (current){
			pre = current;
			current = current->seq;
		}
printf("4 ");
fflush(stdout);
		pre->seq = newFrag;
		//2.sort by offset
		current = table->ipFra;
		pre = current;
		if(current -> offset == newFrag -> offset){
			//if find the same packet, just change the next, not change the coming sequence.
			if(current -> length < newFrag -> length)
			{
				newFrag -> next = current -> next;
				table -> ipFra = newFrag;
			}
		}
		else if (current->offset > newFrag->offset){
			newFrag->next = current;
			table->ipFra = newFrag;
		}
		else{
printf("5 ");
fflush(stdout);

			while (current && current->offset < newFrag->offset)
			{

				pre = current;
				current = current -> next;
				if(current -> offset == newFrag -> offset){
				//if find the same packet, just change the next, not change the coming sequence.
					if(current -> length < newFrag -> length)
					{
						newFrag -> next = current -> next;
						pre -> next = newFrag;
					}
				}
			}
printf("6 ");
fflush(stdout);
			pre->next = newFrag;
			newFrag->next = current;
		}
		//3.judge weather the fragment is complete.
		if (table->MF == 0){//get the last fragement, need to judge now.
//int num = 0;
			printf("MF =0.\n");
			current = table->ipFra;
			pre = current;
printf("7 ");
fflush(stdout);
			while (current -> next){
				if (current->offset + current->length > current->next->offset){
					pre = current;
					current = current->next;
					/*to do :debug!*/
					printf("In loop 7.\n");
 					//if(pre == current){printf("The same.\n");return;}
				}
				else
					break;
			}
			printf("In if.\n");
			if (pre->offset + pre->length >= current->offset){
				//Job done.
				//here has two things to do.
				//1.
				//return;
				
				struct ring_buf * ptr = (struct ring_buf *)rte_malloc("ring_buf",sizeof(struct ring_buf),0);
				//void **obj = rte_malloc("rp",sizeof(void *)*2,0);
				if(ptr == NULL)OUTOFMEM
				ptr -> type = 1;
printf("1");
fflush(stdout);
				ptr -> ptr = table -> ipFra;
				//obj[0] = ptr;
				rte_ring_enqueue(impl -> r, ptr);
		printf("\naddr:%ld %ld %ld\n",(long)table -> ipFra, (long)table -> ipFra -> timer_pre, (long)table -> ipFra->timer_next);	
				if(impl -> tail == table -> ipFra)
				{
printf("3.1");
fflush(stdout);
					impl -> tail = table -> ipFra ->timer_pre;
					impl -> tail ->timer_next = NULL;
				}
				else
				{
printf("3.2");
fflush(stdout);
					printf("%ld %ld", (long)table -> ipFra -> timer_pre, (long)table -> ipFra->timer_next);	
fflush(stdout);
					table->ipFra->timer_pre -> timer_next = table -> ipFra -> timer_next;
printf("3.3");
fflush(stdout);					
					table->ipFra->timer_next ->timer_pre = table -> ipFra -> timer_pre;
				}
				//这边考虑如何把分片包断开
				if(table -> next){
					table -> next -> pre = table -> pre;
				}//here just for test ring
printf("2");
fflush(stdout);
				if(table -> pre){
				table -> pre -> next = table -> next;
				}else
				{
					fa -> packets = NULL;
				}
printf("3");
fflush(stdout);
				
printf("4");
fflush(stdout);
			//	ptr = NULL;
			//	rte_ring_dequeue(impl -> r, (void **)&ptr);
				ptr = getPacket(handle);
				printf("In ring %d IP:%p.\n",ptr -> type, ptr -> ptr);
			}else
			printf("Job not done!\n");
			//else the fragement not completed, just continue.
		}
printf("8 ");
fflush(stdout);
	}

}
//将数据加入到数据包链表中，其中，数据包链表以ip的id为唯一标识
void addToAddr(void *handle, struct srcDstAddr * table, struct ip * iphead, struct sk_buff *skb){
printf("3 ");
fflush(stdout);
	if (table->packets == NULL){//empty packet.
		table->packets = (struct ipPacketHead *)rte_malloc("packets", sizeof(struct ipPacketHead),0);
		if (table->packets == NULL){printf("Out of Mem3!\n");return ;}
		else{

			table->packets->next = NULL;
			table->packets->pre = NULL;
			table->packets->ipFra = NULL;
			table->packets->head = iphead;
			table->packets->MF = 1;
			adddToipFra(handle, table, table->packets, iphead, skb);
		}
	}
	else{
		struct ipPacketHead * current, *pre;
		current = table->packets;
		pre = current;
		while (current){
			if (current->head->ip_id == iphead->ip_id){//two fragment of one packet.
				adddToipFra(handle, table, current, iphead, skb);
				break;
			}
			else{
				pre = current;
				current = current->next;
			}
			if (current == NULL)
			{
				pre->next = (struct ipPacketHead *)rte_malloc("ipPacket", sizeof(struct ipPacketHead),0);
				if (pre->next == NULL){printf("Out of Mem4!\n");return ;}
				else{
					pre->next->pre = pre;
					pre->next->head = iphead;
					pre->next->ipFra = NULL;
					pre->next->next = NULL;
					pre->next->MF = 1;
					adddToipFra(handle, table, pre->next, iphead, skb);

				}
			}

		}
	}
}
//将数据加入到Hash表中，其中，hash表中的表项以源目ip作为唯一标识。
void addToHashTable(void *handle, struct hashtable * table, struct ip * iphead, struct sk_buff *skb){
printf("2 ");
fflush(stdout);
	if (table->addr == NULL){
		table->addr = (struct srcDstAddr *)rte_malloc("srcaddr", sizeof(struct srcDstAddr),0);
		if (table->addr == NULL)
			{printf("Out of Mem5!\n");return ;}
		else{

			table->addr->Src = iphead->ip_src;
			table->addr->Dst = iphead->ip_dst;
			table->addr->next = NULL;
			table->addr->packets = NULL;
			addToAddr(handle, table->addr, iphead, skb);
		}
	}
	else{
		struct srcDstAddr * current, *pre;
		current = table->addr;
		pre = table->addr;
		while (current){
			if (current->Dst.s_addr == iphead->ip_src.s_addr && current->Src.s_addr == iphead->ip_dst.s_addr){
				//hit
				addToAddr(handle, current, iphead, skb);
				break;
			}
			else{
				pre = current;
				current = current->next;
			}
		}
		if (current == NULL){
			pre->next = (struct srcDstAddr *)rte_malloc("srcdst", sizeof(struct srcDstAddr),0);
			if (pre->next == NULL)
				{printf("Out of Mem6!\n");return ;}
			else{

				pre->next->Dst = iphead->ip_dst;
				pre->next->Src = iphead->ip_src;
				pre->next->next = NULL; 
				pre->next->packets = NULL; 
				addToAddr(handle, pre->next, iphead, skb);
			}

		}

	}
}
void ipDeFragment(void * handle, struct ip * iphead,struct sk_buff *skb){
	printf("1\n");
	IpImpl * impl = (IpImpl *)handle;
	int index = addrtoHash( iphead->ip_src, iphead->ip_dst);
	int offset = ntohs(iphead ->ip_off);
	int flags = offset&~IP_OFFSET;
	offset &= IP_OFFSET;
	if(((flags & IP_MF) ==0)&&(offset ==0)){// no fragment.
		//printf("No fragment.\n");
		struct ring_buf * ptr = (struct ring_buf *)rte_malloc("rp",sizeof(struct ring_buf *),0);
		if(ptr ==NULL)OUTOFMEM
		ptr -> type = 0;
		ptr -> ptr = iphead;
		rte_ring_enqueue(impl -> r, ptr);
		
	}
	else
	{
		printf("Fragment in %d.\n",index);
		fflush(stdout);
		addToHashTable(handle, &impl -> tables[index], iphead, skb);
	}
	//	tables[index].addr->packets->ipFra->info.ipHead = iphead;

		/*here need to add ip packet info */
		/*to do :add ipFragment head*/

}

void dpdk_ipDeFragment(void *handle, struct rte_mbuf *m){
	struct ip * iphead = (struct ip *)m;
	struct sk_buff s;
	s.data = (char *)(m - sizeof(struct ip));
	s.truesize = rte_pktmbuf_pkt_len(m) - sizeof(struct ip);
	ipDeFragment(handle, iphead, &s);
}

void initIpTable(struct hashtable* tables){
	int i = 0;
	for (i = 0; i < TABLESIZE; i++)
		tables[i]. addr = NULL;
}
//here is an endless loop.
void checkTimeOut(void * handle){
	IpImpl * impl = (IpImpl *)handle;
	unsigned long timeout = impl -> timeout;
	struct ipFragment *tmp = impl -> head -> timer_next;
	while(tmp){
		if(ISTIMEOUT(tmp -> myJiffies, timeout)){//timeout
			//do timeout
			
			//move to next point.
			tmp = tmp -> timer_next;
			impl -> head ->timer_next = tmp;
		}
		else
			break;
	}
}
//the following is the module interface
struct ring_buf * getPacket(void *handle){
	struct ring_buf * ptr = NULL;
	IpImpl * impl = (IpImpl *)handle;
	rte_ring_dequeue(impl -> r, (void **)&ptr);
	if(ptr != NULL)
	printf("Ptr in getPacket: type:%d addr:%p.\n",ptr -> type, ptr -> ptr);
	return ptr;
}

void init(Stream * pl, const char *name, void ** handle){

	IpImpl * impl = calloc(1,sizeof(IpImpl));
	if (!impl){
		printf("Out of Mem.\n");
		return ;
	}
	//point to func.
	pl -> timeout = 10;//timeout value is 10s the same as the default value.
	impl -> timeout = 10;
	pl -> init = init;
	pl -> addPacket = dpdk_ipDeFragment;
	//empty
	pl -> getPacket = getPacket;
	pl -> getStream = NULL;
	pl -> realsePacket = NULL;
	pl -> checkTimeOut = checkTimeOut;
	pl -> showState = NULL;
	impl -> r = rte_ring_lookup(name);
	impl -> tail = NULL;
	impl -> head = (struct ipFragment *)rte_malloc("tailhead",sizeof(struct ipFragment),0);
	impl -> head -> timer_pre = impl -> head;
	impl -> head -> timer_next = NULL;
	if(impl -> r == NULL){
		printf("Ring %s not found ,now creating a new ring.\n",name);
		impl -> r = rte_ring_create(name,4096, -1, 0);
		if(impl -> r == NULL){
			printf("Error in creating ring.\n");
			return ;
		}
		else
			printf("Done in creating ring.\n");
	}
	//init the module.
	initIpTable(impl -> tables); 
	*handle = impl; 
	printf("Init ip module done!\n");

}
