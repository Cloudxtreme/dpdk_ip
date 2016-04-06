#include "tcp.h"
//hashtable -> tcpstream->half_stream
//对于全局变量的处理

//use in func void func(...)
#define OUTOFMEM {printf("Out of mem.\n");return ;}

struct tcpHashTable tcpTable[1024];
static int isEqual(struct tuple4 a, struct tuple4 b){
	return (a.saddr == b.saddr && a.daddr == b.daddr && a.source == b.source && a.dest == b.dest) || (a.saddr == b.daddr && a.saddr == b.daddr && a.dest == b.source && a.source == b.dest);
}
static int mk_hash_index(struct tuple4 addr){
	return (addr.saddr + addr.daddr + addr.source + addr.dest)%1024;
}


struct tcp_stream * initStream(struct tuple4 addr, struct tcphdr * tcp, char data){
	struct tcp_stream * stream;
	stream = rte_malloc("tcp",sizeof(struct tcp_stream),0);
	if(stream == NULL){
		printf("Out of mem.\n");return NULL;
	}
	stream -> addr = addr;
	stream -> client = rte_malloc("half_stream",sizeof(struct half_stream),0);
	stream -> server = rte_malloc("half_stream",sizeof(struct half_stream),0);
	if(stream->client == NULL || stream -> server == NULL){
		printf("Out of Mem.\n");return NULL;
	}
	//init half_stream, do not know how to do now.
	//to do:
	
	//
	return stream;
}

void addPkttoStream(struct tcp_stream stream, struct tcphdr * tcp, char * data){
/*
**1. judge wether the packet come from client or server.
**2. add the packet to half_stream.
**3. update the message of half_stream.
**4. judge wether the stream is finished.
*/
	strcut skbuff * temp = NULL;
//1
	struct hafl_stream * hs;
	if (tcp ->addr -> dest == stream -> addr -> dest)
		hs = stream -> client;
	else
		hs = stream -> server;
//2:need change
	temp = rte_malloc("skbuff",sizeof(struct skbuff),0);
	if (temp == NULL){
		printf("Out of Mem.\n");
		return ;
	}
	temp -> data = data;
	temp -> truesize = sizeof(data);// not sure that's right
	hs -> listtail -> next = temp;
	temp -> prev = hs -> listtail; 
	temp -> next = NULL;
	hs -> listtail = temp;
//3.todo 
//4.todo
}


void addPkttoTable(struct tcphdr * tcp, struct iphdr * ip, char * data){
	struct tuple4 addr;
	struct tcp_stream *stream, *pre;
	int index = 0;
	addr.saddr = ip -> saddr;
	addr.daddr = ip -> daddr;
	addr.source = tcp -> source;
	addr.dest = tcp -> dest;
	index = mk_hash_index(addr);
	if(tcpTable[index].next == NULL)// a new addr hash value.
	{
			stream = initStream(addr, tcp, data);
			if(stream == NULL)//failed to add this packet, ignore it.
				return ;
			stream -> pre = NULL;
			stream -> next = NULL;
			tcpTable[index].next = stream;
	}else//not a new one, so need to find the stream or create a new stream.
	{
		int flag = 0;
		stream = tcpTable[index].next;
		while(flag == 1 || stream == NULL ){
			if(isEqual(stream -> addr,addr))
				flag = 1;
			else{
				pre = stream;
				stream = stream -> next;
			}
		}
		if(flag){//find the stream, then add the pkt to this stream
			addPkttoStream(stream, tcp, data);
		}else{//404, need to create a new stream
			//todo:malloc and init a stream, then add the pkt to this new stream
			stream = initStream(addr, tcp, data);
			if(stream == NULL)//failed to add this packet, ignore it.
				return ;
			stream -> prev_node = pre;
			stream -> next = NULL;
		}
	}
}

void initTCPtable(int num)
{
	num = 1024;
	//struct tcpHashTable tcpTable[num];
	for(num--;num>=0;num--)
	{
		tcpTable[num].hash_index = num;
		tcpTable[num].next = NULL;
	}
}

