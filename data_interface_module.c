#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <rte_ring.h>
#include <unistd.h>
//#include <rte_timer.h>
#include "ipfragment.h"
#include "module.h"

#define DEBUG

#ifdef DEBUG
#define DBG(CODE) CODE
#else
#define DBG(CODE)
#endif

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

//name of ring
#define IP_RING "dpdk_ip_ring"
#define UDP_RING "dpdk_udp_ring"
#define TCP_RING "dpdk_tcp_steam_ring"

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN, },
};

plugin ip;
struct rte_mempool *mbuf_pool;
static unsigned nb_ports;
//ip,tcp,udp
static struct rte_ring *r[3] = {NULL,NULL,NULL};//ring pool, 2 for recv and send 
//timer
//static struct rte_timer timer0;
/*
**int IPFRAG_ENTRY(struct ip *iph, int pktlen, int thread_id);
**int IP_ENTRY(struct ip *iph, int pktlen,int thread_id);
**void TCP_ENTRY(struct tcp_stream *ts, void **ppme);
**int UDP_ENTRY(struct tuple4 * addr, char * buf, int len,struct ip *a_ip,int thread_id);
*/
//@tip:
//能不能再setup.sh中查看到网卡的ip和地址//不能，那dpdk怎么收到特定的包
//dpdk收所有的包

//@tod0:
//init the dpdk.
//transfer the internet packets to new mbuf.
//send mbuf.

//这边可能用到的函数
//rte_pktmbuf_alloc//alloc mem from mbufpool and reset it to empty
//rte_eth_tx_brust//send burst
//@still unkown:
//性能问题，将内存中的包转为mbuf的空间消耗和时间消耗，是否需要重新定义各种internet头文件。
//ip头中没有包含数据的部分，这部分的数据不知道该怎么发送。
//各种参数的含义没弄懂
//how to constract a mbuf.
/*
static int ipToMbuf(struct ip * iph,void *data)
{
	struct rte_mbuf * m = rte_pktmbuf_alloc(mbuf_pool);
	if(unlikely(m == NULL)){
			DBG(printf("Null rte_mbuf"););
			return 1;
	}
	rte_memcpy((uint8_t *)m->buf_addr + m ->data_off,(uint8_t *)iph,sizeof(struct ip));
	rte_memcpy((uint8_t *)m->buf_addr + m ->data_off + iph ->ip_len,(uint8_t *)data,m ->buf_len - iph -> ip_len);
	m -> pkt_len = iph -> ip_len;
	m -> data_len = iph -> ip_len;//数据报的长度不知道在哪获取。
	return 0;
}*/
//自己构建一个属于该tcp流的ip头和tcp头。
//将流中的数据按照一个ip包最大尺寸-ip头尺寸-tcp头尺寸的大小分开，并组包。
//将最后的mbuf发送出去。
/*
static int tcp_streamToMbuf(struct tcp_stream *ts,void **ppme){

}

static int udpToMbuf(struct tuple4 * addr,char *buf,int len,struct ip * a_ip){

}
*/
//to analyse a mbuf file to ip packet
//use func rte_pktmbuf_adj

/**********************
后续需要考虑将mbuf这类函数写成宏或者直接调用adj的方式
内存和性能考虑
***********************/

static struct ipv4_hdr * mbufToIP(struct rte_mbuf * buf){
	return (struct ipv4_hdr *)rte_pktmbuf_adj(buf, (uint16_t)sizeof(struct ether_hdr));
}

//这里应该是直接发送tcp流而不是单个tcp包。这个函数的声明保留，但是应该是完全没用的函数或者是内部使用的函数。
//作用是将已经整理为ip包的mbuf转为tcp包，然后立刻进行tcp流重组的环节。
/*
static int mbufToTCP(struct rte_mbuf * buf, struct tcp ){
	//todo:NULL
	return 0;
}*/

//将已经整理为ip包的mbuf转为udp包，本函数之后应该讲udp包放入环中。
	/*
static struct udphdr * mbufToUDP(struct rte_mbuf * buf){
	return (struct udphdr *)rte_pktmbuf_adj(buf, (uint16_t)sizeof(struct ipv4_hdr));
	
}*/
//3.2.16 只发送头部到环中，可能需要改成发送完整的包到环中。
static void handleMbuf(struct rte_mbuf * mbuf){
	//static int count = 0;
	struct ipv4_hdr * iphdr = mbufToIP(mbuf);
	/*count ++;
	if (count > 10){
		sleep(10);
		ip.modules[0].checkTimeOut(ip.modules[0].handle);
	}*/
	ip.modules[0].addPacket(ip.modules[0].handle,(struct rte_mbuf *)iphdr);//need change.
	//dpdk_ipDeFragment((struct rte_mbuf *)iphdr);
	//todo:拷贝一份iphdr到环，然后通知相关函数
	//只发送头部到ring中。
	//如果需要发送完整的ip包，将sizeof改成sizeof(struct rte_mbuf) - sizeof(struct rte_ether_hdr)
	//void * temp = rte_malloc("ipv4_hdr", sizeof(struct ipv4_hdr), 0);
	//rte_memcpy(temp, ipv4_hdr, sizeof(struct ipv4_hdr));
	//+
	//rte_ring_enqueue(r[0], temp);
	//check proto_id, ICMP 1, IGMP 2, TCP 6, UDP 17, IGRP 88, OSPF 89  
	printf("in proto:");  
	switch (iphdr->next_proto_id){
	case 6:printf("TCP packet.\n");
		break;
	case 17:/*
		struct udphdr * udp = mbufToUDP(mbuf);
		temp = rte_malloc("udp_hdr", sizeof(struct udphdr), 0);
		rte_memcpy(temp, udp, sizeof(struct udphdr));
		rte_ring_enqueue(r[2], temp);
		//todo:拷贝一份udphdr到环，然后通知相关函数*/
		printf("UDP packet.\n");
		break;
	default:printf("proto_id:%d.\n",iphdr->next_proto_id);
	break;
	}
	//该包处理完毕。这里有可能会出现内存释放的问题。
	//rte_free(mbuf);
}

//在这里可能需要进行数据包的分发工作
static void rxPacket(uint8_t nb_ports)
{
	uint8_t port;
	for (;;){
		for (port = 0; port < nb_ports; port++){
			struct rte_mbuf *bufs[BURST_SIZE];
			uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
			if (unlikely(nb_rx == 0))continue;
			else
				printf("Get %d packets.\n",nb_rx);
			//deal with the packet recived
			uint16_t i;
			for (i = 0; i < nb_rx; i++)
{

				handleMbuf(bufs[i]);
}		}
	}
}

//3.2.16  这个函数的功能可能需要完全改掉
//这个程序需要改造，参考pktgen_send_mbuf
/*
static int txPacket(struct rte_mbuf ** bufs, int nb_mbuf,uint8_t port){
	//uint8_t port;
	//do not need it.
	// here to check the ports, do not need in it.
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
	//
	//just send from port 0
	//port = 0;
			
	uint16_t value_tx = BURST_SIZE;
	int i =0;
	for(i =0;i< nb_mbuf;i+=BURST_SIZE){
		if(nb_mbuf -i  < BURST_SIZE)
			value_tx = nb_mbuf -i;
		const uint16_t nb_tx  = rte_eth_tx_burst(port,0,bufs+i,value_tx);
		//failed send packets, need resend it.
		if(unlikely(nb_tx < value_tx)){
			i -= BURST_SIZE;
		}
	}
	return nb_mbuf;
}*/


static int initRing(int i, const char * name, int ring_size, int socket_id){

	//if (_r == NULL)
	r[i] = rte_ring_create(name, ring_size, socket_id, 0);//
	if (r[i] == NULL)
		return -1;//
	if (rte_ring_lookup(name) != r[i]){
		printf("Can not lookup ring from its name.\n");
		return -1;
	}
	return 0;
}

static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	retval  = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	struct ether_addr addr;

	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	rte_eth_promiscuous_enable(port);
	//rte_eth_add_rx_callback(port, 0, add_timestamps, NULL);
	//rte_eth_add_tx_callback(port, 0, calc_latency, NULL);

	return 0;
}


/*Main fuction, init dpdk and call the send packet functions*/
static int  initDPDK(int argc, char * argv[]){
	
	uint8_t portid;
	/*init eal*/
	int ret = rte_eal_init(argc,argv);

	if(ret < 0)
		rte_exit(EXIT_FAILURE,"Error with initialization.\n");
	argc -= ret;
	argv += ret;

	nb_ports = rte_eth_dev_count();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* initialize all ports */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too much enabled lcores - "
			"App uses only 1 lcore\n");

	/*init ring pool*/
	initRing(0, IP_RING, 4096, -1);//name, ring_size, socket_id_any, 0
	initRing(1, TCP_RING, 4096, -1);
	initRing(2, UDP_RING, 4096, -1);

	/*init the timer*/
	//rte_timer_subsystem_init();

	return 0;
}

int main(int argc, char *argv[]){
	int i = 0;
	char *path[2];
	path[0] = (char *)malloc(100);
	strcpy(path[0],"/home/nachtz/dpdk-2.2.0/ip_module/build/lib/ip_module.so");
	initDPDK(argc,argv);
	//init and load the plgin here.
	initModule(&ip,1,path);
	for (i = 0;i < ip.num;i++){
		ip.modules[i].init(&ip.modules[i],IP_RING,&ip.modules[i].handle);
	}
	//initIpTalbe();
	//begain work here.
	rxPacket(1);
	return 0;
}
