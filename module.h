#ifndef MODULE_H
#define MODULE_H

#include <sys/time.h>

#include <rte_mbuf.h>
//ISTIMEOUT true for timeout, false for not timeout.
#define ISTIMEOUT(myJiffies,timeout) (time_after(getTime(),(myJiffies)+(timeout)))
//daq_like module 
//when use following func, you need to check wether the func ptr's value is NULL
//the structor to save packets data or link struct in ring pool.
struct ring_buf{
	int type;//0 for no fragment, 1 for defragment packets.
	void * ptr;
};

//void * getOneRingbuf();
//int saveOneRingbuf(struct rte_ring *, struct ring_buf *);

//struct ring_buf * readOneRingbuf(struct rte_ring *);

typedef struct common_stream{
	char *name;
	void * handle;
	unsigned long timeout;// set the timeout as 10s.
	//unsigned long timeout = HZ * 10;// set the timeout as 10s.
	//handle is the config of the module.
	void (*addPacket)(void *handle,  struct rte_mbuf *m);
	void (*getStream)(void *handle);
	struct ring_buf * (*getPacket)(void *handle);
	void (*realsePacket)(void *handle);
	void (*init)(struct common_stream * pl,const char * name, void ** handle);//create a handle here
	//checkTimeOut must be an endless loop
	void (*checkTimeOut)(void *handle);
	void (*showState)(void *handle);
	//
} Stream;

typedef struct common_plugin{
	int num;
	Stream modules[1024];//may need add modules type...
} plugin;

inline unsigned long getTime(void);

inline int time_after(unsigned long known, unsigned long unkown);
void initModule(plugin *pl,int argc ,char * argv[]);
Stream loadModule(char *path);
void unloadModule(char *path);
 
#endif
//end of module.h
