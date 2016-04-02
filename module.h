#ifndef MODULE_H
#define MODULE_H

#include <rte_mbuf.h>

//daq_like module 
//when use following func, you need to check wether the func ptr's value is NULL
typedef struct common_stream{
	char *name;
	void * handle;
	//handle is the config of the module.
	void (*addPacket)(void *handle,  struct rte_mbuf *m);
	void (*getStream)(void *handle);
	void (*getPacket)(void *handle);
	void (*realsePacket)(void *handle);
	void (*init)(struct common_stream * pl,const char * name, void ** handle);//create a handle here
	void (*checkTimeOut)(void *handle);
	void (*showState)(void *handle);
	//
} Stream;

typedef struct common_plugin{
	int num;
	Stream modules[1024];//may need add modules type...
} plugin;

void initModule(plugin *pl,int argc ,char * argv[]);
Stream loadModule(char *path);
void unloadModule(char *path);
 
#endif
//end of module.h
