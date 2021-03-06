#include<stdio.h>
#include<dlfcn.h>

#include "module.h"

/*int saveOneRingbuf(struct rte_ring * r, struct ring_buf * ptr){
	rte_ring_dequeue(r,ptr);
}

struct ring_buf * readOneRingbuf(struct rte_ring *){
	
}*/

void initModule(plugin *pl,int argc ,char * argv[]){
	int i =0, j = 0;
	pl -> num = argc;
	for (i = 0; i < argc; i++){
		pl -> modules[j] = loadModule(argv[i]);
		if(pl -> modules[j].name )j++;

	}
}

Stream loadModule(char *path){//here path is the same as name, this need change later.

	void * dp;
	Stream s;
	s.name = path;//maybe bug.
	dp = dlopen(path,RTLD_LAZY);
	if(dp == NULL)
	{
		s.name = NULL;
		printf("Error in load %s.\n",path);
		return s;
	}
	s.timeout = 10;//default value is 10s.
	s.addPacket = dlsym(dp, "addPacket");
	s.getStream = dlsym(dp, "getStream");
	s.getPacket = dlsym(dp, "getPacket");
	s.realsePacket = dlsym(dp, "realsePacket");
	s.init = dlsym(dp,"init");
	s.checkTimeOut = dlsym(dp, "checkTimeOut");
	s.showState = dlsym(dp, "showState");
	return s;
}
//just for test
void unloadModule(char *path){
	printf("%s.\n",path);
}

inline unsigned long getTime(void){
	struct timeval tv;
	gettimeofday(&tv,NULL);
	return tv.tv_sec;
}


inline int time_after(unsigned long known, unsigned long unknown){
	return ((long)known - (long)unknown)>=0;
}
