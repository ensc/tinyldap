#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/shm.h>
#include <stdio.h>
#include "byte.h"
#include "mstorage.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGEMASK ((PAGE_SIZE)-1)

const long mstorage_add(mstorage_t* p,const char* s,unsigned long n) {
  if (p->mapped-p->used<n) {
    if (!p->root) {
      /* nothing allocated.  mmap /dev/zero */
#ifndef MAP_ANONYMOUS
      int fd=open("/dev/zero",O_RDWR);
#endif
      char* tmp;
      long need=(n|PAGEMASK)+1;
#ifdef MAP_ANONYMOUS
      if ((tmp=mmap(0,need,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0))==MAP_FAILED)
#else
      if (fd<0) return -1;
      if ((tmp=mmap(0,need,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0))==MAP_FAILED)
#endif
	return -1;
      p->root=tmp;
      p->mapped=need;
      p->used=0;
#ifndef MAP_ANONYMOUS
      close(fd);
#endif
    } else {
      long need=((p->used+n)|PAGEMASK)+1;
      char* tmp=mremap(p->root,p->mapped,need,MREMAP_MAYMOVE);
      if (tmp==MAP_FAILED) return -1;
      p->mapped=need; p->root=tmp;
    }
  }
  byte_copy(p->root+p->used,n,s);
  {
    unsigned long l=p->used;
    p->used+=n;
    return l;
  }
}
