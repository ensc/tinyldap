#define _GNU_SOURCE
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

/* Sadly, mremap is only available on Linux */
/* Please petition your congressman^Woperating system vendor to include it! */

long mstorage_add(mstorage_t* p,const char* s,unsigned long n) {
  if (p->mapped-p->used<n) {
    if (!p->root) {
      /* nothing allocated.  mmap /dev/zero */
      char* tmp;
      long need=(n|PAGEMASK)+1;
#ifdef MREMAP_MAYMOVE
#ifdef MAP_ANONYMOUS
      if ((tmp=mmap(0,need,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0))==MAP_FAILED)
	return -1;
#else
      int fd=open("/dev/zero",O_RDWR);
      if (fd<0) return -1;
      tmp=mmap(0,need,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0);
      close(fd);
      if (tmp==MAP_FAILED)
	return -1;
#endif
#else
      if (!(tmp=malloc(need)))
	return -1;
#endif
      p->root=tmp;
      p->mapped=need;
      p->used=0;
    } else {
      long need=((p->used+n)|PAGEMASK)+1;
#ifdef MREMAP_MAYMOVE
      char* tmp=mremap(p->root,p->mapped,need,MREMAP_MAYMOVE);
      if (tmp==MAP_FAILED) return -1;
#else
      char* tmp=realloc(p->root,need);
      if (!tmp) return -1;
#endif
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
