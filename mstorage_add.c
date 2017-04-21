#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <stdio.h>
#include <libowfat/byte.h>
#include "mstorage.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGEMASK ((PAGE_SIZE)-1)

unsigned long mstorage_increment=4*PAGE_SIZE;

/* Sadly, mremap is only available on Linux */
/* Please petition your congressman^Woperating system vendor to include it! */

long mstorage_add(mstorage_t* p,const char* s,size_t n) {
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
      long need=((p->used+n)|PAGEMASK)+1+mstorage_increment;
      char* tmp;
#ifdef MREMAP_MAYMOVE
      tmp=mremap(p->root,p->mapped,need,MREMAP_MAYMOVE);
      if (tmp==MAP_FAILED) return -1;
#else
      if (p->fd==-1) {
	tmp=realloc(p->root,need);
	if (!tmp) return -1;
      } else {
	munmap(p->root,p->used);
	tmp=mmap(0,need,PROT_READ|PROT_WRITE,MAP_SHARED,p->fd,0);
	if (tmp==-1) {
	  tmp=mmap(0,p->used,PROT_READ|PROT_WRITE,MAP_SHARED,p->fd,0);
	  /* this can never fail, because we mmap exactly as much as we
	   * had mmapped previously.  We need to munmap before doing the
	   * new mmap, though, because we may run into the address space
	   * limit too early on 32-bit systems with lots of RAM */
	  return -1;
	}
      }
#endif
      if (p->fd!=-1) {
	/* slight complication if the storage is file based: we need to
	  * make sure the file size is extended, or the byte_copy will
	  * yield a bus error. */
	if (ftruncate(p->fd,need)==-1) return -1;
      }
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
