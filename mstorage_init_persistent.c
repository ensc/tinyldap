#define _FILE_OFFSET_BITS 64
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include "mstorage.h"

int mstorage_init_persistent(mstorage_t* p,int fd) {
  off_t o;
  p->fd=fd;
  o=lseek(fd,0,SEEK_END);
  if (o==-1) return -1;
  p->mapped=p->used=o;
  if (p->mapped==0) {
    p->mapped=4096;
    if (ftruncate(fd,4096)==-1) return -1;
  }
  p->root=mmap(0,p->mapped,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
  if (p->root==(char*)-1) return -1;
  return 0;
}
