#include "mstorage.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>

void mstorage_unmap(mstorage_t* p) {
  munmap(p->root,p->mapped);
  if (p->fd!=-1) {
    ftruncate(p->fd,p->used);
    close(p->fd);
  }
}
