#include "mstorage.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/shm.h>

void mstorage_unmap(mstorage_t* p) {
#ifdef MREMAP_MAYMOVE
  munmap(p->root,p->mapped);
#else
  free(p->root);
#endif
  if (p->fd!=-1) {
    ftruncate(p->fd,p->used);
    close(p->fd);
  }
  p->mapped=p->used=0;
  p->root=0;
}
