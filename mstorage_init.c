#include <mstorage.h>

void mstorage_init(mstorage_t* p) {
  p->root=0;
  p->mapped=p->used=0;
  p->fd=-1;
}
