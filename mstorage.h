#ifndef _MSTORAGE_H
#define _MSTORAGE_H

/* persistant storage. */

typedef struct mstorage {
  char* root;
  unsigned long mapped,used;
} mstorage_t;

extern mstorage_t mstorage_root;

/* Works like strstorage_add, but will return an
 * offset to mstorage_root, which is mmapped and may thus change. */
/* negative offset == error */
long mstorage_add(mstorage_t* p,const char* s,unsigned long n);

/* undo mapping */
void mstorage_unmap(mstorage_t* p);

#endif
