#ifndef _MSTORAGE_H
#define _MSTORAGE_H

#include <stddef.h>

/* (optionally persistent) mmapped storage. */

typedef struct mstorage {
  char* root;
  size_t mapped,used;
  int fd;
} mstorage_t;

void mstorage_init(mstorage_t* p);

int mstorage_init_persistent(mstorage_t* p,int fd);

/* Works like strstorage_add, but will return an
 * offset to mstorage_root, which is mmapped and may thus change. */
/* offset -1 ==> error */
long mstorage_add(mstorage_t* p,const char* s,size_t n);

/* undo mapping */
void mstorage_unmap(mstorage_t* p);

/* this is tinyldap specific.  If the data contains at least one 0-byte,
 * it is stored in a tinyldap specific encoding:
 *   char 0;
 *   uint32 len;
 *   char data[len] */
long mstorage_add_bin(mstorage_t* p,const char* s,size_t n);

#endif
