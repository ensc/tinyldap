#include "uint32.h"
#include "mstorage.h"

/* this is tinyldap specific.  If the data contains at least one 0-byte,
 * it is stored in a tinyldap specific encoding:
 *   char 0;
 *   uint32 len;
 *   char data[len] */
long mstorage_add_bin(mstorage_t* p,const char* s,unsigned long n) {
  unsigned int i;
  static char zero;
  long x;
  char intbuf[4];
  for (i=0; i<n-1; ++i)
    if (!s[i]) {
      x=mstorage_add(p,&zero,1);
      uint32_pack(intbuf,n);
      mstorage_add(p,intbuf,4);
      mstorage_add(p,s,n);
      return x;
    }
  x=mstorage_add(p,s,n);
  mstorage_add(p,&zero,1);
  return x;
}