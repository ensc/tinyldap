#include <stdlib.h>
#include "byte.h"
#include "strstorage.h"

#define PAGESIZE 4096

const char* strstorage_add(const char* s,int n) {
  static char* page=0;
  static int leftonpage=0;
  if (leftonpage>=n) {
copyit:
    byte_copy(page,n,s);
    s=page;
    page+=n;
    leftonpage-=n;
  } else {
    if (n>=PAGESIZE/2) {
      char* tmp=malloc(n);
      if (!tmp) return 0;
      byte_copy(tmp,n,s);
      s=tmp;
    } else {
      if (!(page=malloc(PAGESIZE))) return 0;
      leftonpage=PAGESIZE;
      goto copyit;
    }
  }
  return s;
}
