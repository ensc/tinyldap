#include <stdlib.h>
#include <string.h>
#include <libowfat/str.h>
#include "bstr.h"
#include "mstorage.h"
#include "mduptab.h"
#include <libowfat/uint32.h>

long mduptab_add(mduptab_t* t,const char* s,size_t len) {
  unsigned int i;
  unsigned long* l=(unsigned long*)t->table.root;
  long x,bak;
  for (i=0; i<t->table.used/sizeof(unsigned long); ++i)
    if (bstr_equal2(t->Strings->root+l[i],s,len))
      return l[i];
  bak=t->Strings->used;
  if ((x=mstorage_add_bin(t->Strings,s,len))<0) return -1;
  if (mstorage_add(&t->table,(const char*)&x,sizeof(x))<0) {
    t->Strings->used=bak;
    return -1;
  }
  return x;
}
