#include <stdlib.h>
#include "str.h"
#include "bstr.h"
#include "mstorage.h"
#include "mduptab.h"
#include "uint32.h"

const long mduptab_add(mduptab_t* t,const char* s,unsigned int len) {
  unsigned int i;
  unsigned long* l=(unsigned long*)t->table.root;
  static char zero;
  int binary=0;
  for (i=0; i<t->strings.used/sizeof(unsigned long); ++i)
    if (bstr_equal2(t->strings.root+l[i],s,len))
      return l[i];
  for (i=0; i<len; ++i)
    if (!s[i]) binary=1;
  {
    long x;
    char intbuf[4];
    if (binary) {
      x=mstorage_add(&t->strings,&zero,1);
      uint32_pack(intbuf,len);
      mstorage_add(&t->strings,intbuf,4);
      mstorage_add(&t->strings,s,len);
    } else {
      x=mstorage_add(&t->strings,s,len);
      mstorage_add(&t->strings,&zero,1);
    }
    if (mstorage_add(&t->table,(const char*)&x,sizeof(x))<0) {
      t->strings.used-=strlen(s)+1;
      return -1;
    }
    return x;
  }
}
