#include <stdlib.h>
#include "str.h"
#include "mstorage.h"
#include "mduptab.h"
#include "bstr.h"

const long mduptab_adds(mduptab_t* t,const char* s) {
  return mduptab_add(t,s,strlen(s));
}
#if 0
const long mduptab_adds(mduptab_t* t,const char* s) {
  unsigned int i;
  unsigned long* l=(unsigned long*)t->table.root;
  for (i=0; i<t->strings.used/sizeof(unsigned long); ++i)
    if (bstr_equal(t->strings.root+l[i],s))
      return l[i];
  {
    long x=mstorage_add(&t->strings,s,strlen(s)+1);
    if (mstorage_add(&t->table,(const char*)&x,sizeof(x))<0) {
      t->strings.used-=strlen(s)+1;
      return -1;
    }
    return x;
  }
}
#endif
