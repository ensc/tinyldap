#include <stdlib.h>
#include "str.h"
#include "strduptab.h"
#include "strstorage.h"

#define PAGESIZE 4096

const char* strduptab_add(struct stringduptable* t,const char* s) {
  int i;
  for (i=0; i<t->n; ++i)
    if (str_equal(t->s[i],s))
      return t->s[i];
  if (t->n>=t->a) {
    const char** x;
    int a=t->a*2;
    if (!a) a=1024;
    if (!(x=realloc((char**)t->s,a*sizeof(char*))))
      return 0;
    t->a=a;
    t->s=x;
  }
  {
    const char* x=strstorage_add(s,strlen(s)+1);
    if (!x) return 0;
    s=x;
  }
  t->s[t->n]=s; ++t->n;
  return s;
}
