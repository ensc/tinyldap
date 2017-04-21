#include <libowfat/case.h>
#include "bstr.h"
#include "ldif.h"

/* like matchstring, but case insensitively */
int matchcasestring(struct string* s,const char* c) {
  unsigned int l,l1,i;
  if (!c) return -1;
  l1=l=bstrlen(c);
  if (s->l<l1) l1=s->l;
  c=bstrfirst(c);
  i=case_diffb(s->s,l1,c);
  if (i) return i;
  /* same length? */
  if (l==s->l) return 0;
  /* one is a prefix of the other */
  if (l1<l)	/* we cut off c */
    return -c[l1];
  return (int)(s->s[l1]);
}

