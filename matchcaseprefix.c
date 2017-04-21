#include <string.h>
#include <libowfat/case.h>
#include "ldif.h"
#include <libowfat/str.h>

/* behave like strcmp, but also return 0 if s is a prefix of c. */
int matchcaseprefix(struct string* s,const char* c) {
  unsigned int l,l1,i;
  if (!c) return -1;
  l1=l=str_len(c);
  if (s->l<l1) l1=s->l;
  i=case_diffb(s->s,l1,c);
  if (i) return i;
  /* one is a prefix of the other */
  if (l==s->l) return 0;
  if (c[l1]) /* is c the longer string? */
    return 0;
  return -(int)(s->s[l1]);
}

