#include "byte.h"
#include "ldif.h"

/* behave like strcmp, but also return 0 if s is a prefix of c. */
int matchprefix(struct string* s,const char* c) {
  unsigned int l,l1,i;
  if (!c) return -1;
  l1=l=strlen(c);
  if (s->l<l1) l1=s->l;
  i=byte_diff(s->s,l1,c);
  if (i) return i;
  /* one is a prefix of the other */
  if (l==s->l) return 0;
  if (c[l1]) /* is c the longer string? */
    return 0;
  return -(int)(s->s[l1]);
}

