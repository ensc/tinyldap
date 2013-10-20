#include "ldap.h"

size_t fmt_ldappal(char* dest,const struct PartialAttributeList* pal) {
//  int l,l2,sum;
  size_t sum,l,l2;
  if (!pal) return 0;
  sum=fmt_ldapstring(0,&pal->type);
  /* look how much space the adl needs */
  l=fmt_ldapavl(0,pal->values);
  /* write sequence header */
  l2=fmt_asn1SEQUENCE(dest,l+sum);
  if (dest) {
    fmt_ldapstring(dest+l2,&pal->type);
    dest+=sum+l2;
  }
  sum+=l+l2;
  if (dest) {
    fmt_ldapavl(dest,pal->values);
    dest+=l;
  }
  return sum+fmt_ldappal(dest,pal->next);
}

