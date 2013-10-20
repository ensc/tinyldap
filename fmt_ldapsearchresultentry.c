#include "ldap.h"

size_t fmt_ldapsearchresultentry(char* dest,const struct SearchResultEntry* sre) {
  size_t l,sum=0;
  sum=fmt_ldapstring(dest,&sre->objectName);
  if (dest) dest+=sum;
  l=fmt_asn1SEQUENCE(dest,fmt_ldappal(0,sre->attributes));
  sum+=l; if (dest) dest+=l;
  l=fmt_ldappal(dest,sre->attributes);
  return sum+l;
}
