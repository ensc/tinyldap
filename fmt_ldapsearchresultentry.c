#include "asn1.h"
#include "ldap.h"

unsigned int fmt_ldapsearchresultentry(char* dest,struct SearchResultEntry* sre) {
  unsigned int l,sum=0;
  sum=fmt_ldapstring(dest,&sre->objectName);
  if (dest) dest+=sum;
  l=fmt_asn1SEQUENCE(dest,fmt_ldappal(0,sre->attributes));
  sum+=l; if (dest) dest+=l;
  l=fmt_ldappal(dest,sre->attributes);
  return sum+l;
}
