#include "ldap.h"

size_t fmt_ldapsearchrequest(char* dest,const struct SearchRequest* sr) {
  size_t l,sum=0;
  sum=fmt_ldapstring(dest,&sr->baseObject);
  if (dest) dest+=sum;
  l=fmt_asn1ENUMERATED(dest,sr->scope);
  sum+=l; if (dest) dest+=l;
  l=fmt_asn1ENUMERATED(dest,sr->derefAliases);
  sum+=l; if (dest) dest+=l;
  l=fmt_asn1INTEGER(dest,sr->sizeLimit);
  sum+=l; if (dest) dest+=l;
  l=fmt_asn1INTEGER(dest,sr->timeLimit);
  sum+=l; if (dest) dest+=l;
  l=fmt_asn1BOOLEAN(dest,sr->typesOnly);
  sum+=l; if (dest) dest+=l;
  l=fmt_ldapsearchfilter(dest,sr->filter);
  sum+=l; if (dest) dest+=l;
  l=fmt_ldapadl(dest,sr->attributes);
  return sum+l;
}
