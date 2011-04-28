#include "ldap.h"

size_t fmt_ldapmessage(char* dest,long messageid,long op,size_t len) {
  size_t l,l2,l3;
  l2=fmt_asn1INTEGER(0,messageid);
  l3=fmt_asn1transparent(0,APPLICATION,CONSTRUCTED,op,len);
  l=fmt_asn1SEQUENCE(dest,len+l2+l3);
  if (!dest) return l+l2+l3;
  l+=fmt_asn1INTEGER(dest+l,messageid);
  l+=fmt_asn1transparent(dest+l,APPLICATION,CONSTRUCTED,op,len);
  return l;
}
