#include <string.h>
#include "ldap.h"
#include <libowfat/str.h>
#include <libowfat/rangecheck.h>

size_t fmt_ldapbindrequest(char* dest,long version,const char* name,const char* simple) {
  size_t l,sum;
  size_t nlen=str_len(name);
  sum=l=fmt_asn1INTEGER(dest,version);
  if (dest) dest+=l;
  l=fmt_asn1OCTETSTRING(dest,name,nlen);
  if (add_of(sum,sum,l)) return (size_t)-1;
  if (dest) dest+=l;
//  sum+=l; if (dest) dest+=l;
  nlen=str_len(simple);
  l=fmt_asn1string(dest,PRIVATE,PRIMITIVE,0,simple,nlen);
  if (add_of(sum,sum,l)) return (size_t)-1;
  return sum;
}
