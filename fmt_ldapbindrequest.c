#include <string.h>
#include "asn1.h"
#include "ldap.h"
#include "str.h"

unsigned int fmt_ldapbindrequest(char* dest,long version,char* name,char* simple) {
  unsigned int l,sum;
  unsigned int nlen=str_len(name);
  sum=l=fmt_asn1INTEGER(dest,version);
  if (dest) dest+=l;
  l=fmt_asn1OCTETSTRING(dest,name,nlen);
  sum+=l; if (dest) dest+=l;
  nlen=str_len(simple);
  l=fmt_asn1string(dest,PRIVATE,PRIMITIVE,0,simple,nlen);
  if (dest) dest+=l;
  return sum+l;
}
