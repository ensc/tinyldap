#include <string.h>
#include "asn1.h"
#include "ldap.h"

int fmt_ldapbindrequest(char* dest,long version,char* name,char* simple) {
  int l,sum;
  int nlen=strlen(name);
  sum=l=fmt_asn1INTEGER(dest,version);
  if (dest) dest+=l;
  l=fmt_asn1OCTETSTRING(dest,name,nlen);
  sum+=l; if (dest) dest+=l;
  nlen=strlen(simple);
  l=fmt_asn1string(dest,PRIVATE,PRIMITIVE,0,simple,nlen);
  if (dest) dest+=l+nlen;
  return sum+l+nlen;
}
