#include "asn1.h"
#include "ldap.h"

int fmt_ldapbindrequest(char* dest,long version,char* name,char* simple) {
  int l,sum=0;
  int nlen=strlen(name);
  sum=l=fmt_asn1INTEGER(dest,version);
  if (dest) dest+=l;
  l=fmt_asn1OCTETSTRING(dest,name,nlen);
  sum+=l+nlen; if (dest) dest+=l+nlen;
  nlen=strlen(simple);
  l=fmt_asn1string(dest,PRIVATE,PRIMITIVE,0,simple,nlen);
  if (dest) dest+=l+nlen;
  return sum+l+nlen;
}
