#include "asn1.h"
#include "ldap.h"

int scan_ldapava(const char* src,const char* max,struct AttributeValueAssertion* ava) {
  int res,tmp;
  if (!(res=scan_ldapstring(src,max,&ava->desc))) goto error;
  if (!(tmp=scan_ldapstring(src+res,max,&ava->value))) goto error;
  return res+tmp;
error:
  return 0;
}
