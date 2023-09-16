#include "ldap.h"

size_t scan_ldapava(const char* src,const char* max,struct AttributeValueAssertion* ava) {
  size_t res,tmp;
  if (!(res=scan_ldapstring(src,max,&ava->desc)))
    goto error;
  if (!(tmp=scan_ldapstring(src+res,max,&ava->value)))
    goto error;
  return res+tmp;
error:
  return 0;
}
