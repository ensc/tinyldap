#include "ldap.h"

size_t fmt_ldapava(char* dest,const struct AttributeValueAssertion* a) {
  size_t sum,l;
  sum=fmt_ldapstring(dest,&a->desc);
  if (dest) dest+=sum;
  l=fmt_ldapstring(dest,&a->value);
  return sum+l;
}
