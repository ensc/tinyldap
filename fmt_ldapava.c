#include "asn1.h"
#include "ldap.h"

int fmt_ldapava(char* dest,struct AttributeValueAssertion* a) {
  long sum,l;
  sum=fmt_ldapstring(dest,&a->desc);
  if (dest) dest+=sum;
  l=fmt_ldapstring(dest,&a->value);
  return sum+l;
}
