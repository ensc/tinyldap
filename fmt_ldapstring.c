#include "ldap.h"

size_t fmt_ldapstring(char* dest,const struct string* s) {
  return fmt_asn1OCTETSTRING(dest,s->s,s->l);
}
