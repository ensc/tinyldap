#include "asn1.h"
#include "ldap.h"

int fmt_ldapstring(char* dest,struct string* s) {
  return fmt_asn1OCTETSTRING(dest,s->s,s->l);
}
