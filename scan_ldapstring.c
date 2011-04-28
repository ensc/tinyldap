#include "ldap.h"

size_t scan_ldapstring(const char* src,const char* max,struct string* s) {
  return scan_asn1STRING(src,max,&s->s,&s->l);
}
