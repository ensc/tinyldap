#include "ldap.h"

size_t scan_ldapstring(const char* src,const char* max,struct string* s) {
  return scan_asn1STRING(src,max,&s->s,&s->l);
}

#ifdef UNITTEST
#include <assert.h>

#undef UNITTEST
#include "scan_asn1STRING.c"
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"
#include "scan_asn1string.c"

/* scan_asn1string already has 100% coverage */

int main() {
  static char buf[]="\x04\x05""fnord";
  struct string s = { 0 };
  assert(scan_ldapstring(buf,buf+7,&s)==7 && s.l==5 && s.s==buf+2);
  // we only care for 100% coverage of this file, the others have their own unit tests */
  return 0;
}
#endif
