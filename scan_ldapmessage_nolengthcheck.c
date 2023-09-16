#include "ldap.h"

size_t scan_ldapmessage_nolengthcheck(const char* src,const char* max,size_t* len) {
  return scan_asn1SEQUENCE_nolengthcheck(src,max,len);
}

#ifdef UNITTEST
#include <assert.h>
#undef UNITTEST
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"
#include "scan_asn1SEQUENCE_nolengthcheck.c"

int main() {
  static char buf[] = "\x30\x01\x01";	// 0x30 = UNIVERSAL + CONSTRUCTED + SEQUENCE_OF, 0x01 = length 1, 0x01 = dummy filler
  size_t l;

  assert(scan_ldapmessage_nolengthcheck(buf,buf+3,&l)==2 && l==1);
  // we only care for 100% coverage of this file, the others have their own unit tests */
  return 0;
}
#endif
