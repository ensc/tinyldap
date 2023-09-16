#include "asn1.h"

size_t scan_asn1ENUMERATED(const char* src,const char* max,unsigned long* val) {
  size_t tmp;
  unsigned long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  long ltmp;
  if ((tmp=scan_asn1int(src,max,&tc,&tt,&tag,&ltmp)))
    if (tc==UNIVERSAL && tt==PRIMITIVE && tag==ENUMERATED) {
      *val=(unsigned long)ltmp;
      return tmp;
    }
  return 0;
}

#ifdef UNITTEST
#include <string.h>
#include <assert.h>

#undef UNITTEST
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"
#include "scan_asn1rawint.c"
#include "scan_asn1int.c"

int main() {
  char buf[100];
  unsigned long l;
  strcpy(buf,"\x0a\x01\x17");	// 0x0a = UNIVERSAL + CONSTRUCTED + ENUMERATED, 0x01 = length 1, 0x17 = value
  assert(scan_asn1ENUMERATED(buf,buf+3,&l)==3 && l==23);
  assert(scan_asn1ENUMERATED(buf,buf+2,&l)==0);	// not enough input
  buf[0]=0x30;
  assert(scan_asn1ENUMERATED(buf,buf+3,&l)==0);	// 0x30 = SEQUENCE_OF, fails line 10
  // we only care for 100% coverage of this file, the others have their own unit tests */
  return 0;
}
#endif
