#include "asn1.h"

size_t scan_asn1SET(const char* src,const char* max,size_t* len) {
  size_t res,tmp;
  unsigned long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if (!(res=scan_asn1tag(src,max,&tc,&tt,&tag)))
    return 0;
  if (!(tmp=scan_asn1length(src+res,max,len)))
    return 0;
  res+=tmp;
  if (tc==UNIVERSAL && tt==CONSTRUCTED && tag==SET_OF)
    return res;
  return 0;
}

#ifdef UNITTEST
#include <string.h>
#include <assert.h>

#undef UNITTEST
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"

int main() {
  char buf[100];
  size_t l;
  strcpy(buf,"\x31\x01\x01");	// 0x31 = UNIVERSAL + CONSTRUCTED + SET_OF, 0x01 = length 1, 0x01 = dummy filler
  // this function only parses the header so our test data doesn't need
  // to have an actual set, only the header for one. \x01 is not a valid
  // set.
  assert(scan_asn1SET(buf,buf+3,&l)==2 && l==1);
  assert(scan_asn1SET(buf,buf,&l)==0);		// not enough input, first return 0
  assert(scan_asn1SET(buf,buf+2,&l)==0);	// not enough input, second return 0
  buf[0]=0x30;
  assert(scan_asn1SET(buf,buf+3,&l)==0);	// 0x30 = SEQUENCE_OF, third return 0
  // we only care for 100% coverage of this file, the others have their own unit tests */
}
#endif
