#include "asn1.h"

size_t scan_asn1INTEGER(const char* src,const char* max,signed long* val) {
  size_t tmp;
  unsigned long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if ((tmp=scan_asn1int(src,max,&tc,&tt,&tag,val)))
    if (tc==UNIVERSAL && tt==PRIMITIVE && tag==INTEGER)
      return tmp;
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
  long l=0;
  memset(buf,0,sizeof buf);
  strcpy(buf,"\x02\x01\x17");	// 0x02 = UNIVERSAL + CONSTRUCTED + INTEGER, 0x01 = length 1, 0x17 = value
  assert(scan_asn1INTEGER(buf,buf+3,&l)==3 && l==23);
  assert(scan_asn1INTEGER(buf,buf+2,&l)==0);	// not enough input
  buf[0]=0x01;
  assert(scan_asn1INTEGER(buf,buf+3,&l)==0);	// 0x01 = BOOLEAN, fails line 9
  // we only care for 100% coverage of this file, the others have their own unit tests */
  // let's do a few more to leave sample values here
  strcpy(buf,"\x02\x01\xff");	// 0x02 = UNIVERSAL + CONSTRUCTED + INTEGER, 0x01 = length 1, 0xff = value (-1)
  assert(scan_asn1INTEGER(buf,buf+3,&l)==3 && l==-1);
  strcpy(buf,"\x02\x04\x12\x34\x56\x78");	// 0x02 = UNIVERSAL + CONSTRUCTED + INTEGER, 0x01 = length 4, 0x12345678 = value
  assert(scan_asn1INTEGER(buf,buf+6,&l)==6 && l==0x12345678);
  if (sizeof(l)==8) {
    strcpy(buf,"\x02\x08\x11\x22\x33\x44\x55\x66\x77\x88");
    assert(scan_asn1INTEGER(buf,buf+10,&l)==10 && l==0x1122334455667788);
    strcpy(buf,"\x02\x08\xee\xdd\xcc\xbb\xaa\x99\x88\x78");
    assert(scan_asn1INTEGER(buf,buf+10,&l)==10 && l==-0x1122334455667788);	// two's complement
    strcpy(buf,"\x02\x08\x7f\xff\xff\xff\xff\xff\xff\xff");	// LONG_MAX
    assert(scan_asn1INTEGER(buf,buf+10,&l)==10 && l==0x7ffffffffffffffful);
    memcpy(buf,"\x02\x08\x80\x00\x00\x00\x00\x00\x00\x00",10);	// LONG_MIN
    assert(scan_asn1INTEGER(buf,buf+10,&l)==10 && l==(long)0x8000000000000000);
    strcpy(buf,"\x02\x08\xff\xff\xff\xff\xff\xff\xff\xff");
    assert(scan_asn1INTEGER(buf,buf+10,&l)==0);			// non-minimal encoding of -1
  }
  return 0;
}
#endif
