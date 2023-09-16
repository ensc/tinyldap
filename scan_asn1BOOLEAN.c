#include "asn1.h"

size_t scan_asn1BOOLEAN(const char* src,const char* max,int* val) {
  size_t tmp;
  unsigned long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  long ltmp;
  if ((tmp=scan_asn1int(src,max,&tc,&tt,&tag,&ltmp)))
    if (tc==UNIVERSAL && tt==PRIMITIVE && tag==BOOLEAN) {
      if (ltmp!=0 && ltmp!=-1) return 0;
      *val=ltmp;
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
  int l=0;
  memset(buf,0,sizeof buf);
  strcpy(buf,"\x01\x01\x00");	// 0x01 = UNIVERSAL + CONSTRUCTED + BOOLEAN, 0x01 = length 1, 0x00 = false
  assert(scan_asn1BOOLEAN(buf,buf+3,&l)==3 && l==0);
  assert(scan_asn1BOOLEAN(buf,buf+2,&l)==0);	// not enough input
  buf[2]=0xff;
  assert(scan_asn1BOOLEAN(buf,buf+3,&l)==3 && l==-1);
  buf[2]=2;
  assert(scan_asn1BOOLEAN(buf,buf+3,&l)==0);	// only 0 and 1 are valid values for BOOLEAN
  buf[0]=0x30; buf[2]=1;
  assert(scan_asn1BOOLEAN(buf,buf+3,&l)==0);	// 0x30 = SEQUENCE_OF, fails line 10
  // we only care for 100% coverage of this file, the others have their own unit tests */
  return 0;
}
#endif
