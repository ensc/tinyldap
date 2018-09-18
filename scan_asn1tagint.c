#include "asn1.h"

size_t scan_asn1tagint(const char* src,const char* bounds,unsigned long* val) {
  const char* orig=src;
  unsigned long l=0;
  if (src>=bounds ||				/* empty input */
      (unsigned char)src[0]==0x80) return 0;	/* catch non-minimal encoding */
  for (;; ++src) {
    if (src>=bounds ||				/* incomplete input */
        l>>(sizeof(l)*8-7)) return 0;		/* catch integer overflow */
    l=l*128+(*src&0x7F);
    if (!(*src&0x80)) break;
  }
  *val=l;
  return src-orig+1;
}

#ifdef UNITTEST
#include <assert.h>
#include <string.h>

#include <stdio.h>

int main() {
  char buf[10];
  unsigned long l;
  assert(scan_asn1tagint(buf,buf,&l)==0);		// empty input
  strcpy(buf,"\x80\x01");
  assert(scan_asn1tagint(buf,buf+2,&l)==0);		// non-minimal encoding
  strcpy(buf,"\x01");
  assert(scan_asn1tagint(buf,buf+1,&l)==1 && l==1);
  strcpy(buf,"\x7f");
  assert(scan_asn1tagint(buf,buf+1,&l)==1 && l==0x7f);
  strcpy(buf,"\x81\x00");
  assert(scan_asn1tagint(buf,buf+2,&l)==2 && l==0x80);
  assert(scan_asn1tagint(buf,buf+1,&l)==0);		// incomplete input
  memcpy(buf,"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f",10);
  assert(scan_asn1tagint(buf,buf+10,&l)==0);		// value not representable
  memcpy(buf,"\x8f\xff\xff\xff\x7f",9);
  assert(scan_asn1tagint(buf,buf+10,&l)==5 && l==0xffffffff);		// largest 32-bit
  memcpy(buf,"\xff\xff\xff\xff\xff\xff\xff\xff\x7f",9);
  if (sizeof(l)==8) {
    assert(scan_asn1tagint(buf,buf+10,&l)==9 && l==0x7fffffffffffffff);
  } else if (sizeof(l)==4) {
    assert(scan_asn1tagint(buf,buf+10,&l)==0);		// too large
    memcpy(buf,"\x90\x00\x00\x00\x00",9);
    assert(scan_asn1tagint(buf,buf+10,&l)==0);		// too large
  }
}
#endif
