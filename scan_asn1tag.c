#include "asn1.h"

#ifdef UNITTEST
#undef UNITTEST
#include "scan_asn1tagint.c"
#define UNITTEST
#endif

size_t scan_asn1tag(const char* src,const char* max,enum asn1_tagclass* tc,enum asn1_tagtype* tt,unsigned long* tag) {
  if (max<=src)
    return 0;
  *tc=(*src&0xC0);
  *tt=(*src&0x20);
/* The lower 5 bits are the tag, unless it's 0x1f, in which case the
 * next bytes are the tag: always take the lower 7 bits; the last byte
 * in the sequence is marked by a cleared high bit */
  if ((*src & 0x1f) == 0x1f) {
    size_t res=scan_asn1tagint(src+1,max,tag);
    if (res && *tag < 0x1f)	// non-minimal encoding
      return 0;
    return res+!!res;	/* add 1 unless it's 0, then leave 0 */
  } else {
    *tag=*src&0x1f;
    return 1;
  }
}

#ifdef UNITTEST
#include <assert.h>
#include <string.h>

#ifdef __linux__
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>

// This wrapper maps a 64k buffer of memory and makes sure the page
// after it will cause a segfault when accessed. Then we copy the input
// data at the end of the 64k. This is to catch out of bounds reads.
size_t wrapper(const char* src,const char* max,enum asn1_tagclass* tc,enum asn1_tagtype* tt,unsigned long* tag) {
  static char* base;
  if (!base) {
    base=mmap(0,64*1024+4*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(base!=MAP_FAILED);
    mprotect(base+64*1024,4*1024,PROT_NONE);
  }
  assert(src<=max && max-src<64*1024);
  {
    size_t l = max-src;
    char* dest=base+64*1024-l;
    memcpy(dest, src, l);
    return scan_asn1tag(dest, dest+l, tc, tt, tag);
  }
}

#define scan_asn1tag wrapper
#endif

int main() {
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  unsigned long tag;
  char buf[15];

  memset(buf,0,sizeof buf);

  assert(scan_asn1tag(buf,buf,&tc,&tt,&tag)==0);	// empty input
  strcpy(buf,"\x01"); assert(scan_asn1tag(buf,buf+1,&tc,&tt,&tag)==1 && tc==UNIVERSAL && tt==PRIMITIVE && tag==BOOLEAN);
  /* incomplete input */
  strcpy(buf,"\x1f"); assert(scan_asn1tag(buf,buf+1,&tc,&tt,&tag)==0);
  /* long-form encoding when short-form would have sufficed */
  strcpy(buf,"\x1f\x1e");
  assert(scan_asn1tag(buf,buf+2,&tc,&tt,&tag)==0);
  /* OK */
  strcpy(buf,"\x1f\x1f");
  assert(scan_asn1tag(buf,buf+2,&tc,&tt,&tag)==2 && tc==UNIVERSAL && tt==PRIMITIVE && tag==0x1f);
  /* non-minimal encoding */
  strcpy(buf,"\x1f\x80\x01");
  assert(scan_asn1tag(buf,buf+3,&tc,&tt,&tag)==0);
  /* incomplete encoding */
  assert(scan_asn1tag(buf,buf+2,&tc,&tt,&tag)==0);
  strcpy(buf,"\x1f\x81\x00");
  assert(scan_asn1tag(buf,buf+3,&tc,&tt,&tag)==3 && tc==UNIVERSAL && tt==PRIMITIVE && tag==0x80);
  /* value not representable */
  memcpy(buf,"\x1f\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f",11);
  assert(scan_asn1tag(buf,buf+11,&tc,&tt,&tag)==0);
  memcpy(buf,"\x1f\x8f\xff\xff\xff\x7f",7);
  assert(scan_asn1tag(buf,buf+7,&tc,&tt,&tag)==6 && tc==UNIVERSAL && tt==PRIMITIVE && tag==0xffffffff);
  return 0;
}
#endif
