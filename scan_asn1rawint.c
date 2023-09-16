#include "asn1.h"

size_t scan_asn1rawint(const char* src,const char* max,size_t len,long* l) {
  size_t i;
  long m;
  const signed char* s = (const signed char*)src;
  if (src>=max || (size_t)(max-src)<len)
    return 0;		// input buffer too small
  m=(*s>>7);	// -1 if negative, 0 otherwise
  // look for and reject non-minimal encodings
  if (len>1 && *s==m) {
    // we want to catch things like 00 01
    // but a leading 0 byte is needed for 00 a0 because otherwise it would be -96
    if ((s[1]>>7)==m)
      return 0;	// non-minimal encoding
    /* This part is a bit counter intuitive.
       The code used to say this:

    if (len>sizeof(m)+1)
      return 0;	// value too large, does not fit

       But if you look closely then this encoding is only used
       if the highest bit in an unsigned number is set or if
       the highest bit in a signed number is unset.
       If len == sizeof(m) then we can't represent that in a long.
       The actual maximum length is sizeof(m), not sizeof(m)+1.
       Which means the length check is the same and
       can be done outside the if statement. */
  }
  if (len>sizeof(m))
    return 0;	// value too large, does not fit
  for (i=0; i<len; ++i) {
    m=((unsigned long)m<<8)|(unsigned char)s[i];
  }
  *l=m;
  return len;
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
size_t wrapper(const char* src,const char* max,size_t len,long* l) {
  static char* base;
  if (!base) {
    base=mmap(0,64*1024+4*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(base!=MAP_FAILED);
    mprotect(base+64*1024,4*1024,PROT_NONE);
  }
  assert(src<=max && max-src<64*1024);
  {
    size_t L = max-src;
    char* dest=base+64*1024-L;
    memcpy(dest, src, L);
    return scan_asn1rawint(dest, dest+L, len, l);
  }
}

#define scan_asn1rawint wrapper
#endif

int main() {
  char buf[10];
  long l=0;
  memset(buf,0,sizeof buf);
  assert(scan_asn1rawint(buf, buf, 0, &l) == 0);	// no input
  assert(scan_asn1rawint(buf, buf+10, 0, &l) == 0);	// no input
  strcpy(buf,"\x01");
  assert(scan_asn1rawint(buf, buf+10, 1, &l) == 1 && l == 1);	// OK
  memcpy(buf,"\x00\x01",2);
  assert(scan_asn1rawint(buf, buf+10, 1, &l) == 1 && l == 0);	// OK
  assert(scan_asn1rawint(buf, buf+10, 2, &l) == 0);	// non-minimal
  memcpy(buf,"\xa0",1);
  assert(scan_asn1rawint(buf, buf+10, 1, &l) == 1 && l == -96);	// OK
  memcpy(buf,"\x00\xa0",2);
  assert(scan_asn1rawint(buf, buf+10, 2, &l) == 2 && l == 160);	// OK
  memcpy(buf,"\x01\x02\x03\x04\x05\x06\x07\x08\x09",9);
  assert(scan_asn1rawint(buf, buf+10, 9, &l) == 0);	// value too large, not representable
  memcpy(buf,"\xff\x01\x02\x03\x04\x05\x06\x07\x08\x09",10);
  assert(scan_asn1rawint(buf, buf+10, 10, &l) == 0);	// value too large, not representable
  assert(scan_asn1rawint(buf, buf+1, 3, &l) == 0);	// buffer too small for length
  // check for not representable numbers, i.e.
  // positive but > LONG_MAX or negative buf < LONG_MIN
  memcpy(buf,"\xff\x7f\xff\xff\xff\xff\xff\xff\xff",9);
  assert(scan_asn1rawint(buf, buf+sizeof(long)+1, sizeof(long)+1, &l) == 0);
  memcpy(buf,"\x00\xff\xff\xff\xff\xff\xff\xff\xff",9);
  assert(scan_asn1rawint(buf, buf+sizeof(long)+1, sizeof(long)+1, &l) == 0);
  return 0;
}
#endif
