#include "asn1.h"

size_t scan_asn1rawint(const char* src,const char* max,size_t len,long* l) {
  size_t i;
  long m;
  if (src>=max || max-src<len)
    return 0;		// input buffer too small
  m=(*src>>7);	// -1 if negative, 0 otherwise
//  if (*src<0) m=-1; else m=0;		// negative number?
  if (len>1 && *src==m) {
    // we want to catch things like 00 01
    // but a leading 0 byte is needed for 00 a0 because otherwise it would be -96
    if ((src[1]>>7)==m)
      return 0;	// non-minimal encoding
    if (len>sizeof(m)+1)
      return 0;	// value too large, does not fit
  } else
    if (len>sizeof(m))
      return 0;	// value too large, does not fit
  for (i=0; i<len; ++i) {
    m=(m<<8)|(unsigned char)src[i];
  }
  *l=m;
  return len;
}

#ifdef UNITTEST
#include <assert.h>
#include <string.h>

int main() {
  char buf[10];
  long l;
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
}
#endif
