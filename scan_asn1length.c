#include <inttypes.h>
#include "asn1.h"

size_t scan_asn1length(const char* src,const char* max,size_t* value) {
  size_t len=max-src;
  if (len==0 || len>=-(uintptr_t)src) return 0;
  unsigned int i,c=*src;
  size_t l;
  if ((c&0x80)==0) {
    l=c&0x7f;
    i=1;
  } else {
    /* Highest bit set: lower 7 bits is the length of the length value in bytes. */
    c&=0x7f;
    if (!c)
      return 0;		/* length 0x80 means indefinite length encoding, not supported here */
    l=(unsigned char)src[1];
    if (l==0)
      return 0;		/* not minimally encoded: 0x81 0x00 instead of 0x00 */
    if (c>sizeof(l))
      return 0;		/* too many bytes, does not fit into target integer type */
    if (c+1>len)
      return 0;		/* not enough data in input buffer */
    for (i=2; i<=c; ++i)
      l=l*256+(unsigned char)src[i];
    if (l<0x7f)
      return 0;		/* not minimally encoded: 0x81 0x70 instead of 0x70 */
  }
  if (l>len-i)
    return 0;		/* if the length would not fit into the buffer, return 0 */
  *value=l;
  return i;
}

#ifdef UNITTEST
#include <assert.h>
#include <string.h>

int main() {
  char buf[10];
  unsigned long l;
  /* empty input */
  assert(scan_asn1length(buf,buf,&l)==0);
  /* regular 1-byte encoding */
  strcpy(buf,"\x23");
  assert(scan_asn1length(buf,buf+1,&l)==0);	// length fits but value doesn't
  assert(scan_asn1length(buf,buf+0x23,&l)==0);	// length fits but value doesn't
  assert(scan_asn1length(buf,buf+0x24,&l)==1 && l==0x23);	// OK
  /* not minimally encoded */
  strcpy(buf,"\x81\x23");	// not minimal, should have been "\x23"
  assert(scan_asn1length(buf,buf+10,&l)==0);
  /* indefinite length encoding not supported */
  strcpy(buf,"\x80");
  assert(scan_asn1length(buf,buf+1,&l)==0);
  /* regular 2-byte encoding */
  strcpy(buf,"\x81\x97");
  assert(scan_asn1length(buf,buf+2,&l)==0);	// length fits but value doesn't
  assert(scan_asn1length(buf,buf+255,&l)==2 && l==0x97);
  /* non-minimal multi-byte */
  memcpy(buf,"\x82\x00\x97",3);	// not minimal, should have been "\x81\x97"
  assert(scan_asn1length(buf,buf+3,&l)==0);
  /* value not representable */
  memcpy(buf,"\x89\x01\x02\x03\x04\x05\x06\x07\x08\x09",10);	// can't fit 9 bytes into long
  // this will also fail the "length bytes fit in input buffer"
  assert(scan_asn1length(buf,buf+10,&l)==0);
  /* value does not fit in input buffer */
  memcpy(buf,"\x81\x80",2);	// length 0x80
  assert(scan_asn1length(buf,buf+10,&l)==0);	// length fits, value doesn't
  assert(scan_asn1length(buf,buf+0x90,&l)==2 && l==0x80);	// OK
  assert(scan_asn1length(buf,buf+1,&l)==0);	// length doesn't fit
  // three byte encoding
  memcpy(buf,"\x82\x80\x00",3);	// length 0x8000
  assert(scan_asn1length(buf,buf+10,&l)==0);	// length fits, value doesn't
  assert(scan_asn1length(buf,buf+0x8010,&l)==3 && l==0x8000);	// OK
  assert(scan_asn1length(buf,buf+2,&l)==0);	// length doesn't fit
}
#endif
