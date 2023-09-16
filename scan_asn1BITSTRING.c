#include "asn1.h"

size_t scan_asn1BITSTRING(const char* src,const char* max,const char** s,size_t* l) {
  size_t tmp;
  unsigned long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if ((tmp=scan_asn1string(src,max,&tc,&tt,&tag,s,l)))
    if (tc==UNIVERSAL && tt==PRIMITIVE && tag==BIT_STRING) {
      unsigned char lastbyte;
      if (*l==0 ||	/* length must be at least 1 because for bit strings, the first octet contains the number of unused bits in the last octet */
	  (unsigned char)(**s)>7)	/* the number of unused bits in the last octet must not be negative and can be at most 7 */
	return 0;
      /* these are DER checks */
      /* can't have unused bits if the length is 0 */
      if (*l==1 && **s)
	return 0;
      /* now check if the unused bits are 0 */
      lastbyte=(*s)[*l-1];
      if (lastbyte & (0xff >> (8-**s)))
	return 0;
      *l=(*l-1)*8-(unsigned char)(**s);
      ++*s;
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
#include "scan_asn1string.c"

int main() {
  char buf[100];
  const char* s;
  size_t l;
  strcpy(buf,"\x03\x04\x06\x6e\x5d\xc0");
  size_t r = scan_asn1BITSTRING(buf, buf+6, &s, &l);
  assert(r==6 && s==buf+3 && l==18);
  strcpy(buf,"\x03\x02\x07\x80");	// 0x03 = UNIVERSAL PRIMITIVE BIT_STRING, 0x02 = length 2, 0x07 = unused bits in last octet, 0x80 = 1
  assert(scan_asn1BITSTRING(buf,buf+4,&s,&l)==4 && s==buf+3 && l==1);
  assert(scan_asn1BITSTRING(buf,buf+3,&s,&l)==0);	// short input, make scan_asn1string fail
  buf[0]=0x13;	// 0x13 = UNIVERSAL PRIMITIVE PrintableString
  assert(scan_asn1BITSTRING(buf,buf+4,&s,&l)==0);	// scan_asn1string succeeds but line 9 fails
  buf[0]=0x03; buf[2]=8;
  assert(scan_asn1BITSTRING(buf,buf+4,&s,&l)==0);	// scan_asn1string succeeds but line 12 fails
  buf[2]=7; buf[1]=0;
  assert(scan_asn1BITSTRING(buf,buf+4,&s,&l)==0);	// scan_asn1string succeeds but line 11 fails
  strcpy(buf,"\x03\x01\x00");		// length 0 bit string
  assert(scan_asn1BITSTRING(buf,buf+3,&s,&l)==3 && s==buf+3 && l==0);
  buf[2]=1;
  assert(scan_asn1BITSTRING(buf,buf+3,&s,&l)==0);	// length 0 but says it has unused bits, return 0 in line 17
  strcpy(buf,"\x03\x02\x07\x81");	// 0x03 = UNIVERSAL PRIMITIVE BIT_STRING, 0x02 = length 2, 0x07 = unused bits in last octet, 0x81 = invalid
  assert(scan_asn1BITSTRING(buf,buf+4,&s,&l)==0);	// unused bits not 0, return 0 in line 21
  // we only care for 100% coverage of this file, the others have their own unit tests */
  return 0;
}
#endif
