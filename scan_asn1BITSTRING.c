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
      lastbyte=(*s)[*l+1];
      if (lastbyte & (0xff >> (8-**s)))
	return 0;
      *l=*l*8-(unsigned char)(**s);
      ++*s;
      return tmp;
    }
  return 0;
}
